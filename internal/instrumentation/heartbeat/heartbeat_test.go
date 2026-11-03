// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heartbeat_test

import (
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/heartbeat"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/assert"
)

type submission struct {
	name  string
	tags  []string
	value float64
}

// record returns a CountFunc that records each submission in out.
func record(out *[]submission) heartbeat.CountFunc {
	return func(name string, tags []string, value float64) {
		*out = append(*out, submission{name, tags, value})
	}
}

// setCounters sets the test values of the telemetry counters, and restores the
// previous values when the test ends.
func setCounters(t *testing.T) {
	t.Helper()

	var sources [len(telemetry.InstrumentedSource)]uint64
	for i := range telemetry.InstrumentedSource {
		sources[i] = telemetry.InstrumentedSource[i].Swap(0)
	}
	var sinks [len(telemetry.InstrumentedSink)]uint64
	for i := range telemetry.InstrumentedSink {
		sinks[i] = telemetry.InstrumentedSink[i].Swap(0)
	}
	propagation := telemetry.InstrumentedPropagation.Swap(0)
	tainted := telemetry.ExecutedTainted.Swap(0)
	executedPropagation := telemetry.ExecutedPropagation.Swap(0)
	// All the executed source and sink counters are saved and set to zero, so
	// that only the counters set below are submitted.
	executed := map[*atomic.Uint64]uint64{}
	for _, counter := range telemetry.ExecutedSource.Each {
		executed[counter] = counter.Swap(0)
	}
	for _, counter := range telemetry.ExecutedSink.Each {
		executed[counter] = counter.Swap(0)
	}
	verbosity := config.TelemetryVerbosity
	t.Cleanup(func() {
		for i, cnt := range sources {
			telemetry.InstrumentedSource[i].Store(cnt)
		}
		for i, cnt := range sinks {
			telemetry.InstrumentedSink[i].Store(cnt)
		}
		telemetry.InstrumentedPropagation.Store(propagation)
		telemetry.ExecutedTainted.Store(tainted)
		telemetry.ExecutedPropagation.Store(executedPropagation)
		for counter, cnt := range executed {
			counter.Store(cnt)
		}
		config.TelemetryVerbosity = verbosity
	})

	telemetry.InstrumentedSource[constants.OriginHttpRequestQuery].Store(3)
	telemetry.InstrumentedPropagation.Store(4)
	telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakHash].Store(5)
	telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakCipher].Store(8)
	telemetry.ExecutedTainted.Store(6)
	telemetry.ExecutedPropagation.Store(7)
	telemetry.ExecutedSource.HttpRequestQuery.Store(9)
	telemetry.ExecutedSink.WeakHash.Store(10)
}

// buildTime are the submissions of the build-time metrics set by setCounters.
var buildTime = []submission{
	{"instrumented.source", []string{"source_type:http.request.query"}, 3},
	{"instrumented.propagation", nil, 4},
	{"instrumented.sink", []string{"vulnerability_type:WEAK_CIPHER"}, 8},
	{"instrumented.sink", []string{"vulnerability_type:WEAK_HASH"}, 5},
}

// runTime are the submissions of the run-time metrics set by setCounters
// (without "executed.propagation", which needs the DEBUG verbosity).
var runTime = []submission{
	{"executed.tainted", nil, 6},
	{"executed.source", []string{"source_type:http.request.query"}, 9},
	{"executed.sink", []string{"vulnerability_type:WEAK_HASH"}, 10},
}

func TestReportOff(t *testing.T) {
	setCounters(t)
	config.TelemetryVerbosity = config.LogLevelOff

	var got []submission
	heartbeat.Report(record(&got))

	assert.Empty(t, got)
	// The run-time counters are not reset.
	assert.Equal(t, uint64(6), telemetry.ExecutedTainted.Load())
}

func TestReportInformation(t *testing.T) {
	setCounters(t)
	config.TelemetryVerbosity = config.LogLevelInformation

	var got []submission
	heartbeat.Report(record(&got))
	assert.Equal(t, append(append([]submission(nil), buildTime...), runTime...), got)

	// The run-time counters are reset, except "executed.propagation", which is
	// only submitted with the DEBUG verbosity. The build-time counters are not.
	assert.Zero(t, telemetry.ExecutedTainted.Load())
	assert.Zero(t, telemetry.ExecutedSource.HttpRequestQuery.Load())
	assert.Zero(t, telemetry.ExecutedSink.WeakHash.Load())
	assert.Equal(t, uint64(7), telemetry.ExecutedPropagation.Load())

	// The next heartbeat submits the build-time metrics again, and no run-time
	// metric (they are zero).
	got = nil
	heartbeat.Report(record(&got))
	assert.Equal(t, buildTime, got)
}

func TestReportDebug(t *testing.T) {
	setCounters(t)
	config.TelemetryVerbosity = config.LogLevelDebug

	var got []submission
	heartbeat.Report(record(&got))
	want := append(append([]submission(nil), buildTime...), runTime...)
	want = append(want, submission{"executed.propagation", nil, 7})
	assert.Equal(t, want, got)
	assert.Zero(t, telemetry.ExecutedPropagation.Load())
}

func TestCount(t *testing.T) {
	// The handle of a metric is valid before the telemetry client starts. This
	// only checks that the submission does not panic.
	assert.NotPanics(t, func() {
		heartbeat.Count(instrumentation.Instance.TelemetryMetrics())("test.metric", nil, 1)
	})
}
