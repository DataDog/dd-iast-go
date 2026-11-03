// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package heartbeat reports the IAST telemetry metrics of
// [github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry] at each
// telemetry heartbeat. It is not in the telemetry package, so that the
// telemetry package stays dependency-free (see its documentation).
package heartbeat

import (
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

// CountFunc submits value to the count metric name of the IAST telemetry
// namespace, with tags.
type CountFunc func(name string, tags []string, value float64)

// Count returns a [CountFunc] that submits the metrics to c.
func Count(c instrumentation.TelemetryMetrics) CountFunc {
	return func(name string, tags []string, value float64) {
		c.Count(instrumentation.TelemetryNamespaceIAST, name, tags).Submit(value)
	}
}

// Report submits the IAST telemetry metrics with count, as configured by
// [config.TelemetryVerbosity]. The build-time metrics are submitted at each
// heartbeat (they do not change). The run-time metrics are reset to zero when
// they are submitted, so each heartbeat submits the counts since the previous
// one. A metric with a zero count is not submitted (except
// "instrumented.propagation").
func Report(count CountFunc) {
	if config.TelemetryVerbosity == config.LogLevelOff {
		return
	}

	for i := range telemetry.InstrumentedSource {
		cnt := telemetry.InstrumentedSource[i].Load()
		if cnt == 0 {
			continue
		}
		origin := constants.Origin(i)
		count("instrumented.source", []string{instrumentation.TelemetryTagSourceType + ":" + origin.String()}, float64(cnt))
	}
	count("instrumented.propagation", nil, float64(telemetry.InstrumentedPropagation.Load()))
	for i := range telemetry.InstrumentedSink {
		cnt := telemetry.InstrumentedSink[i].Load()
		if cnt == 0 {
			continue
		}
		vulnType := constants.VulnerabilityType(i)
		count("instrumented.sink", []string{instrumentation.TelemetryTagVulnerabilityType + ":" + vulnType.String()}, float64(cnt))
	}

	if cnt := telemetry.ExecutedTainted.Swap(0); cnt != 0 {
		count("executed.tainted", nil, float64(cnt))
	}
	for origin, counter := range telemetry.ExecutedSource.Each {
		cnt := counter.Swap(0)
		if cnt == 0 {
			continue
		}
		count("executed.source", []string{instrumentation.TelemetryTagSourceType + ":" + origin.String()}, float64(cnt))
	}
	for vulnType, counter := range telemetry.ExecutedSink.Each {
		cnt := counter.Swap(0)
		if cnt == 0 {
			continue
		}
		count("executed.sink", []string{instrumentation.TelemetryTagVulnerabilityType + ":" + vulnType.String()}, float64(cnt))
	}

	if config.TelemetryVerbosity != config.LogLevelDebug {
		return
	}
	if cnt := telemetry.ExecutedPropagation.Swap(0); cnt != 0 {
		count("executed.propagation", nil, float64(cnt))
	}
}
