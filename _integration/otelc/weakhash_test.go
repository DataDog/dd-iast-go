// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package otelc_test

import (
	"crypto"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "crypto/sha1" // Linked so the count of instrumented sinks is the same for every run.

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/instrumentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	config.Enabled = true
	config.RequestSamplingPct = 100
	// The same operation is run several times (and with several settings).
	config.DeduplicationEnabled = false
}

// requireInstrumented fails the test if the binary was not built with a
// compile-time instrumentation tool. This module only makes sense when it is
// built with otelc or with Orchestrion, so a plain "go test" is a mistake: the
// test fails instead of skipping, to avoid a silent pass in CI.
func requireInstrumented(t *testing.T) {
	t.Helper()
	if !build.Instrumented() {
		t.Fatal("this binary was not built with otelc or Orchestrion; " +
			"use 'go tool otelc go test ./...' or 'go tool orchestrion go test ./...'")
	}
}

func TestBuildTool(t *testing.T) {
	requireInstrumented(t)
	t.Logf("built with: %s", build.Tool())
	assert.Contains(t, []string{build.ToolOtelc, build.ToolOrchestrion}, build.Tool())
}

// TestInstrumentedSinks checks the number of instrumented sinks that was
// recorded at build time. Only crypto/md5 (2 sinks) is ported to otelc for now;
// crypto/sha1 (2 sinks) is instrumented by Orchestrion only.
func TestInstrumentedSinks(t *testing.T) {
	requireInstrumented(t)

	expected := map[string]uint{
		build.ToolOtelc:       2, // md5.New, md5.Sum
		build.ToolOrchestrion: 4, // md5.New, md5.Sum, sha1.New, sha1.Sum
	}[build.Tool()]
	assert.Equal(t, expected, telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakHash])

	if build.Tool() != build.ToolOtelc {
		// Orchestrion also instruments the weak ciphers of the standard library.
		return
	}
	// Nothing else is instrumented with otelc yet, so nothing else is counted.
	for i, count := range telemetry.InstrumentedSink {
		if constants.VulnerabilityType(i) != constants.VulnerabilityTypeWeakHash {
			assert.Zero(t, count, "unexpected sink count for %s", constants.VulnerabilityType(i))
		}
	}
}

// TestMatchedRules checks that otelc matched exactly the rules that are expected
// for crypto/md5. This is the guard for the count of instrumented sinks: the file
// that otelc copies into crypto/md5 registers a fixed count, which must be equal
// to the number of "inject_code" rules that really matched.
func TestMatchedRules(t *testing.T) {
	requireInstrumented(t)
	if build.Tool() != build.ToolOtelc {
		t.Skip("matched rules are only reported by otelc")
	}

	data, err := os.ReadFile(filepath.Join(".otelc-build", "matched.json"))
	require.NoError(t, err, "otelc writes the matched rules in this file during the build")

	var sets []struct {
		ModulePath string `json:"module_path"`
		RawRules   map[string][]struct {
			Name string `json:"name"`
		} `json:"raw_rules"`
		FileRules []struct {
			Name string `json:"name"`
			File string `json:"file"`
		} `json:"file_rules"`
	}
	require.NoError(t, json.Unmarshal(data, &sets))

	var injected, files []string
	for _, set := range sets {
		if set.ModulePath != "crypto/md5" {
			continue
		}
		for _, rules := range set.RawRules {
			for _, rule := range rules {
				injected = append(injected, rule.Name)
			}
		}
		for _, rule := range set.FileRules {
			files = append(files, rule.File)
		}
	}
	assert.ElementsMatch(t, []string{"md5_new", "md5_sum"}, injected)
	assert.Equal(t, []string{"otelc_decl_md5.go"}, files)
	assert.EqualValues(t, len(injected), telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakHash])
}

func TestMD5(t *testing.T) {
	requireInstrumented(t)

	digest := [md5.Size]byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92}

	for _, stackTrace := range []bool{true, false} {
		t.Run(fmt.Sprintf("stack_trace=%t", stackTrace), func(t *testing.T) {
			original := config.StackTraceEnabled
			config.StackTraceEnabled = stackTrace
			t.Cleanup(func() { config.StackTraceEnabled = original })

			t.Run("md5.Sum", func(t *testing.T) {
				mockTracer := mocktracer.Start()
				t.Cleanup(mockTracer.Stop)

				assert.Equal(t, digest, indirectCall1(md5.Sum, []byte("hello")))

				event, span := singleVulnerabilityEvent(t, mockTracer)
				assertWeakHash(t, event, span, stackTrace, "indirectCall1[...]")
			})

			t.Run("md5.New", func(t *testing.T) {
				mockTracer := mocktracer.Start()
				t.Cleanup(mockTracer.Stop)

				h := indirectCall0(md5.New)
				_, err := h.Write([]byte("hello"))
				require.NoError(t, err)
				assert.Equal(t, digest[:], h.Sum(nil))

				event, span := singleVulnerabilityEvent(t, mockTracer)
				assertWeakHash(t, event, span, stackTrace, "indirectCall0[...]")
			})
		})
	}
}

// TestMD5Method checks that the (*digest).Sum method of crypto/md5 is NOT a
// sink: only md5.New and the md5.Sum function are.
func TestMD5Method(t *testing.T) {
	requireInstrumented(t)

	h := md5.New() // Instrumented, outside of the traced section.

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	_, err := h.Write([]byte("hello"))
	require.NoError(t, err)
	_ = h.Sum(nil)
	_ = h.Sum([]byte{1, 2, 3})

	assert.Empty(t, mockTracer.FinishedSpans())
}

// TestCryptoHashNew checks the `crypto.Hash.New` path (the hash goes through
// the registry, and ends up calling md5.New).
func TestCryptoHashNew(t *testing.T) {
	requireInstrumented(t)

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	h := indirectCall0(crypto.MD5.New)
	_, err := h.Write([]byte("hello"))
	require.NoError(t, err)

	event, span := singleVulnerabilityEvent(t, mockTracer)
	require.Len(t, event.Vulnerabilities, 1)
	loc := event.Vulnerabilities[0].Location
	t.Logf("location: %+v", loc)
	// The frame of crypto.Hash.New is skipped, and the caller is reported.
	assert.Equal(t, "/path/to/file.go", loc.Path)
	assert.Equal(t, "github.com/DataDog/dd-iast-go/_integration/otelc_test.indirectCall0[...]", loc.Method)
	assert.Equal(t, span.Context().SpanID(), loc.SpanID)
}

func singleVulnerabilityEvent(t *testing.T, mockTracer mocktracer.Tracer) (model.Event, *mocktracer.Span) {
	t.Helper()
	spanList := mockTracer.FinishedSpans()
	require.Len(t, spanList, 1)
	span := spanList[0]
	require.Equal(t, "vulnerability", span.OperationName())
	require.Equal(t, "vulnerability", span.Tag(ext.SpanType))
	require.Equal(t, 1.0, span.Tag(spans.SpanTagEnabled))

	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(span.Tag(spans.SpanTagJson).(string)), &event))
	return event, span
}

func assertWeakHash(t *testing.T, event model.Event, span *mocktracer.Span, stackTrace bool, function string) {
	t.Helper()

	var stackID string
	if stackTrace {
		stacks := span.Tag("_dd.stack").(map[string][]*instrumentation.StackTrace)["vulnerability"]
		require.Len(t, stacks, 1)
		stackID = stacks[0].ID
		// The first frame of the recorded stack is the caller of the sink, and not
		// a frame of the library. (Its index differs: Orchestrion keeps the index
		// of the stack before the tracer removes the generated frame, otelc has
		// no generated frame and the index is shifted to 0 by IAST.)
		require.NotEmpty(t, stacks[0].Frames)
		assert.Equal(t, function, stacks[0].Frames[0].Function)
		assert.Equal(t, "github.com/DataDog/dd-iast-go/_integration/otelc_test", stacks[0].Frames[0].Namespace)
	}

	require.Len(t, event.Vulnerabilities, 1)
	assert.Equal(t,
		model.Event{
			Vulnerabilities: []model.Vulnerability{
				model.NewVulnerability(
					constants.VulnerabilityTypeWeakHash,
					model.NewEvidenceString("MD5"),
					&model.Location{
						SpanID:  span.Context().SpanID(),
						StackID: stackID,
						Path:    "/path/to/file.go",
						Line:    1337,
						Method:  "github.com/DataDog/dd-iast-go/_integration/otelc_test." + function,
					},
				),
			},
		},
		event)
}

// indirectCall0 calls the provided function and returns its result. This must
// remain last in the file, as it includes a line directive to ensure the call
// site is stable and independent from the actual filesystem location of the
// source under test.
func indirectCall0[T any](fn func() T) T {
	return /*line /path/to/file.go:1337*/ fn()
}

// indirectCall1 is like indirectCall0 for functions that take one argument.
func indirectCall1[A any, T any](fn func(A) T, arg A) T {
	return /*line /path/to/file.go:1337*/ fn(arg)
}
