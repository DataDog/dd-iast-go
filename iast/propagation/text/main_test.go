// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The tests of this package need the woven standard library (the aspects of
// orchestrion.yml, of iast/runtime and of internal/taint/heapbits). Run them
// with:
//
//	go tool orchestrion go test ./iast/propagation/text
//
// An unwoven run skips them. With DD_IAST_REQUIRE_WOVEN=1, an unwoven run
// fails.

const requireWovenEnv = "DD_IAST_REQUIRE_WOVEN"

func init() {
	// The tests taint more memory than an application. The budget must be set
	// before the first taint.
	heapbits.SetBudget(heapbits.MaxBudget)
}

var wovenChecked atomic.Bool

// requireWoven skips t when the hooks are not woven, or fails t when
// DD_IAST_REQUIRE_WOVEN=1. It fails when the heap bits are woven, but the
// hooks of this package do not propagate.
func requireWoven(t testing.TB) {
	t.Helper()
	if wovenChecked.Load() {
		return
	}
	skip := func(reason string) {
		t.Helper()
		if os.Getenv(requireWovenEnv) == "1" {
			t.Fatalf("%s=1: %s", requireWovenEnv, reason)
		}
		t.Skip(reason + ": use `go tool orchestrion go test` to run this test")
	}
	if !built.WithOrchestrion {
		skip("the test is not built with Orchestrion")
	}
	if !heapbits.Enabled() {
		skip("the heap taint bits are not enabled (not woven, or platform not supported)")
	}
	probe := []byte("woven-probe")
	escapeBytes(probe)
	require.True(t, heapbits.SetBytes(probe))
	got := strings.Clone(unsafe.String(unsafe.SliceData(probe), len(probe)))
	if len(stringSpans(got)) == 0 {
		t.Fatal("the heap bits are woven, but strings.Clone of a tainted value did not propagate: the aspects of iast/propagation/text are not woven")
	}
	wovenChecked.Store(true)
}

// escaped keeps values alive and makes them escape to the heap.
var escaped atomic.Pointer[[]byte]

func escapeBytes(b []byte) { escaped.Store(&b) }

// begin starts an active request analysis for the test (sampling 100 %).
func begin(t *testing.T) request.Analysis {
	t.Helper()
	requireWoven(t)
	enabled, sampling, maxConcurrent := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = enabled, sampling, maxConcurrent
	})
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = request.MaxAnalyses
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	a, ok := scope.Analysis()
	require.True(t, ok)
	return a
}

// source registers a query parameter source and returns the tainted value
// (heap memory).
func source(t *testing.T, a request.Analysis, name, value string) string {
	t.Helper()
	v, ok := a.TaintString(constants.OriginHttpRequestParameter, name, value)
	require.True(t, ok, "taint %s=%q", name, value)
	require.Equal(t, []span{{0, len(value)}}, stringSpans(v))
	return v
}

// sourceBytes registers a query parameter source and returns the tainted
// bytes (heap memory).
func sourceBytes(t *testing.T, a request.Analysis, name, value string) []byte {
	t.Helper()
	b := []byte(value)
	escapeBytes(b)
	v, ok := a.TaintBytes(constants.OriginHttpRequestParameter, name, b)
	require.True(t, ok, "taint %s=%q", name, value)
	require.Equal(t, []span{{0, len(value)}}, bytesSpans(v))
	return v
}

// span is a range [start, end) of tainted bytes.
type span struct{ start, end int }

func spansOf(p unsafe.Pointer, n int) []span {
	var out []span
	size := uintptr(n)
	for off := heapbits.Next(p, size, 0); off < size; {
		end := heapbits.NextClean(p, size, off)
		out = append(out, span{int(off), int(end)})
		off = heapbits.Next(p, size, end)
	}
	return out
}

func stringSpans(s string) []span {
	return spansOf(unsafe.Pointer(unsafe.StringData(s)), len(s))
}

func bytesSpans(b []byte) []span {
	return spansOf(unsafe.Pointer(unsafe.SliceData(b)), len(b))
}

// attributed returns the segments of value for the analysis a, as
// "start-end=name" ("foreign" for a foreign segment).
func attributed(t *testing.T, a request.Analysis, value string) []string {
	t.Helper()
	var r request.Attribution
	a.AttributeString(value, &r)
	var out []string
	for i := 0; i < r.N; i++ {
		s := r.Segments[i]
		label := "foreign"
		if src, ok := r.Source(i); ok {
			label = src.Name
		}
		out = append(out, fmt.Sprintf("%d-%d=%s", s.Start, s.Start+s.Length, label))
	}
	return out
}

func attributedBytes(t *testing.T, a request.Analysis, value []byte) []string {
	t.Helper()
	return attributed(t, a, unsafe.String(unsafe.SliceData(value), len(value)))
}

// sameData reports whether the 2 values start at the same address.
func sameData(a, b string) bool {
	return unsafe.StringData(a) == unsafe.StringData(b)
}
