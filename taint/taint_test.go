// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package taint_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type namedString string
type namedBytes []byte

// requireBits skips the test when the heap taint bits are not in the
// runtime (a build without Orchestrion, or a platform that is not
// supported).
func requireBits(tb testing.TB) {
	tb.Helper()
	if !built.WithOrchestrion {
		tb.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if !heapbits.Enabled() {
		tb.Skip("the heap taint bits are not supported on this platform")
	}
}

func activeScope(t *testing.T) (context.Context, *request.Scope) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	require.True(t, scope.Active())
	t.Cleanup(scope.Finish)
	return ctx, scope
}

// heapCopy returns a heap copy of the parts with their taint bits, as the
// runtime concatenation hook does (make and copy do not copy the bits).
func heapCopy(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, n)
	at := 0
	for _, p := range parts {
		copy(out[at:], p)
		if len(p) != 0 {
			heapbits.Copy(unsafe.Pointer(&out[at]), unsafe.Pointer(&p[0]), uintptr(len(p)))
		}
		at += len(p)
	}
	return out
}

// view returns the bytes of s without a copy.
func view(s string) []byte { return unsafe.Slice(unsafe.StringData(s), len(s)) }

// escape makes a value escape to the heap.
var escape atomic.Pointer[string]

func asString(b []byte) string { return unsafe.String(unsafe.SliceData(b), len(b)) }

func TestTaintStringAndVisit(t *testing.T) {
	requireBits(t)
	ctx, scope := activeScope(t)
	original := namedString("attacker") // read-only data: TaintString clones
	managed := taint.TaintString(ctx, taint.Source{
		Origin: taint.OriginHttpRequestHeader,
		Name:   "X-Input",
	}, original)
	require.Equal(t, original, managed)
	require.False(t, unsafe.StringData(string(original)) == unsafe.StringData(string(managed)))
	require.True(t, taint.IsTaintedString(managed))
	require.False(t, taint.IsTaintedString(original))

	calls := 0
	visited := taint.VisitString(ctx, managed, func(got taint.Range) bool {
		calls++
		require.Equal(t, uint32(0), got.Start)
		require.Equal(t, uint32(len(managed)), got.Length)
		require.Equal(t, taint.OriginHttpRequestHeader, got.Source.Origin)
		require.Equal(t, "X-Input", got.Source.Name)
		require.Equal(t, "attacker", got.Source.Value)
		require.Equal(t, taint.Marks{}, got.Marks)
		require.True(t, taint.IsTaintedString(managed), "visitor must be reentrant")
		return false
	})
	require.True(t, visited)
	require.Equal(t, 1, calls)
	require.False(t, taint.VisitString(ctx, managed, nil))

	scope.Finish()
	require.False(t, taint.IsTaintedString(managed), "IsTainted is false after Finish")
	require.False(t, taint.VisitString(ctx, managed, func(taint.Range) bool { return true }))
}

func TestTaintStringInPlace(t *testing.T) {
	requireBits(t)
	ctx, _ := activeScope(t)
	value := strings.Clone("heap-value")
	escape.Store(&value) // else the compiler can put the clone on the stack
	tainted := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, value)
	require.True(t, unsafe.StringData(value) == unsafe.StringData(tainted), "heap values are tainted in place")
	require.True(t, taint.IsTaintedString(value))
	require.True(t, taint.IsTaintedString(value[2:6]), "a substring has the same memory")
}

func TestTaintBytesInPlaceAndOverwrite(t *testing.T) {
	requireBits(t)
	ctx, _ := activeScope(t)
	original := namedBytes(make([]byte, 6, 12))
	copy(original, "attack")
	managed := taint.TaintBytes(ctx, taint.Source{
		Origin: taint.OriginHttpRequestBody,
		Name:   "body",
	}, original)
	require.Equal(t, []byte("attack"), []byte(managed))
	require.Equal(t, cap(original), cap(managed))
	require.True(t, unsafe.SliceData([]byte(original)) == unsafe.SliceData([]byte(managed)), "heap bytes are tainted in place")

	// The application changes one byte: the bits stay, but the changed
	// byte is no longer equal to the source.
	managed[0] = 'A'
	require.True(t, taint.IsTaintedBytes(managed))
	var got []taint.Range
	require.True(t, taint.VisitBytes(ctx, managed, func(r taint.Range) bool {
		got = append(got, r)
		return true
	}))
	require.Len(t, got, 1)
	require.Equal(t, uint32(1), got[0].Start)
	require.Equal(t, uint32(5), got[0].Length)
	require.Equal(t, "attack", got[0].Source.Value, "the source value is a copy")
	require.Equal(t, "Attack", string(managed))
}

func TestTaintDropsInvalidAndOneByteSources(t *testing.T) {
	requireBits(t)
	ctx, _ := activeScope(t)
	one := namedString(strings.Clone("x"))
	require.Equal(t, one, taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter}, one))
	require.False(t, taint.IsTaintedString(one))

	value := namedString(strings.Clone("value"))
	require.Equal(t, value, taint.TaintString(ctx, taint.Source{}, value))
	require.False(t, taint.IsTaintedString(value))
}

func TestTaintRejectsOversizedValues(t *testing.T) {
	requireBits(t)
	ctx, _ := activeScope(t)
	oversized := namedString(strings.Repeat("x", (64<<10)+1))
	require.Equal(t, oversized, taint.TaintString(ctx, taint.Source{
		Origin: taint.OriginHttpRequestParameter,
	}, oversized))
	require.False(t, taint.IsTaintedString(oversized))
}

func TestInactiveContextReturnsOriginal(t *testing.T) {
	original := namedString("value")
	require.Equal(t, original, taint.TaintString(context.Background(), taint.Source{
		Origin: taint.OriginHttpRequestParameter,
	}, original))
	require.False(t, taint.IsTaintedString(original))
	bytesValue := []byte("value")
	require.Equal(t, bytesValue, taint.TaintBytes(context.Background(), taint.Source{
		Origin: taint.OriginHttpRequestParameter,
	}, bytesValue))
	require.False(t, taint.IsTaintedBytes(bytesValue))
}

func TestVisitRaceFinishReturnsCompleteSourceOrNothing(t *testing.T) {
	requireBits(t)
	ctx, scope := activeScope(t)
	managed := taint.TaintString(ctx, taint.Source{
		Origin: taint.OriginHttpRequestParameter,
		Name:   "query",
	}, "attacker")
	require.True(t, taint.IsTaintedString(managed))

	var invalid atomic.Bool
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for range 1_000 {
			taint.VisitString(ctx, managed, func(got taint.Range) bool {
				if got.Source.Origin != taint.OriginHttpRequestParameter || got.Source.Name != "query" || got.Source.Value != "attacker" {
					invalid.Store(true)
				}
				return true
			})
			taint.IsTaintedString(managed)
		}
	}()
	scope.Finish()
	wait.Wait()
	require.False(t, invalid.Load(), "finish race exposed partial or reused source metadata")
	require.False(t, taint.IsTaintedString(managed))
}

func TestZeroMarksHasNoSecureVulnerability(t *testing.T) {
	var marks taint.Marks
	require.False(t, marks.Has(taint.VulnerabilityTypeSqlInjection))
	require.False(t, marks.Has(0))
}

func TestPublicConstantAliases(t *testing.T) {
	require.Equal(t, "http.request.body", taint.OriginHttpRequestBody.String())
	require.Equal(t, "SQL_INJECTION", taint.VulnerabilityTypeSqlInjection.String())
}

func noOpVisitor(taint.Range) bool { return true }

func TestLookupDoesNotAllocate(t *testing.T) {
	requireBits(t)
	ctx, _ := activeScope(t)
	managed := taint.TaintString(ctx, taint.Source{
		Origin: taint.OriginHttpRequestParameter,
		Name:   "query",
	}, namedString("attacker"))
	require.True(t, taint.IsTaintedString(managed))

	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.IsTaintedString(managed)
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.VisitString(ctx, managed, noOpVisitor)
	}))
	clean := namedString("not-tainted")
	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.IsTaintedString(clean)
	}))
}

func BenchmarkStringLookup(b *testing.B) {
	requireBits(b)
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	defer func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	}()
	ctx, scope, _ := request.Begin(context.Background())
	managed := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter}, "attacker")

	b.Run("hit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			taint.IsTaintedString(managed)
		}
	})
	b.Run("miss", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			taint.IsTaintedString("not-tainted")
		}
	})
	b.Run("visit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			taint.VisitString(ctx, managed, noOpVisitor)
		}
	})
	scope.Finish()
	b.Run("no-active", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			taint.IsTaintedString("not-tainted")
		}
	})
}
