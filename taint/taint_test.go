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
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

type namedString string
type namedBytes []byte

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

func TestTaintStringAndVisit(t *testing.T) {
	ctx, scope := activeScope(t)
	original := namedString("attacker")
	managed := taint.TaintString(ctx, taint.Source{
		Origin: taint.OriginHttpRequestHeader,
		Name:   "X-Input",
	}, original)
	require.Equal(t, original, managed)
	require.False(t, unsafe.StringData(string(original)) == unsafe.StringData(string(managed)))
	require.True(t, taint.IsTaintedString(managed))

	calls := 0
	visited := taint.VisitString(managed, func(got taint.Range) bool {
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
	require.False(t, taint.VisitString(managed, nil))

	scope.Finish()
	require.False(t, taint.IsTaintedString(managed))
}

func TestTaintBytesCopiesImmutableSourceValue(t *testing.T) {
	ctx, _ := activeScope(t)
	original := namedBytes(make([]byte, 6, 12))
	copy(original, "attack")
	managed := taint.TaintBytes(ctx, taint.Source{
		Origin: taint.OriginHttpRequestBody,
		Name:   "body",
	}, original)
	require.Equal(t, []byte("attack"), []byte(managed))
	require.Equal(t, cap(original), cap(managed))
	require.False(t, unsafe.SliceData([]byte(original)) == unsafe.SliceData([]byte(managed)))

	managed[0] = 'A'
	require.True(t, taint.IsTaintedBytes(managed))
	var got taint.Range
	calls := 0
	require.True(t, taint.VisitBytes(managed, func(r taint.Range) bool {
		calls++
		got = r
		return false
	}))
	require.Equal(t, 1, calls)
	require.Equal(t, "attack", got.Source.Value)
	require.Equal(t, "Attack", string(managed))
}

func TestTaintDropsInvalidAndOneByteSources(t *testing.T) {
	ctx, _ := activeScope(t)
	one := namedString("x")
	require.Equal(t, one, taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter}, one))
	require.False(t, taint.IsTaintedString(one))

	value := namedString("value")
	require.Equal(t, value, taint.TaintString(ctx, taint.Source{}, value))
	require.False(t, taint.IsTaintedString(value))
}

func TestTaintRejectsOversizedValues(t *testing.T) {
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
}

func TestVisitRaceFinishReturnsCompleteSourceOrNothing(t *testing.T) {
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
			taint.VisitString(managed, func(got taint.Range) bool {
				if got.Source.Origin != taint.OriginHttpRequestParameter || got.Source.Name != "query" || got.Source.Value != "attacker" {
					invalid.Store(true)
				}
				return true
			})
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
		taint.VisitString(managed, noOpVisitor)
	}))
	clean := namedString("not-tainted")
	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.IsTaintedString(clean)
	}))
}

func BenchmarkStringLookup(b *testing.B) {
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
			taint.VisitString(managed, noOpVisitor)
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
