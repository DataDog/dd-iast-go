// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// These tests need a woven runtime (plan runtime-operator-hooks, section 9.1
// item 1). Run them with:
//
//	go tool orchestrion go test ./iast/runtime/...
//
// An unwoven run skips them. With DD_IAST_REQUIRE_WOVEN=1, an unwoven run
// fails, and TestMain fails when no test entered the bridge.

const requireWovenEnv = "DD_IAST_REQUIRE_WOVEN"

func TestMain(m *testing.M) {
	runtimebridge.CountEntries(true)
	code := m.Run()
	if code == 0 && os.Getenv(requireWovenEnv) == "1" && runtimebridge.Snapshot().HookEntries == 0 {
		fmt.Fprintln(os.Stderr, requireWovenEnv+"=1: no test entered the runtime bridge, the runtime is not woven")
		code = 1
	}
	os.Exit(code)
}

// Sinks keep results live and make them escape to the heap.
var (
	sinkString string
	sinkBytes  []byte
	sinkRunes  []rune
	sinkInt    int
)

// entries returns the number of bridge entries.
func entries() uint64 { return runtimebridge.Snapshot().HookEntries }

// wovenChecked is true after one check found a woven runtime.
var wovenChecked bool

// requireWoven skips t when the runtime is not woven, or fails t when
// DD_IAST_REQUIRE_WOVEN=1.
func requireWoven(t *testing.T) {
	t.Helper()
	if wovenChecked {
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
	// The probe scope finishes before the test starts, so that the test
	// starts with no live root (gate off).
	woven := false
	t.Run("woven probe", func(t *testing.T) {
		ctx := begin(t)
		value := taintString(t, ctx, "probe", "woven-probe")
		before := entries()
		sinkString = heapConcat2("x", value)
		woven = entries() != before
	})
	sinkString = ""
	if !woven {
		skip("the runtime is not woven")
	}
	wovenChecked = true
}

// begin starts one request scope for t. The scope finishes at the end of t.
func begin(t testing.TB) context.Context {
	t.Helper()
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	require.True(t, scope.Active())
	t.Cleanup(func() {
		scope.Finish()
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})
	return ctx
}

func taintString(t testing.TB, ctx context.Context, name, value string) string {
	t.Helper()
	managed := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: name}, value)
	require.True(t, taint.IsTaintedString(managed))
	return managed
}

func taintBytes(t testing.TB, ctx context.Context, name string, value []byte) []byte {
	t.Helper()
	managed := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: name}, value)
	require.True(t, taint.IsTaintedBytes(managed))
	return managed
}

// span is one tainted interval of a value, with the name of its source.
type span struct {
	start, length uint32
	name          string
}

// spansOf returns the tainted intervals of a string, in the order of the
// store, for all owners.
func spansOf(value string) []span {
	var out []span
	request.VisitString(value, func(r request.ResolvedRange) bool {
		out = append(out, span{r.Start, r.Length, r.Source.Name})
		return true
	})
	return out
}

func bytesSpansOf(value []byte) []span {
	var out []span
	request.VisitBytes(value, func(r request.ResolvedRange) bool {
		out = append(out, span{r.Start, r.Length, r.Source.Name})
		return true
	})
	return out
}

// runeRanges returns the ranges of a []rune root, in byte coordinates of the
// rune array.
func runeRanges(value []rune) [][2]uint32 {
	s := store.RuntimeStore()
	key, ok := store.RunesKey(value)
	if s == nil || !ok {
		return nil
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return nil
	}
	var out [][2]uint32
	for i := 0; i < snapshot.Len(); i++ {
		entry, _ := snapshot.At(i)
		for j := 0; j < entry.Ranges.Len(); j++ {
			r, _ := entry.Ranges.At(j)
			out = append(out, [2]uint32{r.Start, r.Length})
		}
	}
	return out
}

// ownerOf returns the store owner and the source ID of the first range of a
// tainted string.
func ownerOf(t testing.TB, value string) (store.Owner, ranges.SourceID) {
	t.Helper()
	s := store.RuntimeStore()
	require.NotNil(t, s)
	key, ok := store.StringKey(value)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	r, ok := entry.Ranges.At(0)
	require.True(t, ok)
	owner, ok := entry.Handle(s)
	require.True(t, ok)
	return owner, r.SourceID
}

// adoptString adopts a clone of value for the owner of source, with one range
// of the source for each interval of spans.
func adoptString(t testing.TB, source, value string, spans ...[2]uint32) string {
	t.Helper()
	owner, id := ownerOf(t, source)
	raw := make([]ranges.Range, len(spans))
	for i, s := range spans {
		raw[i] = ranges.Range{Start: s[0], Length: s[1], SourceID: id}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, raw, uint32(len(value))).Valid)
	managed := strings.Clone(value)
	_, ok := owner.AdoptString(managed, &set)
	require.True(t, ok)
	return managed
}

// adoptRunes adopts a fresh []rune allocation for the owner of source, with
// one range on the runes [from, to).
func adoptRunes(t testing.TB, source string, value []rune, from, to int) {
	t.Helper()
	owner, id := ownerOf(t, source)
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Start: uint32(4 * from), Length: uint32(4 * (to - from)), SourceID: id}}, uint32(4*cap(value))).Valid)
	_, ok := owner.AdoptRunes(value, &set)
	require.True(t, ok)
}

// heapRunes returns a new heap []rune with the runes of value. It does not use
// a runtime conversion, so the hook does not see it.
//
//go:noinline
func heapRunes(value string) []rune {
	out := make([]rune, 0, len(value))
	for _, r := range value {
		out = append(out, r)
	}
	sinkRunes = out
	return out
}

// heapBytes returns a new heap []byte with the bytes of value, without a
// runtime conversion.
//
//go:noinline
func heapBytes(value string) []byte {
	out := make([]byte, len(value))
	copy(out, value)
	sinkBytes = out
	return out
}

func stringData(s string) uintptr { return uintptr(unsafe.Pointer(unsafe.StringData(s))) }

func bytesData(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

func runesData(r []rune) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(r))) }

// keyTainted reports whether the store has a live range for [p, p+n). It
// takes a pointer as uintptr, so the value does not escape.
func keyTainted(p uintptr, n int) bool {
	s := store.RuntimeStore()
	if s == nil || n <= 0 {
		return false
	}
	return s.Confirm(p, uint32(n)) == runtimebridge.ConfirmTainted
}

// probe is the result of an operation whose result stays in the function.
type probe struct {
	tainted bool
}

// repeat returns n copies of s.
func repeat(s string, n int) string { return strings.Repeat(s, n) }
