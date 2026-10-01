// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

// confirmMode selects the behavior of the test binding (see withTestBinding).
type confirmMode int32

const (
	confirmNormal confirmMode = iota
	confirmPanic
	confirmUnknown
	confirmNested
	confirmGrow
	confirmGateOff
)

var (
	testConfirmMode  atomic.Int32
	testCallbackMode atomic.Int32
	confirmCalls     atomic.Uint64
	nestedEntries    atomic.Int64
	grows            atomic.Uint64
	nestedSink       atomic.Pointer[string]
)

// withTestBinding installs, for the duration of t, a binding and callbacks
// that wrap the ones of the process store. The modes select a test behavior;
// the normal mode calls the process store.
func withTestBinding(t *testing.T) {
	t.Helper()
	b, c := runtimebridge.CurrentForTest()
	require.NotNil(t, b)
	require.NotNil(t, c)
	bound, callbacks := *b, *c
	wrapped := &runtimebridge.Binding{
		Filter: bound.Filter,
		Confirm: func(p uintptr, n uint32) runtimebridge.ConfirmResult {
			confirmCalls.Add(1)
			switch confirmMode(testConfirmMode.Load()) {
			case confirmPanic:
				panic("test confirm panic")
			case confirmUnknown:
				return runtimebridge.ConfirmUnknown
			case confirmNested:
				nested()
			case confirmGrow:
				grow(4096)
			case confirmGateOff:
				runtimebridge.SwapGateForTest(0)
				return runtimebridge.ConfirmClean
			}
			return bound.Confirm(p, n)
		},
	}
	wrappedCallbacks := callbacks
	wrappedCallbacks.Concat = func(result string, operands []string) {
		switch confirmMode(testCallbackMode.Load()) {
		case confirmPanic:
			panic("test callback panic")
		case confirmNested:
			nested()
		case confirmGrow:
			grow(4096)
		}
		callbacks.Concat(result, operands)
	}
	restore := runtimebridge.ReplaceForTest(wrapped, runtimebridge.StringToSliceEnabled(), &wrappedCallbacks)
	t.Cleanup(func() {
		testConfirmMode.Store(int32(confirmNormal))
		testCallbackMode.Store(int32(confirmNormal))
		restore()
	})
}

// nested runs the 6 hooked operations inside the bridge. The recursion guard
// must keep them out of the bridge.
//
//go:noinline
func nested() {
	before := entries()
	s := strings.Repeat("n", 40) + "-nested"
	b := []byte(s)
	b2 := []byte(s + "-bytes")
	s2 := string(b) + string(b2)
	r := []rune(s2)
	s3 := string(r)
	nestedSink.Store(&s3)
	nestedEntries.Add(int64(entries() - before))
}

// grow uses about depth frames of stack, so that the goroutine stack grows
// and moves during the tainted path (plan section 3.8).
//
//go:noinline
func grow(depth int) int {
	var pad [64]byte
	pad[0] = byte(depth)
	if depth == 0 {
		grows.Add(1)
		return int(pad[0])
	}
	return grow(depth-1) + int(pad[0])
}

// TestStackResults checks the stack case of each operation: a clean result
// is not tainted; a tainted result goes to the heap and is tainted (plan
// sections 3.8 and R5). TestAllocs checks that the clean results stay on the
// stack.
func TestStackResults(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	s := taintString(t, ctx, "s", "short-value")
	b := taintBytes(t, ctx, "b", []byte("short-bytes"))
	r := heapRunes("short runes")
	adoptRunes(t, s, r, 0, len(r))
	clean, cleanB, cleanR := strings.Clone("clean-value"), heapBytes("clean-bytes"), heapRunes("clean runes")
	tainted := probe{tainted: true}
	stack := probe{}
	for name, test := range map[string][2]probe{
		"concat":            {stackConcat("x", clean), stackConcat("x", s)},
		"concatbytes":       {stackConcatBytes("x", clean), stackConcatBytes("x", s)},
		"slicebytetostring": {stackB2S(cleanB), stackB2S(b)},
		"stringtoslicebyte": {stackS2B(clean), stackS2B(s)},
		"slicerunetostring": {stackR2S(cleanR), stackR2S(r)},
		"stringtoslicerune": {stackS2R(clean), stackS2R(s)},
	} {
		require.Equal(t, stack, test[0], "%s: a clean result stays on the stack", name)
		require.Equal(t, tainted, test[1], "%s: a tainted result goes to the heap", name)
	}
}

// TestAllocs checks the allocation gates of plan section 9.3.
func TestAllocs(t *testing.T) {
	requireWoven(t)
	x, s := "x", strings.Clone("short-value")
	b, r := heapBytes("short-bytes"), heapRunes("short runes")
	stackAll := func() {
		sinkInt = stackConcatLen(x, s) + stackConcatBytesLen(x, s) + stackB2SLen(b) + stackS2BLen(s) + stackR2SLen(r) + stackS2RLen(s)
	}
	long := strings.Repeat("h", 40)
	require.Zero(t, runtimebridge.GateValue(), "no other test has a live root")
	require.Zero(t, testing.AllocsPerRun(200, stackAll), "gate off, stack operations")
	require.Equal(t, 1.0, testing.AllocsPerRun(200, func() { sinkString = heapConcat2(x, long) }), "gate off, heap concat")

	ctx := begin(t)
	_ = taintString(t, ctx, "unrelated", "unrelated-taint")
	require.NotZero(t, runtimebridge.GateValue())
	require.Zero(t, testing.AllocsPerRun(200, stackAll), "gate on, clean, stack operations")
	require.Equal(t, 1.0, testing.AllocsPerRun(200, func() { sinkString = heapConcat2(x, long) }), "gate on, clean, heap concat")

	ts := taintString(t, ctx, "s", "short-value")
	tb := taintBytes(t, ctx, "b", []byte("short-bytes"))
	tr := heapRunes("short runes")
	adoptRunes(t, ts, tr, 0, len(tr))
	for name, f := range map[string]func(){
		"concat":            func() { sinkInt = stackConcatLen(x, ts) },
		"concatbytes":       func() { sinkInt = stackConcatBytesLen(x, ts) },
		"slicebytetostring": func() { sinkInt = stackB2SLen(tb) },
		"stringtoslicebyte": func() { sinkInt = stackS2BLen(ts) },
		"slicerunetostring": func() { sinkInt = stackR2SLen(tr) },
		"stringtoslicerune": func() { sinkInt = stackS2RLen(ts) },
	} {
		// The forced heap result is the only allocation: the store has
		// fixed memory.
		require.Equal(t, 1.0, testing.AllocsPerRun(200, f), "gate on, tainted, stack %s", name)
	}
}

// TestSparseRoot checks plan section 9.1 item 4b: a clean window of a sparse
// tainted root stays on the stack with 0 allocations; a tainted window goes
// to the heap with the correct ranges.
func TestSparseRoot(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	source := taintString(t, ctx, "q", "source")
	root := adoptString(t, source, strings.Repeat("r", 64), [2]uint32{0, 4})
	clean := root[10:20]
	calls := confirmCalls.Load()
	withTestBinding(t)
	require.Equal(t, probe{}, stackConcat("x", clean))
	require.Greater(t, confirmCalls.Load(), calls, "the filter hit calls confirm")
	cleanBytes := unsafe.Slice(unsafe.StringData(root[40:]), 8)
	require.Zero(t, testing.AllocsPerRun(200, func() { sinkInt = stackConcatLen("x", clean) + stackB2SLen(cleanBytes) }))

	require.Equal(t, probe{tainted: true}, stackConcat("x", root[2:6]))
	require.Equal(t, []span{{1, 2, "q"}}, spansOf(heapConcat2("x", root[2:6])))
}

// TestConfirmUnknownForcesHeap checks plan section 9.1 item 4b: when confirm
// cannot take a lock (ConfirmUnknown), each hooked operation puts its result
// on the heap, and the result hook adopts it with the correct taint. A clean
// window of a sparse root (a filter hit) shows that the heap is forced by the
// unknown result: with the normal confirm, the same operations stay on the
// stack.
func TestConfirmUnknownForcesHeap(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintString(t, ctx, "q", "tnt")
	// Operands with a clean head (prefix) and a tainted tail, made before
	// the test binding is installed.
	const prefix = "pfx-"
	k := len(prefix)
	mixed := heapConcat2(prefix, value)
	mixedBytes := heapS2B(mixed)
	mixedRunes := heapS2R(mixed)
	require.Equal(t, []span{{4, 3, "q"}}, spansOf(mixed))
	require.Equal(t, []span{{4, 3, "q"}}, bytesSpansOf(mixedBytes))
	require.Equal(t, [][2]uint32{{16, 12}}, runeRanges(mixedRunes))
	// Clean windows of sparse roots: the filter hits, confirm is called.
	root := adoptString(t, value, strings.Repeat("r", 64), [2]uint32{0, 4})
	clean := root[10:20]
	cleanBytes := unsafe.Slice(unsafe.StringData(root[40:]), 8)
	runeRoot := heapRunes(strings.Repeat("u", 32))
	adoptRunes(t, value, runeRoot, 0, 2)
	cleanRunes := runeRoot[10:20]
	cleanOps := map[string]func(){
		"concat":            func() { sinkInt = stackConcatLen("x", clean) },
		"concatbytes":       func() { sinkInt = stackConcatBytesLen("x", clean) },
		"slicebytetostring": func() { sinkInt = stackB2SLen(cleanBytes) },
		"stringtoslicebyte": func() { sinkInt = stackS2BLen(clean) },
		"slicerunetostring": func() { sinkInt = stackR2SLen(cleanRunes) },
		"stringtoslicerune": func() { sinkInt = stackS2RLen(clean) },
	}
	withTestBinding(t)
	for name, f := range cleanOps {
		require.Zero(t, testing.AllocsPerRun(100, f), "%s: normal confirm, a clean window stays on the stack", name)
	}

	testConfirmMode.Store(int32(confirmUnknown))
	calls := confirmCalls.Load()
	want := split{head: false, tail: true}
	for name, got := range map[string]split{
		"concat":            stackConcatSplit(prefix, value),
		"concatbytes":       stackConcatBytesSplit(prefix, value),
		"slicebytetostring": stackB2SSplit(mixedBytes, k),
		"stringtoslicebyte": stackS2BSplit(mixed, k),
		"slicerunetostring": stackR2SSplit(mixedRunes, k),
		"stringtoslicerune": stackS2RSplit(mixed, k),
	} {
		require.Equal(t, want, got, "%s: the result is on the heap and has the taint of the tail only", name)
	}
	require.Greater(t, confirmCalls.Load(), calls, "the filter hits call confirm")
	for name, f := range map[string]func(){
		"concat":            func() { sinkInt = stackConcatLen("x", value) },
		"concatbytes":       func() { sinkInt = stackConcatBytesLen("x", value) },
		"slicebytetostring": func() { sinkInt = stackB2SLen(mixedBytes) },
		"stringtoslicebyte": func() { sinkInt = stackS2BLen(mixed) },
		"slicerunetostring": func() { sinkInt = stackR2SLen(mixedRunes) },
		"stringtoslicerune": func() { sinkInt = stackS2RLen(mixed) },
	} {
		require.Equal(t, 1.0, testing.AllocsPerRun(100, f), "%s: tainted operand, the heap is forced", name)
	}
	for name, f := range cleanOps {
		require.Equal(t, 1.0, testing.AllocsPerRun(100, f), "%s: unknown confirm forces the heap for a clean window", name)
	}
	cleanSplit := split{}
	require.Equal(t, cleanSplit, stackConcatSplit("x", clean), "a forced clean result is not tainted")
	require.Equal(t, cleanSplit, stackS2RSplit(clean, 1), "a forced clean result is not tainted")
	testConfirmMode.Store(int32(confirmNormal))
}

// TestForcedIndexFullIsNotTainted checks plan section 9.1 item 4b: when the
// index refuses a root (forced indexFull), the admission fails. The value is
// not tainted, no lookup reports it, the gate and the filter do not change,
// and the hooked operations see a clean operand (the stack results stay on
// the stack).
func TestForcedIndexFullIsNotTainted(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	source := taintString(t, ctx, "q", "source")
	owner, id := ownerOf(t, source)
	bound, _ := runtimebridge.CurrentForTest()
	gate, filter, full := runtimebridge.GateValue(), filterSum(bound.Filter), owner.Counters().IndexFull

	restore, ok := store.ForceIndexFullForTest()
	require.True(t, ok, "no other test hook is installed")
	value := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "full"}, "forced-index-full")
	bytesValue := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "full"}, heapBytes("forced-index-full"))
	runes := heapRunes("forced-index-full")
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: uint32(4 * len(runes)), SourceID: id}}, uint32(4*cap(runes))).Valid)
	_, runesOK := owner.AdoptRunes(runes, &set)
	restore()

	require.False(t, runesOK, "the rune root is refused")
	require.Equal(t, full+3, owner.Counters().IndexFull, "each refused root is an indexFull drop")
	require.False(t, taint.IsTaintedString(value))
	require.False(t, taint.IsTaintedBytes(bytesValue))
	require.False(t, keyTainted(stringData(value), len(value)), "no lookup reports the string")
	require.False(t, keyTainted(bytesData(bytesValue), len(bytesValue)), "no lookup reports the bytes")
	require.False(t, keyTainted(runesData(runes), 4*len(runes)), "no lookup reports the runes")
	require.Equal(t, gate, runtimebridge.GateValue(), "a refused root does not change the gate")
	require.Equal(t, filter, filterSum(bound.Filter), "a refused root leaves no filter count")

	for name, got := range map[string]probe{
		"concat":            stackConcat("x", value),
		"concatbytes":       stackConcatBytes("x", value),
		"slicebytetostring": stackB2S(bytesValue),
		"stringtoslicebyte": stackS2B(value),
		"slicerunetostring": stackR2S(runes),
		"stringtoslicerune": stackS2R(value),
	} {
		require.Equal(t, probe{}, got, "%s: the result is not tainted", name)
	}
	for name, f := range map[string]func(){
		"concat":            func() { sinkInt = stackConcatLen("x", value) },
		"concatbytes":       func() { sinkInt = stackConcatBytesLen("x", value) },
		"slicebytetostring": func() { sinkInt = stackB2SLen(bytesValue) },
		"stringtoslicebyte": func() { sinkInt = stackS2BLen(value) },
		"slicerunetostring": func() { sinkInt = stackR2SLen(runes) },
		"stringtoslicerune": func() { sinkInt = stackS2RLen(value) },
	} {
		require.Zero(t, testing.AllocsPerRun(100, f), "%s: a refused root stays clean: the result stays on the stack", name)
	}
	require.Empty(t, spansOf(heapConcat2("x", value)))
	require.Empty(t, bytesSpansOf(heapS2B(value)))
	require.Empty(t, spansOf(heapB2S(bytesValue)))
}

// filterSum returns the sum of the counters of a bridge filter.
func filterSum(f *runtimebridge.Filter) uint64 {
	sum := uint64(0)
	for i := range f {
		sum += uint64(f[i].Load())
	}
	return sum
}

// TestConfirmPanic checks plan sections 3.4.1 and 9.1 items 12 and 13: a
// panic in confirm or in a callback is recovered, the guard is cleared, and
// the next operation enters the bridge again.
func TestConfirmPanic(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintString(t, ctx, "q", "tainted-value")
	withTestBinding(t)

	testConfirmMode.Store(int32(confirmPanic))
	panics := runtimebridge.Snapshot().HookPanics
	p := stackConcat("x", value[:5])
	require.Equal(t, panics+1, runtimebridge.Snapshot().HookPanics)
	require.True(t, p.tainted, "a recovered confirm panic forces the heap, and the result hook adopts the result")
	testConfirmMode.Store(int32(confirmNormal))

	before := entries()
	require.Equal(t, []span{{1, 13, "q"}}, spansOf(heapConcat2("y", value)))
	require.Greater(t, entries(), before, "the guard is clear after a confirm panic")

	testCallbackMode.Store(int32(confirmPanic))
	panics = runtimebridge.Snapshot().HookPanics
	sinkString = heapConcat2("z", value)
	require.Equal(t, panics+1, runtimebridge.Snapshot().HookPanics)
	testCallbackMode.Store(int32(confirmNormal))
	before = entries()
	require.Equal(t, []span{{1, 13, "q"}}, spansOf(heapConcat2("w", value)))
	require.Greater(t, entries(), before, "the guard is clear after a callback panic")
}

// TestRecursionGuard checks plan sections 3.4.1 and 9.1 item 8: operations
// inside confirm and inside a callback do not enter the bridge.
func TestRecursionGuard(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintString(t, ctx, "q", "tnt")
	withTestBinding(t)
	testConfirmMode.Store(int32(confirmNested))
	testCallbackMode.Store(int32(confirmNested))
	nestedEntries.Store(0)
	nestedSink.Store(nil)
	before := entries()
	// Filter check (1 entry) + pre (1 entry, nested confirm) + result hook (1
	// entry, nested callback).
	p := stackConcat("x", value)
	got := entries() - before
	require.Equal(t, uint64(3), got, "only the filter check, the pre-check and the result hook enter the bridge")
	require.Zero(t, nestedEntries.Load(), "nested operations must not enter the bridge")
	require.NotNil(t, nestedSink.Load(), "the nested operations ran")
	require.Equal(t, probe{tainted: true}, p)
}

// TestStackGrowth checks plan section 3.8: confirm and the callback grow the
// goroutine stack during the tainted path. The result is on the heap, it is
// tainted, and it survives two garbage collections.
func TestStackGrowth(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintString(t, ctx, "q", "tnt")
	withTestBinding(t)
	testConfirmMode.Store(int32(confirmGrow))
	testCallbackMode.Store(int32(confirmGrow))
	before := grows.Load()
	p := stackConcat("x", value)
	require.GreaterOrEqual(t, grows.Load(), before+2, "confirm and the callback grew the stack")
	require.Equal(t, probe{tainted: true}, p)
	r := heapConcat2("y", value)
	runtime.GC()
	runtime.GC()
	require.Equal(t, "ytnt", r)
	require.Equal(t, []span{{1, 3, "q"}}, spansOf(r))
}

// TestHeapRetention checks plan section 3.8: the store keeps an adopted
// result live. The data and the ranges do not change after two garbage
// collections.
func TestHeapRetention(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintString(t, ctx, "q", "attack")
	result := heapConcat2(strings.Repeat("p", 40), value)
	data, n := weak.Make(unsafe.StringData(result)), len(result)
	result = ""
	sinkString = ""
	runtime.GC()
	runtime.GC()
	require.NotNil(t, data.Value(), "the store keeps the adopted result live")
	again := unsafe.String(data.Value(), n)
	require.Equal(t, strings.Repeat("p", 40)+"attack", again)
	require.Equal(t, []span{{40, 6, "q"}}, spansOf(again))
}

// TestAddressReuse checks plan section 9.1 item 6: after the owner finished,
// a new allocation at the same address is not tainted.
func TestAddressReuse(t *testing.T) {
	requireWoven(t)
	t.Run("taint", func(t *testing.T) {
		ctx := begin(t)
		value := taintString(t, ctx, "q", "attack")
		sinkString = heapConcat2(strings.Repeat("p", 26), value)
	})
	sinkString = ""
	runtime.GC()
	runtime.GC()
	ctx := begin(t)
	_ = taintString(t, ctx, "other", "other-value")
	for range 10000 {
		s := heapConcat2(strings.Repeat("p", 26), "attack")
		require.Empty(t, spansOf(s))
	}
}

// TestIndependentStores checks plan section 9.1 item 6b in the woven build.
// Two stores from store.New() and the process store are used, also at the
// same time (run it with -race). Taint in a store that is not the process
// store never changes the gate or the bridge filter, and no hook sees it.
// After the refused second bindings, the bridge still uses the gate, the
// filter, confirm and the callbacks of the process store: the results of a
// process store value are adopted in the process store, and the results of a
// second store value are adopted in no store.
func TestIndependentStores(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	process := store.RuntimeStore()
	require.NotNil(t, process)
	others := [2]*store.Store{store.New(), store.New()}
	bound, callbacks := runtimebridge.CurrentForTest()
	// The stores have no root, so only the bridge can refuse the binding.
	for i, other := range others {
		require.Falsef(t, other.BindRuntimeBridge(runtimebridge.Options{StringToSlice: true}), "store %d: a second bind is refused", i)
	}
	afterBinding, afterCallbacks := runtimebridge.CurrentForTest()
	require.Same(t, bound, afterBinding, "the binding does not change")
	require.Same(t, callbacks, afterCallbacks, "the callbacks do not change")
	require.Same(t, process, store.RuntimeStore())

	gate, filter := runtimebridge.GateValue(), filterSum(bound.Filter)
	owner := others[0].Acquire()
	defer owner.Finish()
	foreign, _, ok := owner.TaintString("second-store-value", 1)
	require.True(t, ok)
	require.Equal(t, gate, runtimebridge.GateValue(), "a second store does not change the gate")
	require.Equal(t, filter, filterSum(bound.Filter), "a second store does not change the bridge filter")

	first := taintString(t, ctx, "first", "first-store-value")
	require.Equal(t, probe{tainted: true}, stackConcat("x", first), "confirm uses the process store")
	require.Equal(t, []span{{1, 17, "first"}}, spansOf(heapConcat2("x", first)), "the process store adopts the concat result")
	require.Equal(t, []span{{0, 17, "first"}}, bytesSpansOf(heapS2B(first)), "the process store adopts the []byte(s) result")
	require.Empty(t, foreignFindings(others[:], process, foreign), "the results of a second store value are adopted in no store")

	// Concurrent use of the three stores.
	const iterations = 200
	gate, filter = runtimebridge.GateValue(), filterSum(bound.Filter)
	var wg sync.WaitGroup
	for i, other := range others {
		wg.Go(func() {
			for n := range iterations {
				owner := other.Acquire()
				value, _, ok := owner.TaintString(fmt.Sprintf("store-%d-value-%d", i, n), 1)
				if !ok {
					t.Errorf("store %d: taint refused", i)
				} else if findings := foreignFindings(others[:], process, value); len(findings) != 0 {
					t.Errorf("store %d: %v", i, findings)
				}
				owner.Finish()
			}
		})
	}
	wg.Go(func() {
		for n := range iterations {
			ctx, scope, _ := request.Begin(context.Background())
			value := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p"}, fmt.Sprintf("process-value-%d", n))
			want := []span{{1, uint32(len(value)), "p"}}
			if got := spansOf(heapConcat2("x", value)); !reflect.DeepEqual(want, got) {
				t.Errorf("process store concat result: %v, want %v", got, want)
			}
			if got := bytesSpansOf(heapS2B(value)); len(got) != 1 {
				t.Errorf("process store []byte(s) result: %v", got)
			}
			scope.Finish()
		}
	})
	wg.Wait()
	require.Equal(t, gate, runtimebridge.GateValue(), "the gate is the same when the concurrent roots are finished")
	require.Equal(t, filter, filterSum(bound.Filter), "the filter is the same when the concurrent roots are finished")
}

// foreignFindings runs the hooked operations on value, a value of a store that
// is not the process store. It returns the problems that it finds: a result
// that a store adopted.
func foreignFindings(others []*store.Store, process *store.Store, value string) []string {
	var findings []string
	result := heapConcat2("x", value)
	bytesResult := heapS2B(value)
	stringKey, _ := store.StringKey(result)
	bytesKey, _ := store.BytesKey(bytesResult)
	var snapshot store.Snapshot
	for i, s := range append([]*store.Store{process}, others...) {
		if s.Lookup(stringKey, &snapshot) && snapshot.Len() != 0 {
			findings = append(findings, fmt.Sprintf("store %d adopted the concat result", i))
		}
		if s.Lookup(bytesKey, &snapshot) && snapshot.Len() != 0 {
			findings = append(findings, fmt.Sprintf("store %d adopted the []byte(s) result", i))
		}
	}
	return findings
}

// TestFanout checks plan section 9.1 item 4b: an allocation with the maximum
// number of owners keeps the taint of the admitted owners. The refused owner
// is not visible.
func TestFanout(t *testing.T) {
	requireWoven(t)
	shared := strings.Clone("shared-value")
	admitted := 0
	names := map[string]bool{}
	for i := range store.MaxSnapshotOwners + 1 {
		ctx := begin(t)
		name := string(rune('a' + i))
		source := taintString(t, ctx, name, "src-"+name)
		owner, id := ownerOf(t, source)
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Start: 0, Length: uint32(len(shared)), SourceID: id}}, uint32(len(shared))).Valid)
		if _, ok := owner.AdoptString(shared, &set); ok {
			admitted++
			names[name] = true
		}
	}
	require.Equal(t, store.MaxSnapshotOwners, admitted, "the fifth owner is refused")
	p := stackConcat("x", shared)
	require.Equal(t, probe{tainted: true}, p)
	got := map[string]bool{}
	for _, s := range spansOf(heapConcat2("x", shared)) {
		got[s.name] = true
	}
	require.Equal(t, names, got, "only the admitted owners are visible")
}
