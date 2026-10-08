// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge/bridgetest"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// The benchmarks of the concatenation and conversion gates (the PROFILES
// table of .github/runtime-bench.py has the gates). To measure the cost of the hooks, compare two woven
// test binaries, and run them in turns with -test.bench=BenchmarkRuntime:
//
//	go tool orchestrion go test -c -o hook.test ./iast/runtime
//	go tool orchestrion go test -c -o nohook.test ./iast/runtime
//
// Build nohook.test in a copy of the module, where iast/runtime/orchestrion.yml
// has no prepend-statements aspect (the other aspects do not change).
//
// Do not use an unwoven binary as the reference. The woven binary also links
// the tracer and all the integrations. With the small heap of this test, the
// GC then adds approx. 2 ns to each "heap" case, also when no function is
// hooked. Also, the code placement changes a case with a loop by up to 5 ns,
// with the same instructions. Thus build the two binaries with more than one
// code placement (for example, add a padding function to the injected runtime
// declarations), and use the runs of all the placements together.
// .github/runtime-bench.sh does all this, and checks the gates (the CI workflow runtime-bench.yml runs it on linux).
//
// Each case is a //go:noinline function, so that the call shape is the same in
// all the builds. The "heap" cases store the result in a global (buf == nil);
// the "stack" cases use a stack buffer.

//go:noinline
func benchConcatHeap2(a []string) { sinkString = a[0] + a[1] }

//go:noinline
func benchConcatHeap4(a []string) { sinkString = a[0] + a[1] + a[2] + a[3] }

//go:noinline
func benchConcatHeap6(a []string) { sinkString = a[0] + a[1] + a[2] + a[3] + a[4] + a[5] }

//go:noinline
func benchConcatHeap16(a []string) {
	sinkString = a[0] + a[1] + a[2] + a[3] + a[4] + a[5] + a[6] + a[7] +
		a[8] + a[9] + a[10] + a[11] + a[12] + a[13] + a[14] + a[15]
}

//go:noinline
func benchConcatStack2(a []string) int { s := a[0] + a[1]; return len(s) }

//go:noinline
func benchConcatStack4(a []string) int { s := a[0] + a[1] + a[2] + a[3]; return len(s) }

//go:noinline
func benchConcatStack6(a []string) int {
	s := a[0] + a[1] + a[2] + a[3] + a[4] + a[5]
	return len(s)
}

//go:noinline
func benchConcatStack16(a []string) int {
	s := a[0] + a[1] + a[2] + a[3] + a[4] + a[5] + a[6] + a[7] +
		a[8] + a[9] + a[10] + a[11] + a[12] + a[13] + a[14] + a[15]
	return len(s)
}

// benchOperands returns n heap strings of size bytes.
func benchOperands(n, size int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strings.Repeat(string(rune('a'+i%26)), size)
	}
	return out
}

type benchCase struct {
	name string
	f    func()
}

// benchCases returns the concat and conversion cases. Each input is a clean
// filter miss (see requireFilterMiss).
func benchCases(tb testing.TB) []benchCase {
	h2 := []string{strings.Clone("x"), strings.Repeat("h", 40)}
	h4, h6, h16 := benchOperands(4, 10), benchOperands(6, 8), benchOperands(16, 4)
	s2 := []string{strings.Clone("x"), strings.Clone("short-string")}
	s4, s6, s16 := benchOperands(4, 8), benchOperands(6, 5), benchOperands(16, 2)
	hb, sb := heapBytes(strings.Repeat("b", 40)), heapBytes("short-bytes")
	hs, ss := strings.Repeat("s", 40), strings.Clone("short-string")
	hr, sr := heapRunes(strings.Repeat("r", 40)), heapRunes("short runes")
	var strs []string
	for _, a := range [][]string{h2, h4, h6, h16, s2, s4, s6, s16, {hs, ss}} {
		strs = append(strs, a...)
	}
	requireFilterMiss(tb, strs, [][]byte{hb, sb}, [][]rune{hr, sr})
	return []benchCase{
		{"concat2-heap", func() { benchConcatHeap2(h2) }},
		{"concat4-heap", func() { benchConcatHeap4(h4) }},
		{"concat6-heap", func() { benchConcatHeap6(h6) }},
		{"concat16-heap", func() { benchConcatHeap16(h16) }},
		{"concat2-stack", func() { sinkInt = benchConcatStack2(s2) }},
		{"concat4-stack", func() { sinkInt = benchConcatStack4(s4) }},
		{"concat6-stack", func() { sinkInt = benchConcatStack6(s6) }},
		{"concat16-stack", func() { sinkInt = benchConcatStack16(s16) }},
		{"b2s-heap", func() { sinkString = heapB2S(hb) }},
		{"b2s-stack", func() { sinkInt = stackB2SLen(sb) }},
		{"s2b-heap", func() { sinkBytes = heapS2B(hs) }},
		{"s2b-stack", func() { sinkInt = stackS2BLen(ss) }},
		{"r2s-heap", func() { sinkString = heapR2S(hr) }},
		{"r2s-stack", func() { sinkInt = stackR2SLen(sr) }},
		{"s2r-heap", func() { sinkRunes = heapS2R(hs) }},
		{"s2r-stack", func() { sinkInt = stackS2RLen(ss) }},
	}
}

// benchMultiByte has 8 runes of 2, 3 and 4 bytes (22 bytes).
const benchMultiByte = "éàü€日本語😀"

// runeCases are the rune conversion benchmarks with 8 and 1 000
// runes, ASCII ("r2s8") and multi-byte ("r2s8mb"). With 8 runes, the stack
// buffer of the runtime (32 bytes, 32 runes) holds the result. With 1 000
// runes, the result is always on the heap, thus only the heap case. Each
// input is a clean filter miss (see requireFilterMiss).
func runeCases(tb testing.TB) []benchCase {
	// A clone of benchMultiByte (22 bytes) is in the 24-byte size class, the
	// class of the tainted root of BenchmarkRuntimeClean (23 bytes): the
	// allocator can put it in the granule of the root, and then it is a filter
	// hit. Thus m8 is the start of a 32-byte allocation.
	a8, m8 := strings.Clone("abcdefgh"), strings.Clone(benchMultiByte + "........")[:len(benchMultiByte)]
	a1000, m1000 := strings.Repeat("r", 1000), strings.Repeat(benchMultiByte, 125)
	ra8, rm8, ra1000, rm1000 := heapRunes(a8), heapRunes(m8), heapRunes(a1000), heapRunes(m1000)
	requireFilterMiss(tb, []string{a8, m8, a1000, m1000}, nil, [][]rune{ra8, rm8, ra1000, rm1000})
	return []benchCase{
		{"r2s8-heap", func() { sinkString = heapR2S(ra8) }},
		{"r2s8-stack", func() { sinkInt = stackR2SLen(ra8) }},
		{"r2s8mb-heap", func() { sinkString = heapR2S(rm8) }},
		{"r2s8mb-stack", func() { sinkInt = stackR2SLen(rm8) }},
		{"r2s1000-heap", func() { sinkString = heapR2S(ra1000) }},
		{"r2s1000mb-heap", func() { sinkString = heapR2S(rm1000) }},
		{"s2r8-heap", func() { sinkRunes = heapS2R(a8) }},
		{"s2r8-stack", func() { sinkInt = stackS2RLen(a8) }},
		{"s2r8mb-heap", func() { sinkRunes = heapS2R(m8) }},
		{"s2r8mb-stack", func() { sinkInt = stackS2RLen(m8) }},
		{"s2r1000-heap", func() { sinkRunes = heapS2R(a1000) }},
		{"s2r1000mb-heap", func() { sinkRunes = heapS2R(m1000) }},
	}
}

// requireFilterMiss stops the benchmark when an input is a filter hit: the
// clean cases must measure the filter-miss path, not the filter-hit path of a
// clean neighbor of a tainted root (BenchmarkRuntimeCleanHit measures it).
func requireFilterMiss(tb testing.TB, strs []string, bytes [][]byte, runes [][]rune) {
	tb.Helper()
	s := store.RuntimeStore()
	var keys []store.Key
	for _, v := range strs {
		if k, ok := store.StringKey(v); ok {
			keys = append(keys, k)
		}
	}
	for _, v := range bytes {
		if k, ok := store.BytesKey(v); ok {
			keys = append(keys, k)
		}
	}
	for _, v := range runes {
		if k, ok := store.RunesKey(v); ok {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		if s.MayContain(k) {
			tb.Fatalf("the clean input at %#x (%d bytes) is a filter hit", k.Pointer, k.Length)
		}
	}
}

func runBench(b *testing.B, cases []benchCase) {
	// TestMain turns on the entry counter for the tests. A production
	// process does not count entries, so the benchmarks do not count them.
	previous := runtimebridge.CountEntries(false)
	b.Cleanup(func() { runtimebridge.CountEntries(previous) })
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				c.f()
			}
		})
	}
}

// ownerDrops returns the sum of the drop counters of owner (all kinds).
func ownerDrops(owner *store.Owner) uint64 {
	c := owner.Counters()
	return c.Full + c.Bytes + c.Ranges + c.Contention + c.Late + c.Stale + c.Disabled +
		c.OneByte + c.Fanout + c.IndexFull + c.PreContention + c.PreStale + c.DupOwner
}

// BenchmarkRuntimeOff: no live root, so the gate is off.
func BenchmarkRuntimeOff(b *testing.B) { runBench(b, append(benchCases(b), runeCases(b)...)) }

// BenchmarkRuntimeClean: one unrelated tainted root, so the gate is on, and
// the operands are clean (filter miss).
func BenchmarkRuntimeClean(b *testing.B) {
	ctx := begin(b)
	_ = taintString(b, ctx, "unrelated", "unrelated-tainted-value")
	runBench(b, append(benchCases(b), runeCases(b)...))
}

// BenchmarkRuntimeCleanHit: the gate is on, and each operand is a clean
// filter hit. Each operand is a part of a different tainted root (64 bytes,
// one tier S granule, so the two operands are in different granules) that has
// a range only on [0, 2). Thus the filter check before the wrapper has a hit,
// and the pre-check confirms that the operands are clean: the result stays on
// the stack (0 extra allocations). The gates "filter hit"
// (s2b-stack, one operand) and "2-operand stack concat" (concat2-stack, both
// operands hit) use these cases.
func BenchmarkRuntimeCleanHit(b *testing.B) {
	ctx := begin(b)
	source := taintString(b, ctx, "hit", "hit-source")
	first := adoptString(b, source, strings.Repeat("h", 64), [2]uint32{0, 2})
	second := adoptString(b, source, strings.Repeat("i", 64), [2]uint32{0, 2})
	one, two := first[32:40], second[48:56]
	if stringData(one)>>runtimebridge.ShiftS == stringData(two)>>runtimebridge.ShiftS {
		b.Fatal("the operands are in the same granule")
	}
	for _, s := range []string{one, two} {
		key, ok := store.StringKey(s)
		if !ok || !store.RuntimeStore().MayContain(key) || keyTainted(stringData(s), len(s)) {
			b.Fatal("an operand is not a clean filter hit")
		}
	}
	cases := []benchCase{
		{"s2b-stack", func() { sinkInt = stackS2BLen(one) }},
		{"concat2-stack", func() { sinkInt = stackConcatLen(one, two) }},
	}
	requireCleanHitPath(b, source, cases, []int{1, 2})
	runBench(b, cases)
}

// requireCleanHitPath checks, before the measurement, that each case of a
// hooked binary calls Confirm once for each operand (thus the woven code did
// not skip the pre-check), and that no case allocates. A binary without the
// hooks (nohook, unwoven) does not call Confirm: it only checks the
// allocations.
func requireCleanHitPath(b *testing.B, tainted string, cases []benchCase, operands []int) {
	b.Helper()
	before := entries()
	sinkString = heapConcat2("x", tainted)
	hooked := entries() != before
	sinkString = ""
	previousBinding, previousCallbacks := runtimebridge.CurrentForTest()
	if previousBinding == nil {
		if hooked {
			b.Fatal("the hooked runtime bridge is not bound")
		}
		for _, c := range cases {
			if allocs := testing.AllocsPerRun(100, c.f); allocs != 0 {
				b.Fatalf("%s: %v allocations, want 0", c.name, allocs)
			}
		}
		return
	}
	var confirms int
	counted := *previousBinding
	counted.Confirm = func(p uintptr, n uint32) runtimebridge.ConfirmResult {
		confirms++
		return previousBinding.Confirm(p, n)
	}
	restore := runtimebridge.ReplaceForTest(&counted, runtimebridge.StringToSliceEnabled(), previousCallbacks)
	defer restore()
	for i, c := range cases {
		confirms = 0
		c.f()
		want := 0
		if hooked {
			want = operands[i]
		}
		if confirms != want {
			b.Fatalf("%s: %d calls to Confirm, want %d (hooked: %t)", c.name, confirms, want, hooked)
		}
		if allocs := testing.AllocsPerRun(100, c.f); allocs != 0 {
			b.Fatalf("%s: %v allocations, want 0", c.name, allocs)
		}
	}
}

// BenchmarkRuntimeS2SOff: the gate is on, and the string-to-slice switch is
// off. Only []byte(s) and []rune(s).
func BenchmarkRuntimeS2SOff(b *testing.B) {
	ctx := begin(b)
	_ = taintString(b, ctx, "unrelated", "unrelated-tainted-value")
	previous := bridgetest.SetS2SGate(0)
	b.Cleanup(func() { bridgetest.SetS2SGate(previous) })
	var cases []benchCase
	for _, c := range benchCases(b) {
		if strings.HasPrefix(c.name, "s2") {
			cases = append(cases, c)
		}
	}
	runBench(b, cases)
}

// BenchmarkRuntimeTainted: the gate is on, and one operand is tainted. The
// stack cases get one heap allocation (the gate: +1 allocation of the exact
// result size). The time gates increase with the size of
// the operation (a base time, plus a time for each operand above 2 or for each
// rune; see .github/runtime-bench.py). The heap cases get no extra allocation.
// Before the measurement, runTainted does one operation of each case, and
// checks that a hooked binary taints its result (see checkTaintedResult). The
// stack concat results are 32 bytes or less (one tainted operand of the same
// size as the clean operands), so the runtime buffer holds them without the
// hook.
//
// Each tainted result is a new root of the request owner, and the owner keeps
// at most store.MaxRootsPerOwner roots until the scope finishes. With one
// scope for all the operations, the quota is full after some hundred
// operations, and the hook then measures the refused adoption only. Thus
// runTainted starts a new scope (with new inputs) after each taintedChunk
// operations, with the timer stopped, and reports "drops/op" (approx. 0 in a
// hooked binary). A binary without the hooks adds no root, so it does not
// start new scopes: else the scope changes of its fast operations make the
// run some times longer.
func BenchmarkRuntimeTainted(b *testing.B) {
	withTainted := func(b *testing.B, ctx context.Context, clean []string) []string {
		out := append([]string(nil), clean...)
		out[1] = taintString(b, ctx, "operand", strings.Repeat("t", len(clean[1])))
		return out
	}
	// The rune cases of runeCases, with a tainted input: the complete input
	// is tainted.
	stringCase := func(value string, op func(string)) func(*testing.B, context.Context, string) func() {
		return func(b *testing.B, ctx context.Context, _ string) func() {
			s := taintString(b, ctx, "runes", strings.Clone(value))
			return func() { op(s) }
		}
	}
	runesCase := func(value string, op func([]rune)) func(*testing.B, context.Context, string) func() {
		return func(b *testing.B, _ context.Context, source string) func() {
			r := heapRunes(value)
			adoptRunes(b, source, r, 0, len(r))
			return func() { op(r) }
		}
	}
	a1000, m1000 := strings.Repeat("r", 1000), strings.Repeat(benchMultiByte, 125)
	r2sStack := func(r []rune) { sinkInt = stackR2SLen(r) }
	r2sHeap := func(r []rune) { sinkString = heapR2S(r) }
	s2rStack := func(s string) { sinkInt = stackS2RLen(s) }
	s2rHeap := func(s string) { sinkRunes = heapS2R(s) }
	runTainted(b, []taintedCase{
		{"concat2-stack", func(_ *testing.B, _ context.Context, s string) func() {
			return func() { sinkInt = stackConcatLen("x", s) }
		}, nil},
		{"concat4-stack", func(b *testing.B, ctx context.Context, _ string) func() {
			a := withTainted(b, ctx, benchOperands(4, 8))
			return func() { sinkInt = benchConcatStack4(a) }
		}, nil},
		{"concat6-stack", func(b *testing.B, ctx context.Context, _ string) func() {
			a := withTainted(b, ctx, benchOperands(6, 5))
			return func() { sinkInt = benchConcatStack6(a) }
		}, nil},
		{"concat16-stack", func(b *testing.B, ctx context.Context, _ string) func() {
			a := withTainted(b, ctx, benchOperands(16, 2))
			return func() { sinkInt = benchConcatStack16(a) }
		}, nil},
		{"concat2-heap", func(b *testing.B, ctx context.Context, _ string) func() {
			a := withTainted(b, ctx, []string{strings.Clone("x"), strings.Repeat("h", 40)})
			return func() { benchConcatHeap2(a) }
		}, wantString(span{1, 40, "operand"})},
		{"b2s-stack", func(b *testing.B, ctx context.Context, _ string) func() {
			data := taintBytes(b, ctx, "b", []byte("short-bytes"))
			return func() { sinkInt = stackB2SLen(data) }
		}, nil},
		{"s2b-stack", func(_ *testing.B, _ context.Context, s string) func() {
			return func() { sinkInt = stackS2BLen(s) }
		}, nil},
		{"r2s-stack", runesCase("short runes", r2sStack), nil},
		{"s2r-stack", func(_ *testing.B, _ context.Context, s string) func() {
			return func() { sinkInt = stackS2RLen(s) }
		}, nil},
		{"r2s8-stack", runesCase("abcdefgh", r2sStack), nil},
		{"r2s8mb-stack", runesCase(benchMultiByte, r2sStack), nil},
		{"r2s1000-heap", runesCase(a1000, r2sHeap), wantString(span{0, uint32(len(a1000)), "source"})},
		{"r2s1000mb-heap", runesCase(m1000, r2sHeap), wantString(span{0, uint32(len(m1000)), "source"})},
		{"s2r8-stack", stringCase("abcdefgh", s2rStack), nil},
		{"s2r8mb-stack", stringCase(benchMultiByte, s2rStack), nil},
		{"s2r1000-heap", stringCase(a1000, s2rHeap), wantRunes(1000)},
		{"s2r1000mb-heap", stringCase(m1000, s2rHeap), wantRunes(1000)},
	})
}

// taintedChunk is the number of operations of one request scope in
// runTainted. Each operation adds one root, and the inputs of a case use some
// roots too: the sum stays below store.MaxRootsPerOwner.
const taintedChunk = 256

// taintedCase is one case of BenchmarkRuntimeTainted. setup makes the tainted
// inputs in the request scope ctx (source is a tainted string of this scope),
// and returns the operation. result, when not nil, checks the result of a
// heap case (the operation keeps it in a sink).
type taintedCase struct {
	name   string
	setup  func(b *testing.B, ctx context.Context, source string) func()
	result func(tb testing.TB, hooked bool)
}

// wantString returns a check of sinkString: a hooked binary gives exactly the
// spans want, and a binary without the hooks gives no span.
func wantString(want ...span) func(testing.TB, bool) {
	return func(tb testing.TB, hooked bool) {
		tb.Helper()
		got, expected := spansOf(sinkString), want
		if !hooked {
			expected = nil
		}
		if !slices.Equal(got, expected) {
			tb.Fatalf("the result has the spans %v, want %v (hooked: %t)", got, expected, hooked)
		}
	}
}

// wantRunes returns a check of sinkRunes: a hooked binary gives one range on
// all the n runes (in bytes of the rune array), and a binary without the
// hooks gives no range.
func wantRunes(n int) func(testing.TB, bool) {
	return func(tb testing.TB, hooked bool) {
		tb.Helper()
		got := runeRanges(sinkRunes)
		var want [][2]uint32
		if hooked {
			want = [][2]uint32{{0, uint32(4 * n)}}
		}
		if !slices.Equal(got, want) {
			tb.Fatalf("the result has the ranges %v, want %v (hooked: %t)", got, want, hooked)
		}
	}
}

// checkTaintedResult does one operation of c, before the measurement. A
// hooked binary must adopt the result as a new root of owner (the charged
// bytes of owner increase), and a binary without the hooks must not. When
// c.result is not nil, it also checks the exact ranges of the result. Thus a
// missing hook stops the benchmark: else a missing hook gives 0 extra
// allocations, 0 drops and a small time, and the heap gates pass.
func checkTaintedResult(b *testing.B, c taintedCase, op func(), owner *store.Owner, hooked bool) {
	b.Helper()
	charged := owner.Charged()
	op()
	if adopted := owner.Charged() != charged; adopted != hooked {
		b.Fatalf("%s: the result is adopted: %t, want %t (hooked binary)", c.name, adopted, hooked)
	}
	if c.result != nil {
		c.result(b, hooked)
	}
	sinkString, sinkRunes = "", nil
}

// runTainted runs the cases. A new request scope starts after each
// taintedChunk operations, with the timer stopped (thus its time and its
// allocations are not in the result).
func runTainted(b *testing.B, cases []taintedCase) {
	// begin sets the configuration for the complete benchmark. Its unrelated
	// root keeps the gate on between two scopes.
	ctx := begin(b)
	unrelated := taintString(b, ctx, "unrelated", "unrelated-tainted-value")
	// TestMain counts the entries: a hooked binary enters the bridge.
	entered := entries()
	sinkString = heapConcat2("x", unrelated)
	sinkString = ""
	hooked := entries() != entered
	previous := runtimebridge.CountEntries(false)
	b.Cleanup(func() { runtimebridge.CountEntries(previous) })
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.StopTimer()
			var (
				finish        func()
				owner         store.Owner
				op            func()
				drops, before uint64
			)
			reset := func() {
				if finish != nil {
					drops += ownerDrops(&owner) - before
					finish()
				}
				var scopeCtx context.Context
				scopeCtx, finish = beginScope(b)
				source := taintString(b, scopeCtx, "source", "short-value")
				op = c.setup(b, scopeCtx, source)
				owner, _ = ownerOf(b, source)
				before = ownerDrops(&owner)
			}
			reset()
			checkTaintedResult(b, c, op, &owner, hooked)
			b.StartTimer()
			for i := range b.N {
				if hooked && i > 0 && i%taintedChunk == 0 {
					b.StopTimer()
					reset()
					b.StartTimer()
				}
				op()
			}
			b.StopTimer()
			drops += ownerDrops(&owner) - before
			finish()
			b.ReportMetric(float64(drops)/float64(b.N), "drops/op")
		})
	}
}

// beginScope starts a new request scope, and returns its context and its
// finish function. The caller sets the configuration (see begin).
func beginScope(tb testing.TB) (context.Context, func()) {
	tb.Helper()
	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		tb.Fatal("no active request scope")
	}
	return ctx, scope.Finish
}
