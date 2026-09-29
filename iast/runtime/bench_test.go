// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge/bridgetest"
)

// The benchmarks of plan section 9.2 for the concatenation and conversion
// gates of section 9.3. To measure the cost of the hooks, compare two woven
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

func benchCases() []benchCase {
	h2 := []string{strings.Clone("x"), strings.Repeat("h", 40)}
	h4, h6, h16 := benchOperands(4, 10), benchOperands(6, 8), benchOperands(16, 4)
	s2 := []string{strings.Clone("x"), strings.Clone("short-string")}
	s4, s6, s16 := benchOperands(4, 8), benchOperands(6, 5), benchOperands(16, 2)
	hb, sb := heapBytes(strings.Repeat("b", 40)), heapBytes("short-bytes")
	hs, ss := strings.Repeat("s", 40), strings.Clone("short-string")
	hr, sr := heapRunes(strings.Repeat("r", 40)), heapRunes("short runes")
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

// BenchmarkRuntimeOff: no live root, so the gate is off.
func BenchmarkRuntimeOff(b *testing.B) { runBench(b, benchCases()) }

// BenchmarkRuntimeClean: one unrelated tainted root, so the gate is on, and
// the operands are clean (filter miss).
func BenchmarkRuntimeClean(b *testing.B) {
	ctx := begin(b)
	_ = taintString(b, ctx, "unrelated", "unrelated-tainted-value")
	runBench(b, benchCases())
}

// BenchmarkRuntimeS2SOff: the gate is on, and the string-to-slice switch is
// off. Only []byte(s) and []rune(s).
func BenchmarkRuntimeS2SOff(b *testing.B) {
	ctx := begin(b)
	_ = taintString(b, ctx, "unrelated", "unrelated-tainted-value")
	previous := bridgetest.SetS2SGate(0)
	b.Cleanup(func() { bridgetest.SetS2SGate(previous) })
	var cases []benchCase
	for _, c := range benchCases() {
		if strings.HasPrefix(c.name, "s2") {
			cases = append(cases, c)
		}
	}
	runBench(b, cases)
}

// BenchmarkRuntimeTainted: the gate is on, and one operand is tainted. The
// stack cases get one heap allocation (plan section 9.3: +1 allocation,
// <= +60 ns).
func BenchmarkRuntimeTainted(b *testing.B) {
	ctx := begin(b)
	s := taintString(b, ctx, "s", "short-value")
	data := taintBytes(b, ctx, "b", []byte("short-bytes"))
	runes := heapRunes("short runes")
	adoptRunes(b, s, runes, 0, len(runes))
	runBench(b, []benchCase{
		{"concat2-stack", func() { sinkInt = stackConcatLen("x", s) }},
		{"b2s-stack", func() { sinkInt = stackB2SLen(data) }},
		{"s2b-stack", func() { sinkInt = stackS2BLen(s) }},
		{"r2s-stack", func() { sinkInt = stackR2SLen(runes) }},
		{"s2r-stack", func() { sinkInt = stackS2RLen(s) }},
	})
}
