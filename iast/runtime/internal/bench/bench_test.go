// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bench_test

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

// The benchmarks of the runtime hooks (gate group G-B of plan
// heapbits-sqli-cmdi, section 10.1). To measure the cost of the hooks, compare
// two woven test binaries, and run them in turns with
// -test.bench=BenchmarkRuntime:
//
//	go tool orchestrion go test -c -o hook.test ./iast/runtime/internal/bench
//	go tool orchestrion go test -c -o nohook.test ./iast/runtime/internal/bench
//
// .github/runtime-bench.sh does these steps. This package must not link
// package heapbits/heapbitstest (directly or through a dependency): that
// package turns on the test knobs of the woven runtime, and each bit check
// then does more work than in a production program (TestNoTestKnobs).
//
// Build nohook.test in a copy of the module, where iast/runtime/orchestrion.yml
// has no hook aspect (remove all the aspects after the line
// "  - id: iast-concatstrings"; keep the declarations aspect and the heapbits
// aspects).
//
// Do not use an unwoven binary as the reference: the woven binary also links
// the tracer and all the integrations, and its GC costs more. Also build the
// two binaries with more than one code placement (the code placement changes
// a case with a loop by some ns), and use the runs of all the placements
// together.
//
// The gate of the heap taint bits is sticky: BenchmarkRuntimeOff must run
// first in its process (it is the first benchmark of this file, and no test
// must run before it: use -test.run='^$').
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
		out[i] = heapString(strings.Repeat(string(rune('a'+i%26)), size))
	}
	return out
}

type benchCase struct {
	name string
	f    func()
}

func benchCases() []benchCase {
	h2 := []string{heapString("x"), heapString(strings.Repeat("h", 40))}
	h4, h6, h16 := benchOperands(4, 10), benchOperands(6, 8), benchOperands(16, 4)
	s2 := []string{heapString("x"), heapString("short-string")}
	s4, s6, s16 := benchOperands(4, 8), benchOperands(6, 5), benchOperands(16, 2)
	hb, sb := heapBytes(strings.Repeat("b", 40)), heapBytes("short-bytes")
	hs, ss := heapString(strings.Repeat("s", 40)), heapString("short-string")
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
		{"grow-heap", func() { sinkBytes = heapGrow(hb) }},
		{"growbuf-stack", func() { sinkInt = stackBufGrowLen(20) }},
	}
}

func runBench(b *testing.B, cases []benchCase) {
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				c.f()
			}
		})
	}
}

// BenchmarkRuntimeOff: no taint was ever set in the process, so the gate is
// off. It must run first in its process.
func BenchmarkRuntimeOff(b *testing.B) {
	if heapbits.Live() {
		b.Fatal("the gate is on: run BenchmarkRuntimeOff first in its process, with -test.run='^$'")
	}
	runBench(b, benchCases())
	if heapbits.Live() {
		b.Fatal("a case turned the gate on")
	}
}

// benchTaint returns a heap copy of s with all its bytes tainted.
func benchTaint(b *testing.B, s string) string {
	b.Helper()
	v := heapString(s)
	if !heapbits.SetString(v) {
		b.Skip("the heap taint bits are not woven (use go tool orchestrion)")
	}
	return v
}

// BenchmarkRuntimeClean: one unrelated tainted value, so the gate is on, and
// the operands are clean (their memory has no taint chunk, or an empty one).
func BenchmarkRuntimeClean(b *testing.B) {
	sinkString = benchTaint(b, "unrelated-tainted-value")
	runBench(b, benchCases())
}

// BenchmarkRuntimeCleanNear: the gate is on, and each operand is a clean
// part of a tainted allocation (64 bytes with taint on [0, 2)). The bit check
// then reads a taint chunk and a word that has bits (the bits of the operand
// are 0). This is the worst clean case of the bit check (not the "filter hit"
// of PR #39, which measured its store).
func BenchmarkRuntimeCleanNear(b *testing.B) {
	first := heapString(strings.Repeat("h", 64))
	second := heapString(strings.Repeat("i", 64))
	if !heapbits.Set(unsafe.Pointer(unsafe.StringData(first)), 2) || !heapbits.Set(unsafe.Pointer(unsafe.StringData(second)), 2) {
		b.Skip("the heap taint bits are not woven (use go tool orchestrion)")
	}
	one, two := first[32:40], second[48:56]
	if heapbits.AnyString(one) || heapbits.AnyString(two) {
		b.Fatal("an operand is tainted")
	}
	oneBytes := unsafe.Slice(unsafe.StringData(one), len(one))
	runBench(b, []benchCase{
		{"s2b-stack", func() { sinkInt = stackS2BLen(one) }},
		{"b2s-stack", func() { sinkInt = stackB2SLen(oneBytes) }},
		{"concat2-stack", func() { sinkInt = stackConcatLen(one, two) }},
	})
	sinkString = first + second
}

// BenchmarkRuntimeS2SOff: the gate is on, and the string-to-slice switch is
// off. Only []byte(s) and []rune(s).
func BenchmarkRuntimeS2SOff(b *testing.B) {
	sinkString = benchTaint(b, "unrelated-tainted-value")
	previous := setStringToSlice(false)
	b.Cleanup(func() { setStringToSlice(previous) })
	var cases []benchCase
	for _, c := range benchCases() {
		if strings.HasPrefix(c.name, "s2") {
			cases = append(cases, c)
		}
	}
	runBench(b, cases)
}

// BenchmarkRuntimeTainted: the gate is on, and one operand is tainted. The
// stack cases get one heap allocation (+1 allocation of the result size).
func BenchmarkRuntimeTainted(b *testing.B) {
	s := benchTaint(b, "short-value")
	data := heapBytes("short-bytes")
	heapbits.SetBytes(data)
	runes := heapRunes("short runes")
	heapbits.Set(unsafe.Pointer(&runes[0]), uintptr(4*len(runes)))
	grow := heapBytes(strings.Repeat("g", 40))
	heapbits.SetBytes(grow)
	runBench(b, []benchCase{
		{"concat2-stack", func() { sinkInt = stackConcatLen("x", s) }},
		{"b2s-stack", func() { sinkInt = stackB2SLen(data) }},
		{"s2b-stack", func() { sinkInt = stackS2BLen(s) }},
		{"r2s-stack", func() { sinkInt = stackR2SLen(runes) }},
		{"s2r-stack", func() { sinkInt = stackS2RLen(s) }},
		{"grow-heap", func() { sinkBytes = heapGrow(grow) }},
	})
}
