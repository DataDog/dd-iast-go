// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command plaintwins runs strings.Join, strings.Replace, strings.Repeat and
// strings.ToLower on inputs without taint, and prints for each case the
// result (or the panic value), whether the result is a part of the input, and
// the allocations (count and bytes) of one call.
//
// TestPlainTwins builds it without Orchestrion (the original bodies) and with
// Orchestrion (the plain twins of orchestrion.yml, rule 5), runs it, and
// compares the outputs: they must be the same.
//
// Flags:
//
//   - -live sets the taint bits of a probe value first: then the gate of the
//     hooks is on, and the hooks check the inputs before they call the plain
//     twins. In a woven build, the program fails when the gate is not in the
//     expected state.
//   - -fake adds the cases of an output length overflow. They use strings
//     with a length that is larger than their memory (the bodies panic
//     before they read the data). Do not use -fake with -live: the taint
//     check of the hooks reads the bits of all the input.
package main

import (
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/orchestrion/runtime/built"
)

const maxInt = int(^uint(0) >> 1)

// testCase is one call. in is the input that the result can be a part of.
type testCase struct {
	name string
	in   string
	call func() string
}

// sink keeps the results alive (the compiler cannot remove the calls).
var sink string

// probe is a heap value with taint bits in -live mode.
var probe []byte

func main() {
	live := flag.Bool("live", false, "set the taint bits of a probe value first")
	fake := flag.Bool("fake", false, "add the cases with an output length overflow")
	flag.Parse()

	if *live {
		probe = []byte("plaintwins-probe")
		heapbits.SetBytes(probe)
	}
	if built.WithOrchestrion && heapbits.Live() != *live {
		fmt.Fprintf(os.Stderr, "the gate of the hooks is %v, want %v\n", heapbits.Live(), *live)
		os.Exit(3)
	}
	// One P: the background goroutines do not run during a measure (as in
	// testing.AllocsPerRun).
	runtime.GOMAXPROCS(1)

	for _, c := range cases(*fake) {
		fmt.Println(run(c))
	}
	runtime.KeepAlive(probe)
}

// run calls c one time for the result, then measures the allocations of
// one call.
func run(c testCase) string {
	r, p := call(c.call)
	if p != nil {
		return fmt.Sprintf("%s: panic %v", c.name, p)
	}
	out := describe(r)
	if len(r) > 0 && len(c.in) > 0 && within(r, c.in) {
		out += " (part of the input)"
	}
	if heapbits.AnyString(r) {
		out += " (TAINTED)"
	}
	allocs, bytes := measure(c.call)
	return fmt.Sprintf("%s: %s allocs=%d bytes=%d", c.name, out, allocs, bytes)
}

func call(f func() string) (r string, p any) {
	defer func() { p = recover() }()
	return f(), nil
}

// describe prints the result, or its length and hash when it is long.
func describe(s string) string {
	if len(s) <= 64 {
		return fmt.Sprintf("%q", s)
	}
	h := fnv.New64a()
	h.Write([]byte(s))
	return fmt.Sprintf("len=%d fnv=%x", len(s), h.Sum64())
}

func within(part, whole string) bool {
	p, w := uintptr(unsafe.Pointer(unsafe.StringData(part))), uintptr(unsafe.Pointer(unsafe.StringData(whole)))
	return p >= w && p+uintptr(len(part)) <= w+uintptr(len(whole))
}

// measure returns the allocations (count and bytes) of one call of f: the
// smallest mean of 5 trials of 200 calls.
func measure(f func() string) (allocs, bytes uint64) {
	const runs = 200
	allocs, bytes = ^uint64(0), ^uint64(0)
	for range 5 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range runs {
			sink = f()
		}
		runtime.ReadMemStats(&after)
		allocs = min(allocs, (after.Mallocs-before.Mallocs)/runs)
		bytes = min(bytes, (after.TotalAlloc-before.TotalAlloc)/runs)
	}
	return allocs, bytes
}

// heap returns a copy of s in heap memory (as the values of an application).
func heap(s string) string {
	return string([]byte(s))
}

// fakeString returns a string of length n that uses the memory of a small
// buffer. Only for the bodies that panic before they read the data.
func fakeString(n int) string {
	return unsafe.String(unsafe.SliceData(make([]byte, 1)), n)
}

func cases(fake bool) []testCase {
	var out []testCase
	add := func(name, in string, f func() string) {
		out = append(out, testCase{name: name, in: in, call: f})
	}

	// strings.Join
	one := []string{heap("only")}
	two := []string{heap("left"), heap("right")}
	three := []string{heap("a"), heap(""), heap("ccc")}
	many := make([]string, 100)
	for i := range many {
		many[i] = heap(fmt.Sprintf("e%d", i))
	}
	sep := heap(", ")
	add("Join/nil", "", func() string { return strings.Join(nil, sep) })
	add("Join/one", one[0], func() string { return strings.Join(one, sep) })
	add("Join/two/no-sep", "", func() string { return strings.Join(two, "") })
	add("Join/two", "", func() string { return strings.Join(two, sep) })
	add("Join/three/empty-element", "", func() string { return strings.Join(three, sep) })
	add("Join/many", "", func() string { return strings.Join(many, sep) })
	add("Join/empty-elements", "", func() string { return strings.Join([]string{"", "", ""}, "") })
	if fake {
		bigSep := fakeString(maxInt / 2)
		add("Join/overflow/sep", "", func() string { return strings.Join(three, bigSep) })
		half := fakeString(maxInt/2 + 1)
		add("Join/overflow/elements", "", func() string { return strings.Join([]string{half, half}, "") })
	}

	// strings.Replace and strings.ReplaceAll
	text := heap("one OLD two OLD three OLD")
	utf := heap("héllo, wörld")
	add("Replace/same", text, func() string { return strings.Replace(text, "OLD", "OLD", -1) })
	add("Replace/n=0", text, func() string { return strings.Replace(text, "OLD", "new", 0) })
	add("Replace/no-match", text, func() string { return strings.Replace(text, "missing", "new", -1) })
	add("Replace/n=1", text, func() string { return strings.Replace(text, "OLD", "new", 1) })
	add("Replace/n=2", text, func() string { return strings.Replace(text, "OLD", "N", 2) })
	add("Replace/n=10", text, func() string { return strings.Replace(text, "OLD", "longer value", 10) })
	add("Replace/all/shrink", text, func() string { return strings.Replace(text, "OLD", "", -1) })
	add("Replace/empty-old", utf, func() string { return strings.Replace(utf, "", "|", -1) })
	add("Replace/empty-old/n=3", utf, func() string { return strings.Replace(utf, "", "<>", 3) })
	add("Replace/empty-old/empty-s", "", func() string { return strings.Replace("", "", "x", -1) })
	add("Replace/whole", text, func() string { return strings.Replace(text, text, "x", -1) })
	add("ReplaceAll", text, func() string { return strings.ReplaceAll(text, "OLD", "new") })

	// strings.Repeat
	ab := heap("ab")
	abc := heap("abc")
	add("Repeat/0", ab, func() string { return strings.Repeat(ab, 0) })
	add("Repeat/1", ab, func() string { return strings.Repeat(ab, 1) })
	add("Repeat/negative", ab, func() string { return strings.Repeat(ab, -1) })
	add("Repeat/overflow", ab, func() string { return strings.Repeat(ab, maxInt/2+1) })
	add("Repeat/empty", "", func() string { return strings.Repeat("", 5) })
	add("Repeat/3", ab, func() string { return strings.Repeat(ab, 3) })
	add("Repeat/chunks", abc, func() string { return strings.Repeat(abc, 5000) })
	add("Repeat/single-byte-chunks", "", func() string { return strings.Repeat("x", 10000) })
	for _, s := range []string{" ", "-", "0", "=", "\t"} {
		v := heap(s)
		add(fmt.Sprintf("Repeat/fast-path/%q", s), v, func() string { return strings.Repeat(v, 10) })
		add(fmt.Sprintf("Repeat/fast-path-too-long/%q", s), v, func() string { return strings.Repeat(v, 200) })
		w := heap(s + "x")
		add(fmt.Sprintf("Repeat/fast-path-no-prefix/%q", s), w, func() string { return strings.Repeat(w, 4) })
	}

	// strings.ToLower
	for _, s := range []string{"", "lower", "UPPER", "MiXeD-Case 123", "A", "x", "HÉLLO", "héllo", "ÀB", strings.Repeat("Ab", 100)} {
		v := heap(s)
		add(fmt.Sprintf("ToLower/%.20q", s), v, func() string { return strings.ToLower(v) })
	}
	return out
}
