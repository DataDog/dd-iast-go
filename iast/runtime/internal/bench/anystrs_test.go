// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bench_test

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/stretchr/testify/require"
)

// The tests of __dd_iast_anystrs, the filter of the concatenation hooks. They
// are in this package because the test knobs must be off: with the knobs on
// (iast/runtime), the function sends each operand to __dd_taint_any.

// rtAnyStrs is __dd_iast_anystrs of the woven runtime (nil without weaving).
//
//go:linkname rtAnyStrs __dd_iast_runtime.anystrs
var rtAnyStrs func(a []string) bool

const (
	region = 128 << 10 // heap bytes for one taint chunk
	inline = 1024      // __dd_iast_anystrsMax
)

// regionBuffer is a heap buffer that holds 4 full 128 KiB regions (0 to 3):
// the regions are only memory of the buffer, thus they have a taint chunk
// only when the test taints a byte in them.
type regionBuffer struct {
	buf []byte
	// base is the offset in buf of the start of the first full region.
	base int
}

func newRegionBuffer() *regionBuffer {
	buf := make([]byte, 5*region)
	escapeBytes.Store(unsafe.SliceData(buf))
	p := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	base := int((region - p%region) % region)
	return &regionBuffer{buf: buf, base: base}
}

// at returns the offset in buf of byte off of region r (off can be negative
// or more than one region, to cross a region edge).
func (b *regionBuffer) at(r, off int) int { return b.base + r*region + off }

// str returns the string of the n bytes at offset off of buf.
func (b *regionBuffer) str(off, n int) string {
	if n == 0 {
		return ""
	}
	return unsafe.String(&b.buf[off], n)
}

func (b *regionBuffer) taint(t *testing.T, off int) {
	t.Helper()
	require.True(t, heapbits.Set(unsafe.Pointer(&b.buf[off]), 1))
}

func (b *regionBuffer) clear() {
	heapbits.Clear(unsafe.Pointer(unsafe.SliceData(b.buf)), uintptr(len(b.buf)))
}

// oracle is the reference result: the loop of heapbits.Any (__dd_taint_any)
// over the operands.
func oracle(a []string) bool {
	for _, x := range a {
		if heapbits.AnyString(x) {
			return true
		}
	}
	return false
}

func requireAnyStrs(t *testing.T) {
	t.Helper()
	requireWoven(t)
	require.NotNil(t, rtAnyStrs, "__dd_iast_anystrs is not woven")
	require.False(t, testKnobs, "the test knobs are on: __dd_iast_anystrs does not use its own path")
}

// operand is an operand of a case: n bytes at byte off of region r.
type operand struct{ r, off, n int }

// TestAnyStrsShapes checks the result for operands of many shapes, with one
// tainted byte before, at the start of, in, at the end of and after an
// operand: the result is true only when the tainted byte is in an operand.
func TestAnyStrsShapes(t *testing.T) {
	requireAnyStrs(t)
	shapes := []operand{
		{1, 0, 1},                         // first byte of a region
		{1, 63, 1},                        // last byte of a word
		{1, 63, 2},                        // two words
		{1, 64, 64},                       // one full word
		{1, 10, 100},                      // some words
		{1, 1000, inline},                 // largest inline operand
		{1, 1000, inline + 1},             // smallest long operand
		{1, 100, 4096},                    // long operand in one region
		{1, region - inline, inline},      // ends at the region edge
		{1, region - inline + 1, inline},  // crosses the region edge by one byte
		{1, -5, 10},                       // crosses the region edge
		{1, -1024, 2048},                  // long, crosses the region edge
		{1, region - 1, 1},                // last byte of a region
		{0, region - 64, region + 128},    // long, more than one region
		{1, 2*region - 3, 1},              // in region 2, given from region 1
		{2, -(inline / 2), inline},        // crosses into region 2
		{1, 17, 0},                        // empty
		{1, region/2 + 7, 3*region/2 - 7}, // long, ends at the edge of region 3
	}
	b := newRegionBuffer()
	defer runtime.KeepAlive(b)
	for _, s := range shapes {
		start := b.at(s.r, s.off)
		for _, pos := range []int{start - 1, start, start + s.n/2, start + s.n - 1, start + s.n} {
			if pos < 0 || pos >= len(b.buf) {
				continue
			}
			name := fmt.Sprintf("r%d+%d/n%d/taint%+d", s.r, s.off, s.n, pos-start)
			b.clear()
			b.taint(t, pos)
			want := s.n > 0 && pos >= start && pos < start+s.n
			op := b.str(start, s.n)
			// The other operands are clean: before and after, in the same
			// region and in other regions.
			near := b.str(b.at(1, 3000), 10)
			other := b.str(b.at(3, 3000), 10)
			for _, a := range [][]string{
				{op},
				{near, op},
				{op, near},
				{other, op, near},
				{"", op, ""},
				{"static", op, other},
			} {
				require.Equal(t, want, oracle(a), "%s %d operands: the oracle", name, len(a))
				require.Equal(t, want, rtAnyStrs(a), "%s %d operands", name, len(a))
			}
		}
	}
}

// TestAnyStrsRegionCache checks the chunk cache: a clean operand at the same
// offset in another region as a tainted byte is not tainted, when the
// operand before it is in the region of the tainted byte (and the other way).
func TestAnyStrsRegionCache(t *testing.T) {
	requireAnyStrs(t)
	b := newRegionBuffer()
	defer runtime.KeepAlive(b)
	b.taint(t, b.at(2, 100))
	tainted := b.str(b.at(2, 100), 1)
	clean2 := b.str(b.at(2, 500), 10) // same chunk, clean bits
	clean1 := b.str(b.at(1, 100), 1)  // same offset, region without chunk
	clean3 := b.str(b.at(3, 96), 10)  // same word offset, region without chunk
	cross := b.str(b.at(2, -5), 10)   // crosses from region 1 into region 2
	for _, c := range []struct {
		a    []string
		want bool
	}{
		{[]string{clean2, clean1}, false},
		{[]string{clean1, clean2, clean3}, false},
		{[]string{clean2, clean1, clean2, clean3, clean2}, false},
		{[]string{clean1, tainted}, true},
		{[]string{clean2, clean1, clean3, tainted}, true},
		{[]string{clean1, cross, clean3}, false},
		{[]string{tainted, clean1}, true},
	} {
		require.Equal(t, c.want, oracle(c.a), "%d operands: the oracle", len(c.a))
		require.Equal(t, c.want, rtAnyStrs(c.a), "%d operands", len(c.a))
	}

	// Taint in region 1 too: an operand of region 2 after one of region 1
	// reads the bits of region 2.
	b.taint(t, b.at(1, 300))
	clean2b := b.str(b.at(2, 300), 1) // the offset of the taint of region 1
	require.False(t, rtAnyStrs([]string{b.str(b.at(1, 200), 8), clean2b}))
	require.True(t, rtAnyStrs([]string{clean2b, b.str(b.at(1, 300), 1)}))
}

// TestAnyStrsStack checks stack operands and operands that are not heap
// memory: they are never tainted.
func TestAnyStrsStack(t *testing.T) {
	requireAnyStrs(t)
	b := newRegionBuffer()
	defer runtime.KeepAlive(b)
	b.taint(t, b.at(1, 0))
	require.False(t, stackAnyStrs(b.str(b.at(1, 64), 8)), "stack operands and a clean heap operand")
	require.True(t, stackAnyStrs(b.str(b.at(1, 0), 8)), "stack operands and a tainted heap operand")
	require.False(t, rtAnyStrs([]string{"static", "", "data"}))
	require.False(t, rtAnyStrs(nil))
}

// stackAnyStrs calls __dd_iast_anystrs with 3 stack operands of different
// sizes and the heap operand h.
//
//go:noinline
func stackAnyStrs(h string) bool {
	var small [16]byte
	var word [100]byte
	var large [2000]byte
	for i := range large {
		large[i] = byte(i)
	}
	small[0], word[0] = 1, 1
	a := [...]string{
		unsafe.String(&small[0], len(small)),
		unsafe.String(&word[0], len(word)),
		h,
		unsafe.String(&large[0], len(large)),
	}
	return rtAnyStrs(a[:])
}

// TestAnyStrsRandom compares __dd_iast_anystrs with the oracle for random
// operands and random taint ranges in 3 regions.
func TestAnyStrsRandom(t *testing.T) {
	requireAnyStrs(t)
	b := newRegionBuffer()
	defer runtime.KeepAlive(b)
	rng := rand.New(rand.NewPCG(1, 2))
	hits := 0
	for i := 0; i < 2000; i++ {
		if i%50 == 0 {
			b.clear()
			for range 1 + rng.IntN(4) {
				off := b.at(rng.IntN(3), rng.IntN(region))
				n := 1 + rng.IntN(200)
				require.True(t, heapbits.Set(unsafe.Pointer(&b.buf[off]), uintptr(min(n, len(b.buf)-off))))
			}
		}
		a := make([]string, 1+rng.IntN(16))
		for j := range a {
			var n int
			switch rng.IntN(4) {
			case 0:
				n = rng.IntN(8)
			case 1:
				n = rng.IntN(130)
			case 2:
				n = inline - 4 + rng.IntN(8)
			default:
				n = rng.IntN(5000)
			}
			off := b.at(rng.IntN(3), rng.IntN(region))
			if rng.IntN(4) == 0 {
				off = b.at(1+rng.IntN(2), -rng.IntN(64)) // near a region edge
			}
			n = min(n, len(b.buf)-off)
			a[j] = b.str(off, n)
		}
		want := oracle(a)
		if want {
			hits++
		}
		require.Equal(t, want, rtAnyStrs(a), "case %d", i)
	}
	require.Greater(t, hits, 100, "the random cases have too few tainted results")
	require.Less(t, hits, 1900, "the random cases have too few clean results")
}

// TestConcatSpans checks the bits of concatenation results with the test
// knobs off (the path of a production program): each tainted operand gives
// its bits at its offset in the result.
func TestConcatSpans(t *testing.T) {
	requireAnyStrs(t)
	b := newRegionBuffer()
	defer runtime.KeepAlive(b)
	b.clear()
	off := b.at(1, -3)
	require.True(t, heapbits.Set(unsafe.Pointer(&b.buf[off]), 6)) // crosses the region edge
	require.True(t, heapbits.Set(unsafe.Pointer(&b.buf[b.at(2, 1000)]), 2))
	edge := b.str(off-2, 10)             // tainted [2, 8)
	far := b.str(b.at(2, 998), 6)        // tainted [2, 4)
	long := b.str(b.at(1, 100), 3000)    // clean, long
	big := b.str(b.at(2, 900), 2*inline) // tainted [100, 102)
	clean := heapString("clean")

	for name, c := range map[string]struct {
		got  string
		want []span
	}{
		"edge":             {heapConcat2(clean, edge), []span{{7, 13}}},
		"far+edge":         {heapConcat2(far, edge), []span{{2, 4}, {8, 14}}},
		"long+far":         {heapConcat2(long, far), []span{{3002, 3004}}},
		"clean+long":       {heapConcat2(clean, long), nil},
		"big+edge+clean":   {heapConcat3(big, edge, clean), []span{{100, 102}, {2*inline + 2, 2*inline + 8}}},
		"empty+far":        {heapConcat3("", far, ""), []span{{2, 4}}},
		"6 operands":       {heapConcat6(clean, far, "", long, edge, big), []span{{7, 9}, {3011 + 2, 3011 + 8}, {3021 + 100, 3021 + 102}}},
		"6 clean operands": {heapConcat6(clean, long, "", "x", clean, long), nil},
		"bytes far+edge":   {bytesView(heapConcatBytes(far, edge)), []span{{2, 4}, {8, 14}}},
		"bytes clean+long": {bytesView(heapConcatBytes(clean, long)), nil},
	} {
		require.Equal(t, c.want, stringSpans(c.got), name)
	}
	require.True(t, stackConcatTainted("x", far), "a stack result with a tainted operand goes to the heap")
	require.False(t, stackConcatTainted("x", long), "a clean stack result")
}

// span is a tainted interval [Start, End) of a value, in bytes.
type span struct{ Start, End int }

// stringSpans returns the tainted intervals of s.
func stringSpans(s string) []span {
	var out []span
	p, m := unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s))
	for off := heapbits.Next(p, m, 0); off < m; {
		end := heapbits.NextClean(p, m, off)
		out = append(out, span{int(off), int(end)})
		off = heapbits.Next(p, m, end)
	}
	return out
}

// bytesView returns a string with the memory of b (not a copy).
func bytesView(b []byte) string { return unsafe.String(unsafe.SliceData(b), len(b)) }

//go:noinline
func heapConcat3(a, b, c string) string { return a + b + c }

//go:noinline
func heapConcat6(a, b, c, d, e, f string) string { return a + b + c + d + e + f }

//go:noinline
func heapConcatBytes(a, b string) []byte { return []byte(a + b) }

// stackConcatTainted concatenates a and b in a stack buffer, and tells if the
// result is tainted (only a heap result can be).
//
//go:noinline
func stackConcatTainted(a, b string) bool {
	s := a + b
	return anyTainted(uintptr(unsafe.Pointer(unsafe.StringData(s))), len(s))
}

// anyTainted reports whether one of the n bytes at p is tainted. It takes a
// uintptr, so the value does not escape.
func anyTainted(p uintptr, n int) bool {
	return heapbits.Any(*(*unsafe.Pointer)(unsafe.Pointer(&p)), uintptr(n))
}
