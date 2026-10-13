// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// TestHooksFire checks that each of the 8 hooked runtime functions copies the
// exact tainted ranges of its input (plan heapbits-sqli-cmdi, section 5.1).
func TestHooksFire(t *testing.T) {
	requireWoven(t)
	value := taintString(t, "attack")
	data := taintBytes(t, "00attack99")
	text := taintStringRange(t, "héllo", 1, 3) // "é"
	runes := taintRunes(t, "wörld!", 1, 5)     // "örld"

	t.Run("concatstrings", func(t *testing.T) {
		before := entries()
		got := heapConcat2("pre:", value)
		require.Equal(t, "pre:attack", got)
		require.Equal(t, []span{{4, 10}}, stringSpans(got))
		require.Greater(t, entries(), before)
	})
	t.Run("concatbytes", func(t *testing.T) {
		got := heapConcatBytes("pre:", value)
		require.Equal(t, []byte("pre:attack"), got)
		require.Equal(t, []span{{4, 10}}, bytesSpans(got))
	})
	t.Run("slicebytetostring", func(t *testing.T) {
		got := heapB2S(data[1:9])
		require.Equal(t, "0attack9", got)
		require.Equal(t, []span{{0, 8}}, stringSpans(got))
	})
	t.Run("stringtoslicebyte", func(t *testing.T) {
		got := heapS2B(value)
		require.Equal(t, []byte("attack"), got)
		require.Equal(t, []span{{0, 6}}, bytesSpans(got))
	})
	t.Run("slicerunetostring", func(t *testing.T) {
		// Runes 1 to 4 ("örld") are tainted. "ö" has 2 bytes in UTF-8.
		got := heapR2S(runes)
		require.Equal(t, "wörld!", got)
		require.Equal(t, []span{{1, 6}}, stringSpans(got))
	})
	t.Run("stringtoslicerune", func(t *testing.T) {
		// Rune 1 ("é") is tainted: bytes [4, 8) of the rune array.
		got := heapS2R(text)
		require.Equal(t, []rune("héllo"), got)
		require.Equal(t, []span{{4, 8}}, runeSpans(got))
	})
	t.Run("growslice", func(t *testing.T) {
		before := entries()
		got := heapGrow(data)
		require.Equal(t, "00attack99!", string(got))
		require.NotEqual(t, bytesData(data), bytesData(got), "append grew the slice")
		require.Equal(t, []span{{0, 10}}, bytesSpans(got))
		require.Greater(t, entries(), before)
	})
	t.Run("growsliceBuf", func(t *testing.T) {
		got := bufGrow(45)
		require.Len(t, got, 7)
		require.Equal(t, []span{{0, 2}}, bytesSpans(got), "the 2 tainted old elements keep their taint")
	})
}

// TestGrowNoOldElements checks the appends with no old element (newLen ==
// num): the growslice and growsliceBuf hooks do not call their filter and
// their wrapper, and the new backing store has no bits, also when the old
// backing store (after len) is tainted. The memmove of the new elements does
// not copy bits. An append with one old element still copies its bits. The
// test counter of the filter calls without old element (rtGrow0) stays 0:
// it fails when the hooks call the filter for such an append.
func TestGrowNoOldElements(t *testing.T) {
	requireWoven(t)
	require.NotNil(t, rtGrow0, "the woven runtime does not push __dd_iast_runtime.grow0")
	data := taintBytes(t, "00attack99")
	src := taintBytes(t, "attack")
	require.Equal(t, []span{{0, 10}}, bytesSpans(data))

	before := entries()
	before0 := rtGrow0()
	got := heapAppendTo(data[:0:0], src)
	require.Equal(t, "attack", string(got))
	require.NotEqual(t, bytesData(data), bytesData(got), "append made a new backing store")
	require.Empty(t, bytesSpans(got), "no old element: no bits")
	got = heapAppendTo(nil, src)
	require.Equal(t, "attack", string(got))
	require.Empty(t, bytesSpans(got), "nil slice: no bits")
	require.Equal(t, before, entries(), "no wrapper call without old elements")
	got = bufAppendEach(src)
	require.Equal(t, "attack", string(got))
	require.Empty(t, bytesSpans(got), "growsliceBuf: the old elements are clean stack memory")
	require.Equal(t, before, entries(), "no wrapper call without old elements (growsliceBuf)")
	require.Equal(t, before0, rtGrow0(), "a hook called the grow filter without old elements")

	got = heapAppendTo(data[:1:1], src)
	require.Equal(t, "0attack", string(got))
	require.Equal(t, []span{{0, 1}}, bytesSpans(got), "the one old element keeps its bits")
	require.Greater(t, entries(), before)
}

// heapAppendTo appends src to dst (a new heap backing store when cap(dst) is
// too small).
//
//go:noinline
func heapAppendTo(dst, src []byte) []byte { return append(dst, src...) }

// bufAppendEach appends the bytes of src one by one to an empty slice. The
// result escapes and the code reads its capacity, thus the compiler uses
// growsliceBuf with a stack buffer (as in bufGrow): the first call has no old
// element (newLen == num == 1).
//
//go:noinline
func bufAppendEach(src []byte) []byte {
	var out []byte
	for _, c := range src {
		out = append(out, c)
		sinkInt += cap(out)
	}
	return out
}

type definedString string

func genericConcat[T ~string](left, right T) T { return left + right }

//go:noinline
func concat17(x, last string) string {
	return x + x + x + x + x + x + x + x + x + x + x + x + x + x + x + x + last
}

//go:noinline
func concat40(x, last string) string {
	return x + x + x + x + x + x + x + x + x + x +
		x + x + x + x + x + x + x + x + x + x +
		x + x + x + x + x + x + x + x + x + x +
		x + x + x + x + x + x + x + x + x + last
}

// concat18 concatenates a[0] to a[17] with one expression.
//
//go:noinline
func concat18(a []string) string {
	return a[0] + a[1] + a[2] + a[3] + a[4] + a[5] + a[6] + a[7] + a[8] +
		a[9] + a[10] + a[11] + a[12] + a[13] + a[14] + a[15] + a[16] + a[17]
}

// TestConcatCases checks the exact ranges of concatenations.
func TestConcatCases(t *testing.T) {
	requireWoven(t)
	value := taintString(t, "attack")
	x := "x"

	for _, test := range []struct {
		name string
		got  string
		want []span
	}{
		{"a+b", heapConcat2(x, value), []span{{1, 7}}},
		{"a+b+c", heapConcat3(x, value, x), []span{{1, 7}}},
		{"6 operands", heapConcat6(x, x, value, x, value, x), []span{{2, 8}, {9, 15}}},
		{"adjacent operands", heapConcat3(x, value, value), []span{{1, 13}}},
		{"17 operands, only the last tainted", concat17(x, value), []span{{16, 22}}},
		{"40 operands, only the last tainted", concat40(x, value), []span{{39, 45}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, stringSpans(test.got))
		})
	}

	t.Run("partly tainted operand", func(t *testing.T) {
		// Only "tac" (bytes [2, 5)) of the operand is tainted.
		partial := taintStringRange(t, "attack", 2, 5)
		require.Equal(t, []span{{6, 9}}, stringSpans(heapConcat3("pre:", partial, ":post")))
		require.Equal(t, []span{{2, 5}, {8, 11}}, stringSpans(heapConcat2(partial, partial)))
	})
	t.Run("plus assign", func(t *testing.T) {
		got := "prefix:"
		got += value
		require.Equal(t, []span{{7, 13}}, stringSpans(got))
	})
	t.Run("defined and generic", func(t *testing.T) {
		defined := definedString(value)
		got := definedString("prefix:") + defined
		require.Equal(t, []span{{7, 13}}, stringSpans(string(got)))
		generic := genericConcat(definedString("pre:"), defined)
		require.Equal(t, []span{{4, 10}}, stringSpans(string(generic)))
	})
	t.Run("bytes of concat", func(t *testing.T) {
		got := []byte("pre:" + value + ":post")
		require.Equal(t, []span{{4, 10}}, bytesSpans(got))
	})
	t.Run("identity", func(t *testing.T) {
		empty := ""
		got := empty + value
		require.Equal(t, unsafe.StringData(value), unsafe.StringData(got))
		require.Equal(t, []span{{0, 6}}, stringSpans(got))
	})
	t.Run("two sources", func(t *testing.T) {
		alpha, bravo := taintString(t, "AA"), taintString(t, "BB")
		parts := make([]string, 18)
		for i := range parts {
			parts[i] = "-"
		}
		parts[3], parts[10] = alpha, bravo
		got := concat18(parts)
		require.Equal(t, "---AA------BB-------", got)
		require.Equal(t, []span{{3, 5}, {11, 13}}, stringSpans(got))
	})
}

// TestConcatClean checks that a clean concatenation is not tainted when the
// gate is on, and that it does not enter a wrapper.
func TestConcatClean(t *testing.T) {
	requireWoven(t)
	_ = taintString(t, "attack")
	clean := heapString("value")
	before := entries()
	got := heapConcat2("clean-", clean)
	require.Equal(t, before, entries())
	require.Empty(t, stringSpans(got))
	require.Empty(t, bytesSpans(heapS2B(clean)))
	require.Empty(t, stringSpans(heapB2S(heapBytes("clean-bytes"))))
}

// TestConcatConcurrent runs tainted and clean operations on many goroutines
// (run it with -race): each result has the exact taint of its own inputs.
func TestConcatConcurrent(t *testing.T) {
	requireWoven(t)
	value := taintString(t, "tainted")
	clean := heapString("cleaned")
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := range 8 {
		wg.Go(func() {
			for i := range 500 {
				pre := strings.Repeat("p", (g+i)%7)
				tainted := heapConcat3(pre, value, clean)
				if got := stringSpans(tainted); len(got) != 1 || got[0] != (span{len(pre), len(pre) + 7}) {
					errs <- "tainted concat: " + spansString(got)
					return
				}
				if got := stringSpans(heapConcat2(pre, clean)); len(got) != 0 {
					errs <- "clean concat: " + spansString(got)
					return
				}
				if got := bytesSpans(heapS2B(tainted)); len(got) != 1 {
					errs <- "[]byte(s): " + spansString(got)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func spansString(s []span) string {
	var b strings.Builder
	for _, x := range s {
		b.WriteString(x.String())
	}
	return b.String()
}
