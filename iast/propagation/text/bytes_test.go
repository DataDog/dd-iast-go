// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"bytes"
	"testing"
	"unicode"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// The inputs are the ones of the PR #39 tests (P/iast/propagation/
// bytes_allocating_test.go, bytes_provenance_test.go), with exact ranges
// (plan section 9.2).

// partialBytes returns "pre-OLD-post" with "pre-" and "post" tainted by the
// sources "pre" and "post" (spans [0,4) and [8,12)).
func partialBytes(t *testing.T, sources map[string]string) []byte {
	t.Helper()
	got := []byte(sources["pre"] + "OLD-" + sources["post"])
	require.Equal(t, "pre-OLD-post", string(got))
	require.Equal(t, []span{{0, 4}, {8, 12}}, bytesSpans(got))
	return got
}

func sameBytes(a, b []byte) bool { return unsafe.SliceData(a) == unsafe.SliceData(b) }

func TestAllocatingByteOperations(t *testing.T) {
	a := begin(t)
	sources := map[string]string{"pre": source(t, a, "pre", "pre-"), "post": source(t, a, "post", "post")}
	input := partialBytes(t, sources)
	separator := sourceBytes(t, a, "separator", "::")
	replacement := sourceBytes(t, a, "replacement", "XY")

	t.Run("clone", func(t *testing.T) {
		got := bytes.Clone(input)
		require.Equal(t, input, got)
		require.False(t, sameBytes(input, got))
		require.Equal(t, []span{{0, 4}, {8, 12}}, bytesSpans(got))
		require.Nil(t, bytes.Clone(nil))
	})

	t.Run("join maps elements and separator", func(t *testing.T) {
		got := bytes.Join([][]byte{[]byte("plain"), input, []byte("tail")}, separator)
		require.Equal(t, "plain::pre-OLD-post::tail", string(got))
		require.Equal(t, []span{{5, 11}, {15, 21}}, bytesSpans(got))
		require.Equal(t, []string{"5-7=separator", "7-11=pre", "15-19=post", "19-21=separator"}, attributedBytes(t, a, got))
		one := bytes.Join([][]byte{input}, separator)
		require.False(t, sameBytes(input, one))
		require.Equal(t, []span{{0, 4}, {8, 12}}, bytesSpans(one))
		require.Empty(t, bytes.Join(nil, separator))
		require.Empty(t, bytesSpans(bytes.Join([][]byte{[]byte("a"), []byte("b")}, []byte("--"))))
	})

	t.Run("repeat", func(t *testing.T) {
		got := bytes.Repeat(input, 2)
		require.Equal(t, "pre-OLD-postpre-OLD-post", string(got))
		require.Equal(t, []span{{0, 4}, {8, 16}, {20, 24}}, bytesSpans(got))
		long := bytes.Repeat(input, 1000) // more than the 8 KiB chunk limit
		require.Len(t, bytesSpans(long), 1001)
		require.Empty(t, bytes.Repeat(input, 0))
		require.Panics(t, func() { bytes.Repeat(input, -1) })
	})

	for _, test := range []struct {
		name string
		call func() []byte
	}{
		{name: "replace", call: func() []byte { return bytes.Replace(input, []byte("OLD"), replacement, 1) }},
		{name: "replace all", call: func() []byte { return bytes.ReplaceAll(input, []byte("OLD"), replacement) }},
	} {
		t.Run(test.name+" maps copied and replacement ranges", func(t *testing.T) {
			got := test.call()
			require.Equal(t, "pre-XY-post", string(got))
			require.Equal(t, []span{{0, 6}, {7, 11}}, bytesSpans(got))
			require.Equal(t, []string{"0-4=pre", "4-6=replacement", "7-11=post"}, attributedBytes(t, a, got))
		})
	}

	t.Run("replace with an empty old value", func(t *testing.T) {
		got := bytes.Replace(input[:4], nil, replacement, -1)
		require.Equal(t, "XYpXYrXYeXY-XY", string(got))
		require.Equal(t, []span{{0, len(got)}}, bytesSpans(got))
	})

	t.Run("unused replacement copies the input", func(t *testing.T) {
		got := bytes.Replace(input, []byte("missing"), replacement, -1)
		require.False(t, sameBytes(input, got))
		require.Equal(t, []span{{0, 4}, {8, 12}}, bytesSpans(got))
	})
}

func TestByteCaseAndValidUTF8BranchesPreserveProvenance(t *testing.T) {
	a := begin(t)
	first := source(t, a, "first", "ab")
	second := source(t, a, "second", "cd")
	input := []byte("x" + first + "-" + second + "Z")

	t.Run("ASCII ToUpper is positional", func(t *testing.T) {
		got := bytes.ToUpper(input)
		require.Equal(t, "XAB-CDZ", string(got))
		require.Equal(t, []span{{1, 3}, {4, 6}}, bytesSpans(got))
		require.Equal(t, []string{"1-3=first", "4-6=second"}, attributedBytes(t, a, got))
	})

	t.Run("ASCII ToLower is positional", func(t *testing.T) {
		got := bytes.ToLower(input)
		require.Equal(t, "xab-cdz", string(got))
		require.Equal(t, []span{{1, 3}, {4, 6}}, bytesSpans(got))
		require.Equal(t, []string{"1-3=first", "4-6=second"}, attributedBytes(t, a, got))
	})

	t.Run("no change is an exact copy", func(t *testing.T) {
		lower := []byte("x" + first)
		got := bytes.ToLower(lower)
		require.False(t, sameBytes(lower, got))
		require.Equal(t, []span{{1, 3}}, bytesSpans(got))
		require.Equal(t, []string{"1-3=first"}, attributedBytes(t, a, got))
	})

	t.Run("non-ASCII is coarse", func(t *testing.T) {
		got := bytes.ToUpper([]byte("é" + first))
		require.Equal(t, "ÉAB", string(got))
		require.Equal(t, []span{{0, 4}}, bytesSpans(got))
		require.Equal(t, []string{"0-4=first"}, attributedBytes(t, a, got))
	})

	t.Run("Map is coarse and calls the mapping function one time for each rune", func(t *testing.T) {
		calls := 0
		got := bytes.Map(func(r rune) rune {
			calls++
			if r == '-' {
				return -1
			}
			return unicode.ToUpper(r)
		}, input)
		require.Equal(t, "XABCDZ", string(got))
		require.Equal(t, 7, calls)
		require.Equal(t, []span{{0, 6}}, bytesSpans(got))
		require.Equal(t, []string{"0-6=first"}, attributedBytes(t, a, got))
		require.Equal(t, []span{{0, 7}}, bytesSpans(bytes.ToTitle(input)))
	})

	t.Run("ToValidUTF8 is an exact copy", func(t *testing.T) {
		replacement := sourceBytes(t, a, "replacement", "<>")
		in := []byte(first + "\xff\xfe" + "é" + second + "\xff")
		got := bytes.ToValidUTF8(in, replacement)
		require.Equal(t, "ab<>écd<>", string(got))
		require.Equal(t, []span{{0, 4}, {6, 10}}, bytesSpans(got))
		require.Equal(t, []string{"0-2=first", "2-4=replacement", "6-8=second", "8-10=replacement"}, attributedBytes(t, a, got))

		valid := bytes.ToValidUTF8([]byte("é"+first), []byte("?"))
		require.Equal(t, []span{{2, 4}}, bytesSpans(valid))
		onlyReplacement := bytes.ToValidUTF8([]byte("a\xffb"), replacement)
		require.Equal(t, "a<>b", string(onlyReplacement))
		require.Equal(t, []span{{1, 3}}, bytesSpans(onlyReplacement))
	})
}

// TestByteResultsUnchanged checks that the hooks do not change the results:
// each function gives the same value for a tainted input as for a clean copy.
func TestByteResultsUnchanged(t *testing.T) {
	a := begin(t)
	const value = "Héllo, wörld! 'x' \xff OLD old ...   --==00 \xfe\xfd end"
	tainted := sourceBytes(t, a, "q", value)
	clean := []byte(value)
	for name, f := range map[string]func([]byte) []byte{
		"Clone":   bytes.Clone,
		"ToUpper": bytes.ToUpper,
		"ToLower": bytes.ToLower,
		"ToUpperASCII": func(b []byte) []byte {
			return bytes.ToUpper(bytes.ToValidUTF8(bytes.Map(func(r rune) rune {
				if r >= 0x80 {
					return -1
				}
				return r
			}, b), nil))
		},
		"ToTitle":     bytes.ToTitle,
		"Map":         func(b []byte) []byte { return bytes.Map(unicode.ToUpper, b) },
		"ToValidUTF8": func(b []byte) []byte { return bytes.ToValidUTF8(b, []byte("\uFFFD")) },
		"Repeat":      func(b []byte) []byte { return bytes.Repeat(b, 5) },
		"Replace":     func(b []byte) []byte { return bytes.Replace(b, []byte("old"), []byte("new"), -1) },
		"ReplaceNone": func(b []byte) []byte { return bytes.Replace(b, []byte("old"), []byte("new"), 0) },
		"ReplaceRune": func(b []byte) []byte { return bytes.Replace(b, nil, []byte("|"), 4) },
		"Join":        func(b []byte) []byte { return bytes.Join([][]byte{b, b}, []byte(", ")) },
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, f(clean), f(tainted))
			require.Empty(t, bytesSpans(f(clean)), "a clean input gives a clean output")
			require.NotEmpty(t, bytesSpans(f(tainted)))
		})
	}
}
