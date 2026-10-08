// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

// The inputs are the ones of the PR #39 tests (P/iast/propagation/
// strings_allocating_test.go, strings_provenance_test.go); the ranges are
// exact (plan section 9.2) and the sources are found by the request
// attribution (content match of the source values).

// partial returns "pre-OLD-post" with "pre-" and "post" tainted by the
// sources "pre" and "post" (spans [0,4) and [8,12)).
func partial(t *testing.T, sources map[string]string) string {
	t.Helper()
	got := sources["pre"] + "OLD-" + sources["post"]
	require.Equal(t, "pre-OLD-post", got)
	require.Equal(t, []span{{0, 4}, {8, 12}}, stringSpans(got))
	return got
}

func TestBuilderWrites(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "attack")
	data := sourceBytes(t, a, "b", "bytes!")

	var b strings.Builder
	b.WriteString("pre:")
	b.WriteString(value)
	b.WriteByte(' ')
	b.Write(data)
	b.WriteRune('é')
	got := b.String()
	require.Equal(t, "pre:attack bytes!é", got)
	require.Equal(t, []span{{4, 10}, {11, 17}}, stringSpans(got))
	require.Equal(t, []string{"4-10=q", "11-17=b"}, attributed(t, a, got))

	t.Run("growth keeps the bits", func(t *testing.T) {
		var b strings.Builder
		var want []span
		for i := range 200 {
			if i%3 == 0 {
				want = append(want, span{b.Len(), b.Len() + len(value)})
				b.WriteString(value)
			} else {
				b.WriteString("clean-")
			}
		}
		require.Equal(t, want, stringSpans(b.String()))
	})

	t.Run("Grow copies the bits", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(value)
		before := b.String()
		b.Grow(4096)
		after := b.String()
		require.False(t, sameData(before, after), "Grow moved the buffer")
		require.Equal(t, []span{{0, 6}}, stringSpans(after))
	})

	t.Run("clean writes have no bits", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("clean")
		b.Write([]byte(" bytes"))
		require.Empty(t, stringSpans(b.String()))
	})
}

func TestStringsClone(t *testing.T) {
	a := begin(t)
	sources := map[string]string{"pre": source(t, a, "pre", "pre-"), "post": source(t, a, "post", "post")}
	input := partial(t, sources)
	got := strings.Clone(input)
	require.Equal(t, input, got)
	require.False(t, sameData(input, got))
	require.Equal(t, []span{{0, 4}, {8, 12}}, stringSpans(got))
	require.Equal(t, []string{"0-4=pre", "8-12=post"}, attributed(t, a, got))
	require.Empty(t, stringSpans(strings.Clone(strings.Repeat("x", 12))))
}

func TestAllocatingStringOperations(t *testing.T) {
	a := begin(t)
	sources := map[string]string{"pre": source(t, a, "pre", "pre-"), "post": source(t, a, "post", "post")}
	input := partial(t, sources)
	separator := source(t, a, "separator", "::")
	replacement := source(t, a, "replacement", "XY")

	t.Run("join maps elements and separator", func(t *testing.T) {
		got := strings.Join([]string{"plain", input, "tail"}, separator)
		require.Equal(t, "plain::pre-OLD-post::tail", got)
		require.Equal(t, []span{{5, 11}, {15, 21}}, stringSpans(got))
		require.Equal(t, []string{"5-7=separator", "7-11=pre", "15-19=post", "19-21=separator"}, attributed(t, a, got))
	})

	t.Run("repeat preserves aliases and fresh copies", func(t *testing.T) {
		aliased := strings.Repeat(input, 1)
		require.True(t, sameData(input, aliased))
		got := strings.Repeat(input, 2)
		require.Equal(t, "pre-OLD-postpre-OLD-post", got)
		require.False(t, sameData(input, got))
		require.Equal(t, []span{{0, 4}, {8, 16}, {20, 24}}, stringSpans(got))
		require.Equal(t, []string{"0-4=pre", "8-12=post", "12-16=pre", "20-24=post"}, attributed(t, a, got))

		long := strings.Repeat(input, 1000) // more than the 8 KiB chunk limit
		require.Len(t, stringSpans(long), 1001)
	})

	t.Run("repeat does not use the read-only fast path for tainted values", func(t *testing.T) {
		for _, value := range []string{"--", "  ", "00", "==", "\t\t"} {
			s := source(t, a, "fast", value)
			got := strings.Repeat(s, 3)
			require.Equal(t, value+value+value, got)
			require.Equal(t, []span{{0, 6}}, stringSpans(got), "%q", value)
		}
		// A clean value still uses the fast path (no hook work).
		require.Empty(t, stringSpans(strings.Repeat("--", 3)))
	})

	for _, test := range []struct {
		name string
		call func() string
	}{
		{name: "replace", call: func() string { return strings.Replace(input, "OLD", replacement, 1) }},
		{name: "replace all", call: func() string { return strings.ReplaceAll(input, "OLD", replacement) }},
	} {
		t.Run(test.name+" maps copied and replacement ranges", func(t *testing.T) {
			got := test.call()
			require.Equal(t, "pre-XY-post", got)
			require.Equal(t, []span{{0, 6}, {7, 11}}, stringSpans(got))
			require.Equal(t, []string{"0-4=pre", "4-6=replacement", "7-11=post"}, attributed(t, a, got))
		})
	}

	t.Run("unused replacement does not contribute", func(t *testing.T) {
		got := strings.Replace(input, "missing", replacement, -1)
		require.True(t, sameData(input, got))
		require.Equal(t, []span{{0, 4}, {8, 12}}, stringSpans(got))
	})
}

func TestStringCaseOperations(t *testing.T) {
	a := begin(t)
	first := source(t, a, "first", "ab")
	second := source(t, a, "second", "cd")
	input := "x" + first + "-" + second + "Z"

	t.Run("ASCII ToUpper is positional", func(t *testing.T) {
		got := strings.ToUpper(input)
		require.Equal(t, "XAB-CDZ", got)
		require.Equal(t, []span{{1, 3}, {4, 6}}, stringSpans(got))
		require.Equal(t, []string{"1-3=first", "4-6=second"}, attributed(t, a, got))
		query := "SELECT '" + got[1:6] + "'"
		require.Equal(t, []string{"8-10=first", "11-13=second"}, attributed(t, a, query))
	})

	t.Run("ASCII ToLower is positional", func(t *testing.T) {
		upper := source(t, a, "upper", "SELECT")
		got := strings.ToLower("x" + upper)
		require.Equal(t, "xselect", got)
		require.Equal(t, []span{{1, 7}}, stringSpans(got))
		require.Equal(t, []string{"1-7=upper"}, attributed(t, a, got))
	})

	t.Run("no change returns the input", func(t *testing.T) {
		upper := "X" + source(t, a, "same", "ABC")
		got := strings.ToUpper(upper)
		require.True(t, sameData(upper, got))
		require.Equal(t, []span{{1, 4}}, stringSpans(got))
	})

	t.Run("non-ASCII is coarse", func(t *testing.T) {
		accent := source(t, a, "accent", "héllo")
		got := strings.ToUpper("x" + accent)
		require.Equal(t, "XHÉLLO", got)
		require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
		require.Equal(t, []string{"0-7=accent"}, attributed(t, a, got))
		query := "q=" + got
		require.Equal(t, []string{"2-9=accent"}, attributed(t, a, query))
	})

	t.Run("ToTitle and special cases are coarse", func(t *testing.T) {
		got := strings.ToTitle(input)
		require.Equal(t, "XAB-CDZ", got)
		require.Equal(t, []span{{0, 7}}, stringSpans(got))
		require.Equal(t, []string{"0-7=first"}, attributed(t, a, got))
		got = strings.ToUpperSpecial(unicode.TurkishCase, "i"+first)
		require.Equal(t, "İAB", got)
		require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
	})
}

func TestStringMap(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "héllo wörld")
	input := "<" + value + ">"

	count := func(s string) (string, int) {
		calls := 0
		out := strings.Map(func(r rune) rune {
			calls++
			if r == ' ' {
				return -1
			}
			return unicode.ToUpper(r)
		}, s)
		return out, calls
	}
	got, calls := count(input)
	want, wantCalls := count(strings.Clone("<héllo wörld>"))
	require.Equal(t, want, got)
	require.Equal(t, wantCalls, calls, "the mapping function runs one time for each rune")
	require.Equal(t, "<HÉLLOWÖRLD>", got)
	require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
	require.Equal(t, []string{"0-14=q"}, attributed(t, a, got))

	t.Run("unchanged input is returned", func(t *testing.T) {
		got := strings.Map(func(r rune) rune { return r }, input)
		require.True(t, sameData(input, got))
		require.Equal(t, stringSpans(input), stringSpans(got))
	})

	t.Run("all runes dropped", func(t *testing.T) {
		require.Empty(t, strings.Map(func(rune) rune { return -1 }, input))
	})

	t.Run("a panic of the mapping function goes on", func(t *testing.T) {
		require.PanicsWithValue(t, "boom", func() {
			strings.Map(func(rune) rune { panic("boom") }, input)
		})
	})
}

func TestToValidUTF8(t *testing.T) {
	a := begin(t)

	t.Run("tainted input is coarse", func(t *testing.T) {
		value := source(t, a, "q", "ab\xffcd")
		got := strings.ToValidUTF8("<"+value, "?")
		require.Equal(t, "<ab?cd", got)
		require.Equal(t, []span{{0, 6}}, stringSpans(got))
		require.Equal(t, []string{"0-6=q"}, attributed(t, a, got))
	})

	t.Run("valid input is returned", func(t *testing.T) {
		value := "<" + source(t, a, "valid", "valid")
		got := strings.ToValidUTF8(value, "?")
		require.True(t, sameData(value, got))
	})

	t.Run("a tainted replacement keeps its exact bits", func(t *testing.T) {
		replacement := source(t, a, "replacement", "<>")
		got := strings.ToValidUTF8(strings.Clone("a\xff\xfeb"), replacement)
		require.Equal(t, "a<>b", got)
		require.Equal(t, []span{{1, 3}}, stringSpans(got))
		require.Equal(t, []string{"1-3=replacement"}, attributed(t, a, got))
	})
}

func TestReplacerReplace(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "a'b'c")

	for name, r := range map[string]*strings.Replacer{
		"byte":         strings.NewReplacer("'", "\""),
		"byte string":  strings.NewReplacer("'", "''"),
		"single":       strings.NewReplacer("'b'", "[B]"),
		"generic":      strings.NewReplacer("'", "\\'", "b", "B"),
		"generic many": strings.NewReplacer("a", "1", "b", "2", "c", "3"),
	} {
		t.Run(name, func(t *testing.T) {
			input := "x=" + value
			got := r.Replace(input)
			require.Equal(t, r.Replace(strings.Clone("x=a'b'c")), got)
			require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
			require.Equal(t, []string{"0-" + strconv.Itoa(len(got)) + "=q"}, attributed(t, a, got))
		})
	}

	t.Run("no replacement returns the input", func(t *testing.T) {
		input := "x=" + value
		got := strings.NewReplacer("z", "y").Replace(input)
		require.True(t, sameData(input, got))
	})

	// Deviation from TestReplacerReplacementProvenanceIsUnsupported (plan
	// section 9.2): the Builder hook copies the bits of a tainted
	// replacement.
	t.Run("tainted replacement of the single string replacer", func(t *testing.T) {
		replacement := source(t, a, "replacement", "NEW")
		got := strings.NewReplacer("old", replacement).Replace(strings.Clone("an old value"))
		require.Equal(t, "an NEW value", got)
		require.Equal(t, []span{{3, 6}}, stringSpans(got))
		require.Equal(t, []string{"3-6=replacement"}, attributed(t, a, got))
	})
}

// TestStringResultsUnchanged checks that the hooks do not change the results:
// each function gives the same value for a tainted input as for a clean copy.
func TestStringResultsUnchanged(t *testing.T) {
	a := begin(t)
	tainted := source(t, a, "q", "Héllo, wörld! 'x' \xff OLD old ...   --==00")
	clean := strings.Clone("Héllo, wörld! 'x' \xff OLD old ...   --==00")
	for name, f := range map[string]func(string) string{
		"Clone":       strings.Clone,
		"ToUpper":     strings.ToUpper,
		"ToLower":     strings.ToLower,
		"ToTitle":     strings.ToTitle,
		"Map":         func(s string) string { return strings.Map(unicode.ToUpper, s) },
		"ToValidUTF8": func(s string) string { return strings.ToValidUTF8(s, "\uFFFD") },
		"Repeat":      func(s string) string { return strings.Repeat(s, 5) },
		"Replace":     func(s string) string { return strings.Replace(s, "old", "new", -1) },
		"Replacer":    func(s string) string { return strings.NewReplacer("'", "''", "OLD", "N").Replace(s) },
		"Join":        func(s string) string { return strings.Join([]string{s, s}, ", ") },
		"Builder": func(s string) string {
			var b strings.Builder
			b.WriteString(s)
			_, _ = b.Write([]byte(s))
			return b.String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, f(clean), f(tainted))
			require.Empty(t, stringSpans(f(clean)), "a clean input gives a clean output")
			require.NotEmpty(t, stringSpans(f(tainted)))
		})
	}
}
