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
	"github.com/stretchr/testify/require"
)

type definedBytes []byte

func bytesToStringReturn(value definedBytes) definedString { return definedString(value) }

func genericBytesToString[T ~[]byte, S ~string](value T) S { return S(value) }

//go:noinline
func identityString(value string) string { return value }

// aliasOperand returns a concatenation with the operand string(b). The
// compiler does not copy b for this operand (OBYTES2STRTMP): the operand is
// an alias of b, and the interior lookup finds its taint.
//
//go:noinline
func aliasOperand(b []byte) string { return "<" + string(b) + ">" }

// TestConversionForms checks plan section 9.1 item 3: the rows of section
// 4.1, including the alias rows and the documented misses.
func TestConversionForms(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintBytes(t, ctx, "conversion", []byte("00attack99"))
	text := taintString(t, ctx, "text", "attack")
	want := []span{{0, 10, "conversion"}}

	assigned := string(value)
	var declared definedString = definedString(value)
	for name, got := range map[string]string{
		"assignment":    assigned,
		"declaration":   string(declared),
		"return":        string(bytesToStringReturn(definedBytes(value))),
		"generic":       string(genericBytesToString[definedBytes, definedString](definedBytes(value))),
		"call argument": identityString(string(value)),
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, "00attack99", got)
			require.Equal(t, want, spansOf(got))
		})
	}

	t.Run("alias operand of a concatenation", func(t *testing.T) {
		got := aliasOperand(value)
		require.Equal(t, []span{{1, 10, "conversion"}}, spansOf(got))
	})
	t.Run("alias forms run", func(t *testing.T) {
		keys := map[string]bool{"00attack99": true}
		require.True(t, keys[string(value)])
		require.True(t, string(value) == "00attack99")
		switch string(value) {
		case "00attack99":
		default:
			t.Fatal("switch on string(b)")
		}
		count := 0
		for range []byte(text) {
			count++
		}
		require.Equal(t, len(text), count)
		require.Equal(t, 10, len(string(value)))
	})
	t.Run("bytes of string", func(t *testing.T) {
		got := []byte(text)
		require.Equal(t, []span{{0, 6, "text"}}, bytesSpansOf(got))
	})
	t.Run("literal bytes are clean", func(t *testing.T) {
		require.Empty(t, bytesSpansOf([]byte("literal")))
	})
	t.Run("documented misses", func(t *testing.T) {
		// string(r) of a rune value has no memory identity.
		require.Empty(t, spansOf(string(rune(text[0]))+string(rune(text[1]))))
		// A one-byte result is static memory or below the root minimum.
		require.Empty(t, spansOf(string(value[2:3])))
		// append and copy are not hooked.
		appended := append([]byte("prefix:"), value...)
		require.Empty(t, bytesSpansOf(appended))
		copied := make([]byte, len(value))
		copy(copied, value)
		require.Empty(t, bytesSpansOf(copied))
	})
}

// TestSlicesNeedNoHook checks that slices of a tainted value keep their taint
// without a hook: the interior lookup finds every window of a root.
func TestSlicesNeedNoHook(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	source := taintString(t, ctx, "string", "attack")
	value := adoptString(t, source, "00attack99", [2]uint32{2, 6})
	for _, test := range []struct {
		got  string
		want []span
	}{
		{value[:], []span{{2, 6, "string"}}},
		{value[1:], []span{{1, 6, "string"}}},
		{value[:9], []span{{2, 6, "string"}}},
		{value[1:9], []span{{1, 6, "string"}}},
		{value[3:5], []span{{0, 2, "string"}}},
		{value[8:], nil},
	} {
		require.Equal(t, test.want, spansOf(test.got), "%q", test.got)
	}
	data := taintBytes(t, ctx, "bytes", []byte("0123456789"))
	require.Equal(t, []span{{0, 7, "bytes"}}, bytesSpansOf(data[1:8:9]))
	require.Equal(t, []span{{0, 9, "bytes"}}, bytesSpansOf(data[:9:9]))
}

// TestRuneConversions checks the rune mapping of plan section 4.5 through
// the woven runtime.
func TestRuneConversions(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	source := taintString(t, ctx, "r", "source")

	t.Run("ascii round trip", func(t *testing.T) {
		value := adoptString(t, source, "hello world", [2]uint32{6, 5})
		runes := heapS2R(value)
		require.Equal(t, [][2]uint32{{24, 20}}, runeRanges(runes))
		back := heapR2S(runes)
		require.Equal(t, "hello world", back)
		require.Equal(t, []span{{6, 5, "r"}}, spansOf(back))
	})
	t.Run("multi-byte word", func(t *testing.T) {
		// "世界" is bytes [7, 13) and runes [6, 8).
		value := adoptString(t, source, "héllo 世界", [2]uint32{7, 6})
		runes := heapS2R(value)
		require.Equal(t, [][2]uint32{{24, 8}}, runeRanges(runes))
		require.Equal(t, []span{{7, 6, "r"}}, spansOf(heapR2S(runes)))
	})
	t.Run("range starts inside a rune", func(t *testing.T) {
		// Byte 2 is the second byte of "é": the range covers all of "é".
		value := adoptString(t, source, "aébc", [2]uint32{2, 2})
		require.Equal(t, [][2]uint32{{4, 8}}, runeRanges(heapS2R(value)))
	})
	t.Run("invalid utf-8", func(t *testing.T) {
		value := adoptString(t, source, "a\xffb", [2]uint32{1, 1})
		runes := heapS2R(value)
		require.Equal(t, [][2]uint32{{4, 4}}, runeRanges(runes))
		back := heapR2S(runes)
		require.Equal(t, "a\uFFFDb", back)
		require.Equal(t, []span{{1, 3, "r"}}, spansOf(back))
	})
	t.Run("surrogate rune", func(t *testing.T) {
		runes := heapRunes("a?b")
		runes[1] = 0xD800
		adoptRunes(t, source, runes, 1, 2)
		back := heapR2S(runes)
		require.Equal(t, "a\uFFFDb", back)
		require.Equal(t, []span{{1, 3, "r"}}, spansOf(back))
	})
	t.Run("interior window", func(t *testing.T) {
		runes := heapRunes("abcdefg")
		adoptRunes(t, source, runes, 2, 5)
		require.Equal(t, []span{{0, 3, "r"}}, spansOf(heapR2S(runes[2:5])))
		require.Equal(t, []span{{1, 2, "r"}}, spansOf(heapR2S(runes[1:4])))
	})
	t.Run("stack boundary", func(t *testing.T) {
		for _, n := range []int{32, 33} {
			value := taintString(t, ctx, "n", repeat("a", n))
			p := stackS2R(value)
			require.True(t, p.tainted, "%d runes", n)
		}
	})
	t.Run("root limit", func(t *testing.T) {
		for _, test := range []struct {
			runes   int
			tainted bool
		}{{16384, true}, {16385, false}} {
			value := taintString(t, ctx, "big", repeat("a", test.runes))
			runes := heapS2R(value)
			require.Equal(t, test.tainted, len(runeRanges(runes)) != 0, "[]rune(s) with %d runes", test.runes)
		}
		for _, test := range []struct {
			runes   int
			tainted bool
		}{{16383, true}, {16384, false}} {
			runes := heapRunes(repeat("a", test.runes))
			adoptRunes(t, source, runes, 0, test.runes)
			require.Equal(t, test.tainted, len(spansOf(heapR2S(runes))) != 0, "string(rs) with %d runes", test.runes)
		}
	})
}

// TestStringToSliceSwitchOff checks plan section 4.4: with the switch off,
// []byte(s) and []rune(s) do not enter the bridge and stay on the stack, and
// string(b) and concatenation still propagate.
func TestStringToSliceSwitchOff(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	short := taintString(t, ctx, "short", "short-value")
	long := taintString(t, ctx, "long", repeat("z", 40))
	previous := bridgetest.SetS2SGate(0)
	t.Cleanup(func() { bridgetest.SetS2SGate(previous) })
	require.False(t, runtimebridge.StringToSliceEnabled())

	before := entries()
	b := heapS2B(long)
	r := heapS2R(long)
	p1 := stackS2B(short)
	p2 := stackS2R(short)
	require.Equal(t, before, entries(), "the switch is off: no bridge entry")
	require.Empty(t, bytesSpansOf(b))
	require.Empty(t, runeRanges(r))
	require.Equal(t, probe{}, p1)
	require.Equal(t, probe{}, p2)
	require.Zero(t, testing.AllocsPerRun(100, func() { sinkInt = stackS2BLen(short) + stackS2RLen(short) }))

	require.NotEmpty(t, spansOf(heapConcat2("x", long)))
	data := taintBytes(t, ctx, "data", []byte(strings.Repeat("q", 40)))
	require.NotEmpty(t, spansOf(heapB2S(data)))
}
