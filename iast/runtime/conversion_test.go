// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

type definedBytes []byte

func bytesToStringReturn(value definedBytes) definedString { return definedString(value) }

func genericBytesToString[T ~[]byte, S ~string](value T) S { return S(value) }

//go:noinline
func identityString(value string) string { return value }

// aliasOperand returns a concatenation with the operand string(b). The
// compiler does not copy b for this operand (OBYTES2STRTMP): the operand is
// an alias of b, so it has the bits of b.
//
//go:noinline
func aliasOperand(b []byte) string { return "<" + string(b) + ">" }

// TestConversionForms checks the source forms of string(b) and []byte(s),
// including the alias forms and the documented misses.
func TestConversionForms(t *testing.T) {
	requireWoven(t)
	value := taintBytes(t, "00attack99")
	text := taintString(t, "attack")
	want := []span{{0, 10}}

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
			require.Equal(t, want, stringSpans(got))
		})
	}

	t.Run("alias operand of a concatenation", func(t *testing.T) {
		got := aliasOperand(value)
		require.Equal(t, []span{{1, 11}}, stringSpans(got))
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
		require.Equal(t, []span{{0, 6}}, bytesSpans(got))
	})
	t.Run("literal bytes are clean", func(t *testing.T) {
		require.Empty(t, bytesSpans([]byte("literal")))
	})
	t.Run("documented misses", func(t *testing.T) {
		// string(r) of a rune value has no memory identity.
		require.Empty(t, stringSpans(string(rune(text[0]))+string(rune(text[1]))))
		// A one-byte result is static memory.
		require.Empty(t, stringSpans(string(value[2:3])))
		// The appended part of append(x, y...) and copy are an inline
		// memmove: no hook.
		appended := append(heapBytes("prefix:"), value...)
		require.Empty(t, bytesSpans(appended))
		copied := make([]byte, len(value))
		copy(copied, value)
		require.Empty(t, bytesSpans(copied))
	})
}

// TestSlicesNeedNoHook checks that slices of a tainted value keep their taint
// without a hook: a slice uses the same memory.
func TestSlicesNeedNoHook(t *testing.T) {
	requireWoven(t)
	value := taintStringRange(t, "00attack99", 2, 8)
	for _, test := range []struct {
		got  string
		want []span
	}{
		{value[:], []span{{2, 8}}},
		{value[1:], []span{{1, 7}}},
		{value[:9], []span{{2, 8}}},
		{value[1:9], []span{{1, 7}}},
		{value[3:5], []span{{0, 2}}},
		{value[8:], nil},
	} {
		require.Equal(t, test.want, stringSpans(test.got), "%q", test.got)
	}
	data := taintBytes(t, "0123456789")
	require.Equal(t, []span{{0, 7}}, bytesSpans(data[1:8:9]))
	require.Equal(t, []span{{0, 9}}, bytesSpans(data[:9:9]))
}

// TestRuneConversions checks the rune mappings of plan section 5.1 (rows 5
// and 6): a rune is tainted when one of its UTF-8 bytes is tainted, and the
// UTF-8 bytes of a rune are tainted when one of its 4 bytes is tainted.
func TestRuneConversions(t *testing.T) {
	requireWoven(t)

	t.Run("ascii round trip", func(t *testing.T) {
		value := taintStringRange(t, "hello world", 6, 11)
		runes := heapS2R(value)
		require.Equal(t, []span{{24, 44}}, runeSpans(runes))
		back := heapR2S(runes)
		require.Equal(t, "hello world", back)
		require.Equal(t, []span{{6, 11}}, stringSpans(back))
	})
	t.Run("multi-byte word", func(t *testing.T) {
		// "世界" is bytes [7, 13) and runes [6, 8).
		value := taintStringRange(t, "héllo 世界", 7, 13)
		runes := heapS2R(value)
		require.Equal(t, []span{{24, 32}}, runeSpans(runes))
		require.Equal(t, []span{{7, 13}}, stringSpans(heapR2S(runes)))
	})
	t.Run("range starts inside a rune", func(t *testing.T) {
		// Byte 2 is the second byte of "é": the range covers all of "é".
		value := taintStringRange(t, "aébc", 2, 4)
		require.Equal(t, []span{{4, 12}}, runeSpans(heapS2R(value)))
	})
	t.Run("two runs", func(t *testing.T) {
		value := taintString(t, "ab")
		mixed := heapConcat3(value, "-ü-", value)
		require.Equal(t, []span{{0, 2}, {6, 8}}, stringSpans(mixed))
		runes := heapS2R(mixed)
		require.Equal(t, []span{{0, 8}, {20, 28}}, runeSpans(runes))
		require.Equal(t, []span{{0, 2}, {6, 8}}, stringSpans(heapR2S(runes)))
	})
	t.Run("invalid utf-8", func(t *testing.T) {
		value := taintStringRange(t, "a\xffb", 1, 2)
		runes := heapS2R(value)
		require.Equal(t, []span{{4, 8}}, runeSpans(runes))
		back := heapR2S(runes)
		require.Equal(t, "a\uFFFDb", back)
		require.Equal(t, []span{{1, 4}}, stringSpans(back))
	})
	t.Run("invalid utf-8 only", func(t *testing.T) {
		value := taintString(t, "\xff\xfe")
		back := heapR2S(heapS2R(value))
		require.Equal(t, "\uFFFD\uFFFD", back)
		require.Equal(t, []span{{0, 6}}, stringSpans(back))
	})
	t.Run("surrogate and out of range runes", func(t *testing.T) {
		runes := heapRunes("a??b")
		runes[1], runes[2] = 0xD800, 0x110000
		require.True(t, taintBytesNoLeak(runesData(runes)+4, 8))
		back := heapR2S(runes)
		require.Equal(t, "a\uFFFD\uFFFDb", back)
		require.Equal(t, []span{{1, 7}}, stringSpans(back))
	})
	t.Run("one byte of a rune", func(t *testing.T) {
		runes := heapRunes("aöb")
		require.True(t, taintBytesNoLeak(runesData(runes)+7, 1)) // the last byte of 'ö'
		require.Equal(t, []span{{1, 3}}, stringSpans(heapR2S(runes)))
	})
	t.Run("interior window", func(t *testing.T) {
		runes := taintRunes(t, "abcdefg", 2, 5)
		require.Equal(t, []span{{0, 3}}, stringSpans(heapR2S(runes[2:5])))
		require.Equal(t, []span{{1, 3}}, stringSpans(heapR2S(runes[1:4])))
	})
	t.Run("stack boundary", func(t *testing.T) {
		for _, n := range []int{32, 33} {
			value := taintString(t, strings.Repeat("a", n))
			require.True(t, stackS2R(value).tainted, "%d runes", n)
		}
	})
	t.Run("large", func(t *testing.T) {
		const n = 100_000
		value := taintStringRange(t, strings.Repeat("é", n), 2*n-4, 2*n)
		runes := heapS2R(value)
		require.Equal(t, []span{{4 * (n - 2), 4 * n}}, runeSpans(runes))
		require.Equal(t, []span{{2*n - 4, 2 * n}}, stringSpans(heapR2S(runes)))
	})
}

// TestStringToSliceSwitchOff checks the string-to-slice switch: when it is
// off, []byte(s) and []rune(s) do not enter the hooks and stay on the stack,
// and string(b) and concatenation still propagate.
func TestStringToSliceSwitchOff(t *testing.T) {
	requireWoven(t)
	short := taintString(t, "short-value")
	long := taintString(t, strings.Repeat("z", 40))
	previous := setStringToSlice(false)
	t.Cleanup(func() { setStringToSlice(previous) })

	before := entries()
	b := heapS2B(long)
	r := heapS2R(long)
	p1 := stackS2B(short)
	p2 := stackS2R(short)
	require.Equal(t, before, entries(), "the switch is off: no wrapper call")
	require.Empty(t, bytesSpans(b))
	require.Empty(t, runeSpans(r))
	require.Equal(t, probe{}, p1)
	require.Equal(t, probe{}, p2)
	require.Zero(t, testing.AllocsPerRun(100, func() { sinkInt = stackS2BLen(short) + stackS2RLen(short) }))

	require.NotEmpty(t, stringSpans(heapConcat2("x", long)))
	data := taintBytes(t, strings.Repeat("q", 40))
	require.NotEmpty(t, stringSpans(heapB2S(data)))

	setStringToSlice(true)
	require.Equal(t, []span{{0, 40}}, bytesSpans(heapS2B(long)), "the switch is on again")
}

// TestNoPointerArithmeticOnStack checks that the hooks accept operands on the
// stack (a stack tmpBuf of an earlier operation): they are never tainted.
func TestNoPointerArithmeticOnStack(t *testing.T) {
	requireWoven(t)
	value := taintString(t, "tnt")
	var buf [16]byte
	copy(buf[:], "stack-bytes")
	local := unsafe.String(&buf[0], 11)
	got := heapConcat3(local, value, local)
	require.Equal(t, "stack-bytestntstack-bytes", got)
	require.Equal(t, []span{{11, 14}}, stringSpans(got))
}
