// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"unicode/utf8"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// Range mapping between a string and its []rune form (the callbacks of
// string(rs) and []rune(s) in runtime.go use it).
//
// A []rune value uses the byte coordinates of its rune array: rune i is bytes
// [4i, 4i+4). UTF-8 byte offsets are not rune indexes, so the mapping is not a
// shift. Both directions walk the value once, keep exact ranges on rune
// boundaries, and make a range that starts or ends inside a rune cover the
// complete rune. Thus they can over-taint by less than one rune at each end,
// and they never lose taint. They do not allocate.

// maxRuneBytes is the largest rune-array byte length that a uint32 range
// offset can describe.
const maxRuneBytes = uint64(^uint32(0))

// stringRangesToRunes maps src, the ranges of s in UTF-8 byte offsets, to the
// byte coordinates of the []rune form of s, which has runeCount runes. It
// decodes s as "for range s" does: an invalid byte is one utf8.RuneError of
// width 1. It returns false when src is not valid for s or when the result
// does not fit in runeCount runes.
func stringRangesToRunes(dst *ranges.Set, limit ranges.Limit, src *ranges.Set, s string, runeCount int) bool {
	if dst == nil || src == nil || runeCount < 0 || 4*uint64(runeCount) > maxRuneBytes || !src.ValidFor(uint32(min(uint64(len(s)), maxRuneBytes))) {
		return false
	}
	var mapped [ranges.HardLimit]ranges.Range
	count := 0
	offset, index := 0, 0 // the rune at byte offset has rune index index
	width := runeWidthAt(s, 0)
	for i := 0; i < src.Len(); i++ {
		r, ok := src.At(i)
		if !ok || r.Length == 0 {
			continue
		}
		start, last := int(r.Start), int(r.Start)+int(r.Length)-1
		if last >= len(s) {
			return false
		}
		// Ranges are sorted and do not overlap, so the cursor only moves
		// forward.
		for offset+width <= start {
			offset += width
			index++
			width = runeWidthAt(s, offset)
		}
		first := index
		for offset+width <= last {
			offset += width
			index++
			width = runeWidthAt(s, offset)
		}
		mapped[count] = ranges.Range{Start: uint32(4 * first), Length: uint32(4 * (index - first + 1)), SourceID: r.SourceID, Marks: r.Marks}
		count++
	}
	// Two ranges that end and start inside one rune map to overlapping
	// ranges. Canonicalize keeps the earlier range on the overlap.
	return ranges.Canonicalize(dst, limit, mapped[:count], uint32(4*runeCount)).Valid
}

// runeWidthAt returns the width of the rune at byte offset of s. It returns 1
// for an invalid byte, as "for range s" does, and 1 at the end of s.
func runeWidthAt(s string, offset int) int {
	if offset >= len(s) {
		return 1
	}
	if s[offset] < utf8.RuneSelf {
		return 1
	}
	_, width := utf8.DecodeRuneInString(s[offset:])
	return width
}

// runeRangesToString maps src, the ranges of runes in rune-array byte
// coordinates, to UTF-8 byte offsets of string(runes), which has resultLen
// bytes. A range [a, e) covers the runes [a/4, ceil(e/4)). Each rune has the
// width that the runtime encoder writes: utf8.RuneLen, and 3 for an invalid
// rune or a surrogate. The output is clipped to resultLen. It returns false
// when src is not valid for runes.
func runeRangesToString(dst *ranges.Set, limit ranges.Limit, src *ranges.Set, runes []rune, resultLen uint32) bool {
	if dst == nil || src == nil || 4*uint64(len(runes)) > maxRuneBytes || !src.ValidFor(uint32(4*len(runes))) {
		return false
	}
	var mapped [ranges.HardLimit]ranges.Range
	count := 0
	index, offset := 0, uint64(0) // offset is the output offset of rune index
	for i := 0; i < src.Len(); i++ {
		r, ok := src.At(i)
		if !ok || r.Length == 0 {
			continue
		}
		firstRune := int(r.Start / 4)
		endRune := int((uint64(r.Start) + uint64(r.Length) + 3) / 4)
		for index < firstRune {
			offset += uint64(encodedRuneWidth(runes[index]))
			index++
		}
		start := offset
		for index < endRune {
			offset += uint64(encodedRuneWidth(runes[index]))
			index++
		}
		end := min(offset, uint64(resultLen))
		if start >= end {
			continue
		}
		mapped[count] = ranges.Range{Start: uint32(start), Length: uint32(end - start), SourceID: r.SourceID, Marks: r.Marks}
		count++
	}
	return ranges.Canonicalize(dst, limit, mapped[:count], resultLen).Valid
}

// encodedRuneWidth returns the number of bytes that the runtime writes for r
// in string([]rune): utf8.RuneError (3 bytes) for an invalid rune or a
// surrogate.
func encodedRuneWidth(r rune) int {
	if width := utf8.RuneLen(r); width > 0 {
		return width
	}
	return 3
}
