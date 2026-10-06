// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"unicode/utf8"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
)

// The functions of this file are the analysis side of the propagation hooks
// (package propbridge). They run on the goroutine of the hook. They call no
// hooked function: no concatenation, no string conversion, no strings,
// bytes, fmt or strconv function that a hook changes (plan section 6.1 rule
// 4). They recover their panics: a hook calls them without a recover.

// derived is the propbridge Derived callback: for each owner that has a
// source in the input, it adds a derived entry for the output (plan section
// 4.3).
func (m *Manager) derived(out unsafe.Pointer, outLen uintptr, in unsafe.Pointer, inLen uintptr, mode uint8) {
	defer func() { _ = recover() }()
	if mode != propbridge.Positional || outLen != inLen {
		mode = propbridge.Coarse
	}
	m.deriveAll(out, outLen, in, inLen, func(r *Attribution, segs *[MaxDerivedSegments]segment) int {
		if mode == propbridge.Positional {
			return positionalSegments(r, segs)
		}
		return coarseSegments(r, outLen, segs)
	})
}

// runes is the propbridge Runes callback of the rune conversions of the
// runtime.
func (m *Manager) runes(out unsafe.Pointer, outLen uintptr, in unsafe.Pointer, inLen uintptr, kind uint8) {
	defer func() { _ = recover() }()
	if kind != propbridge.RunesFromString && kind != propbridge.StringFromRunes {
		return
	}
	input := unsafe.Slice((*byte)(in), inLen)
	m.deriveAll(out, outLen, in, inLen, func(r *Attribution, segs *[MaxDerivedSegments]segment) int {
		if count, ok := runeSegments(r, input, outLen, kind, segs); ok {
			return count
		}
		return coarseSegments(r, outLen, segs)
	})
}

// deriveAll attributes the input for each active owner (shared work
// budget), and adds the derived entry that build makes for each owner with
// a match.
func (m *Manager) deriveAll(out unsafe.Pointer, outLen uintptr, in unsafe.Pointer, inLen uintptr, build func(r *Attribution, segs *[MaxDerivedSegments]segment) int) {
	if !m.Active() || outLen == 0 || inLen == 0 || outLen > MaxValueBytes || !bitsAny(in, inLen) {
		return
	}
	var r Attribution
	w := newWork()
	m.forEachActive(func(s *slot, generation uint32, id uint64) bool {
		m.use(s, generation, id, func(d *ownerData) {
			r.Reset()
			d.attribute(in, inLen, matchAll, MaxAttributed, &w, &r)
			if r.Attributed == 0 {
				return
			}
			var segs [MaxDerivedSegments]segment
			if count := build(&r, &segs); count > 0 {
				d.addDerived(out, outLen, segs[:count])
			}
		})
		return w.checks > 0
	})
}

// attributedSegments calls f for each attributed segment of r, in order.
func attributedSegments(r *Attribution, f func(start, end int, id SourceID) bool) {
	for i := 0; i < r.N; i++ {
		s := r.Segments[i]
		if s.Foreign {
			continue
		}
		if !f(int(s.Start), int(s.Start+s.Length), r.ids[s.source]) {
			return
		}
	}
}

// coarseSegments: one segment over the whole output, with the first source
// of the owner in the input.
func coarseSegments(r *Attribution, outLen uintptr, segs *[MaxDerivedSegments]segment) int {
	count := 0
	attributedSegments(r, func(_, _ int, id SourceID) bool {
		segs[0] = segment{start: 0, length: uint32(outLen), source: id}
		count = 1
		return false
	})
	return count
}

// positionalSegments: byte i of the output comes from byte i of the input.
func positionalSegments(r *Attribution, segs *[MaxDerivedSegments]segment) int {
	count := 0
	attributedSegments(r, func(start, end int, id SourceID) bool {
		segs[count] = segment{start: uint32(start), length: uint32(end - start), source: id}
		count++
		return count < len(segs)
	})
	return count
}

// runeSegments maps the attributed segments of the input of a rune
// conversion to the output: a rune gets the source of the first attributed
// byte of its input bytes. It returns false when the output length does not
// match the input (then the caller uses the coarse rule).
func runeSegments(r *Attribution, input []byte, outLen uintptr, kind uint8, segs *[MaxDerivedSegments]segment) (int, bool) {
	count := 0
	cursor := 0 // first segment of r that can overlap the next input
	emit := func(outStart, outEnd int, id SourceID) {
		if count > 0 {
			last := &segs[count-1]
			if last.source == id && int(last.start+last.length) == outStart {
				last.length = uint32(outEnd) - last.start
				return
			}
		}
		if count < len(segs) {
			segs[count] = segment{start: uint32(outStart), length: uint32(outEnd - outStart), source: id}
			count++
		}
	}
	// sourceOf returns the source of the first attributed byte in
	// [start, end) of the input.
	sourceOf := func(start, end int) (SourceID, bool) {
		for cursor < r.N {
			s := r.Segments[cursor]
			if int(s.Start+s.Length) <= start {
				cursor++
				continue
			}
			break
		}
		for i := cursor; i < r.N; i++ {
			s := r.Segments[i]
			if int(s.Start) >= end {
				break
			}
			if !s.Foreign {
				return r.ids[s.source], true
			}
		}
		return 0, false
	}
	out := 0
	switch kind {
	case propbridge.RunesFromString:
		for b := 0; b < len(input); {
			_, width := utf8.DecodeRune(input[b:])
			if id, ok := sourceOf(b, b+width); ok {
				emit(out, out+4, id)
			}
			b += width
			out += 4
		}
	case propbridge.StringFromRunes:
		if len(input)%4 != 0 {
			return 0, false
		}
		for b := 0; b < len(input); b += 4 {
			value := *(*rune)(unsafe.Pointer(&input[b]))
			width := utf8.RuneLen(value)
			if width < 0 {
				width = utf8.RuneLen(utf8.RuneError)
			}
			if id, ok := sourceOf(b, b+4); ok {
				emit(out, out+width, id)
			}
			out += width
		}
	}
	if out != int(outLen) {
		return 0, false
	}
	return count, true
}
