// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtimebridge

import "unsafe"

// This file has the functions that the woven runtime calls (plan sections
// 2.2, 3.2.1, 4.2, 4.3 and 4.5). Each one has a push //go:linkname to a
// linker symbol with the prefix "__dd_iast_rt.". The runtime pulls them with
// body-less //go:noescape declarations, and it sets its per-g guard before
// each call (plan section 3.4.1).
//
// Pre-checks ("pre") run before the runtime function, only when the result
// can go to a stack buffer. A true result makes the runtime put the result on
// the heap, so the result function can adopt it. A pre-check returns true only
// for a confirmed taint, for an unknown result (contention), or after a
// recovered panic. It never returns false for a tainted value.
//
// Result functions run after the runtime function, only when the result is
// not on the stack.

// maxLength is the largest value length that the store can key.
const maxLength = uint64(^uint32(0))

func length32(n int) (uint32, bool) {
	if n <= 0 || uint64(n) > maxLength {
		return 0, false
	}
	return uint32(n), true
}

//go:linkname concatPre __dd_iast_rt.concat_pre
func concatPre(a []string) bool {
	enter()
	b := binding.Load()
	if b == nil {
		return false
	}
	for i := range a {
		s := a[i]
		if len(s) != 0 && FilterHit(b.Filter, stringPointer(s)) {
			return confirmStrings(b, a[i:])
		}
	}
	return false
}

//go:linkname bytesPre __dd_iast_rt.bytes_pre
func bytesPre(ptr *byte, n int) bool {
	enter()
	return preOne(uintptr(unsafe.Pointer(ptr)), n)
}

//go:linkname strPre __dd_iast_rt.str_pre
func strPre(s string) bool {
	enter()
	if !StringToSliceEnabled() {
		return false
	}
	return preOne(stringPointer(s), len(s))
}

//go:linkname runesPre __dd_iast_rt.runes_pre
func runesPre(a []rune) bool {
	enter()
	if uint64(len(a)) > maxLength/4 {
		return false
	}
	return preOne(uintptr(unsafe.Pointer(unsafe.SliceData(a))), 4*len(a))
}

func preOne(p uintptr, n int) bool {
	b := binding.Load()
	if b == nil || p == 0 || n <= 0 || !FilterHit(b.Filter, p) {
		return false
	}
	return confirmOne(b, p, n)
}

// confirmStrings confirms the operands of a after the first filter hit. A
// recovered panic returns true: this costs at most one heap allocation, and
// it does not lose taint.
//
//go:noinline
func confirmStrings(b *Binding, a []string) (hit bool) {
	defer func() {
		if recover() != nil {
			hookPanic.Add(1)
			hit = true
		}
	}()
	for _, s := range a {
		n, ok := length32(len(s))
		if !ok {
			continue
		}
		p := stringPointer(s)
		if FilterHit(b.Filter, p) && b.Confirm(p, n) != ConfirmClean {
			return true
		}
	}
	return false
}

// confirmOne confirms one value. See confirmStrings.
//
//go:noinline
func confirmOne(b *Binding, p uintptr, n int) (hit bool) {
	defer func() {
		if recover() != nil {
			hookPanic.Add(1)
			hit = true
		}
	}()
	length, ok := length32(n)
	if !ok {
		return false
	}
	return b.Confirm(p, length) != ConfirmClean
}

//go:linkname concatHook __dd_iast_rt.concat_hook
func concatHook(res string, a []string) {
	enter()
	c := callbacks.Load()
	if len(res) < 2 || c == nil || c.Concat == nil || !stringsHit(a) {
		return
	}
	concatSlow(c, res, a)
}

//go:linkname concatBytesHook __dd_iast_rt.concat_bytes_hook
func concatBytesHook(res []byte, a []string) {
	enter()
	c := callbacks.Load()
	if len(res) < 2 || c == nil || c.ConcatBytes == nil || !stringsHit(a) {
		return
	}
	concatBytesSlow(c, res, a)
}

//go:linkname fromBytesHook __dd_iast_rt.from_bytes
func fromBytesHook(res string, ptr *byte, n int) {
	enter()
	c := callbacks.Load()
	if len(res) < 2 || n <= 0 || c == nil || c.FromBytes == nil || !pointerHit(uintptr(unsafe.Pointer(ptr))) {
		return
	}
	fromBytesSlow(c, res, ptr, n)
}

//go:linkname toBytesHook __dd_iast_rt.to_bytes
func toBytesHook(res []byte, s string) {
	enter()
	c := callbacks.Load()
	if len(res) < 2 || len(s) == 0 || c == nil || c.ToBytes == nil || !StringToSliceEnabled() || !pointerHit(stringPointer(s)) {
		return
	}
	toBytesSlow(c, res, s)
}

//go:linkname fromRunesHook __dd_iast_rt.from_runes
func fromRunesHook(res string, a []rune) {
	enter()
	c := callbacks.Load()
	if len(res) < 2 || len(a) == 0 || c == nil || c.FromRunes == nil || !pointerHit(uintptr(unsafe.Pointer(unsafe.SliceData(a)))) {
		return
	}
	fromRunesSlow(c, res, a)
}

//go:linkname toRunesHook __dd_iast_rt.to_runes
func toRunesHook(res []rune, s string) {
	enter()
	c := callbacks.Load()
	if len(res) == 0 || len(s) == 0 || c == nil || c.ToRunes == nil || !StringToSliceEnabled() || !pointerHit(stringPointer(s)) {
		return
	}
	toRunesSlow(c, res, s)
}

// stringsHit reports whether the filter of the binding has a hit for one
// operand of a.
func stringsHit(a []string) bool {
	b := binding.Load()
	if b == nil {
		return false
	}
	for i := range a {
		s := a[i]
		if len(s) != 0 && FilterHit(b.Filter, stringPointer(s)) {
			return true
		}
	}
	return false
}

func pointerHit(p uintptr) bool {
	b := binding.Load()
	return b != nil && p != 0 && FilterHit(b.Filter, p)
}

//go:noinline
func concatSlow(c *Callbacks, res string, a []string) {
	defer recoverHook()
	c.Concat(res, a)
}

//go:noinline
func concatBytesSlow(c *Callbacks, res []byte, a []string) {
	defer recoverHook()
	c.ConcatBytes(res, a)
}

//go:noinline
func fromBytesSlow(c *Callbacks, res string, ptr *byte, n int) {
	defer recoverHook()
	c.FromBytes(res, unsafe.Slice(ptr, n))
}

//go:noinline
func toBytesSlow(c *Callbacks, res []byte, s string) {
	defer recoverHook()
	c.ToBytes(res, s)
}

//go:noinline
func fromRunesSlow(c *Callbacks, res string, a []rune) {
	defer recoverHook()
	c.FromRunes(res, a)
}

//go:noinline
func toRunesSlow(c *Callbacks, res []rune, s string) {
	defer recoverHook()
	c.ToRunes(res, s)
}

func recoverHook() {
	if recover() != nil {
		hookPanic.Add(1)
	}
}
