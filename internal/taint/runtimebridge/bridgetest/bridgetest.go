// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package bridgetest calls the runtime bridge the same way as the woven
// runtime: it pulls the bridge linker symbols with body-less //go:linkname
// and //go:noescape declarations (plan runtime-operator-hooks, section 2.2).
// Only tests import it. It does not set the runtime guard.
package bridgetest

import (
	"sync/atomic"
	_ "unsafe" // for go:linkname

	// The bridge must be in the build for the linker to find its symbols.
	_ "github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
)

//go:linkname gate __dd_iast_rt.gate
var gate uint32

//go:linkname s2sGate __dd_iast_rt.s2s_gate
var s2sGate uint32

// Gate returns the runtime gate word, with an atomic load as the runtime does.
func Gate() uint32 { return atomic.LoadUint32(&gate) }

// S2SGate returns the string-to-slice switch word.
func S2SGate() uint32 { return atomic.LoadUint32(&s2sGate) }

// SetS2SGate stores the string-to-slice switch word and returns the previous
// value. Only tests change this word after Bind.
func SetS2SGate(value uint32) uint32 { return atomic.SwapUint32(&s2sGate, value) }

// ConcatPre is __dd_iast_rt.concat_pre.
//
//go:linkname ConcatPre __dd_iast_rt.concat_pre
//go:noescape
func ConcatPre(a []string) bool

// ConcatHook is __dd_iast_rt.concat_hook.
//
//go:linkname ConcatHook __dd_iast_rt.concat_hook
//go:noescape
func ConcatHook(res string, a []string)

// ConcatBytesHook is __dd_iast_rt.concat_bytes_hook.
//
//go:linkname ConcatBytesHook __dd_iast_rt.concat_bytes_hook
//go:noescape
func ConcatBytesHook(res []byte, a []string)

// BytesPre is __dd_iast_rt.bytes_pre.
//
//go:linkname BytesPre __dd_iast_rt.bytes_pre
//go:noescape
func BytesPre(ptr *byte, n int) bool

// FromBytes is __dd_iast_rt.from_bytes.
//
//go:linkname FromBytes __dd_iast_rt.from_bytes
//go:noescape
func FromBytes(res string, ptr *byte, n int)

// StrPre is __dd_iast_rt.str_pre.
//
//go:linkname StrPre __dd_iast_rt.str_pre
//go:noescape
func StrPre(s string) bool

// ToBytes is __dd_iast_rt.to_bytes.
//
//go:linkname ToBytes __dd_iast_rt.to_bytes
//go:noescape
func ToBytes(res []byte, s string)

// RunesPre is __dd_iast_rt.runes_pre.
//
//go:linkname RunesPre __dd_iast_rt.runes_pre
//go:noescape
func RunesPre(a []rune) bool

// FromRunes is __dd_iast_rt.from_runes.
//
//go:linkname FromRunes __dd_iast_rt.from_runes
//go:noescape
func FromRunes(res string, a []rune)

// ToRunes is __dd_iast_rt.to_runes.
//
//go:linkname ToRunes __dd_iast_rt.to_runes
//go:noescape
func ToRunes(res []rune, s string)

// BytesToString calls the bridge as the woven slicebytetostring does after
// the conversion: FromBytes(result, &input[0], len(input)).
func BytesToString(result string, input []byte) {
	if len(input) != 0 {
		FromBytes(result, &input[0], len(input))
	}
}

// BytesPreOf calls BytesPre for input.
func BytesPreOf(input []byte) bool {
	if len(input) == 0 {
		return false
	}
	return BytesPre(&input[0], len(input))
}
