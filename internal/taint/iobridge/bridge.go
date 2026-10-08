// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package iobridge is the dependency-minimal bridge imported into io and bufio.
//
// This package must import only sync/atomic and unsafe. The io, bufio and
// net/http packages import it, thus it cannot import a package that imports
// them.
package iobridge

import (
	"sync/atomic"
	"unsafe"
)

// MaxBufferedReaderSize limits the buffer size of tracked bufio readers.
const MaxBufferedReaderSize = 4096

// Callbacks are the reader callbacks. The request package registers them
// during package initialization.
type Callbacks struct {
	// Propagate binds output to the owners of input. The binding is
	// exclusive only when input has one effectively exclusive owner.
	Propagate func(input, output any)
	// PropagateShared binds output to the owners of input. The binding is
	// never exclusive.
	PropagateShared func(input, output any)
	// PropagateJoin binds output to the owners of the first
	// min(count, MaxJoinInputs) items of inputs. count is the number of
	// inputs of output. The binding is exclusive only when count is 1 to
	// MaxJoinInputs, and all the inputs have the same effectively exclusive
	// owner.
	PropagateJoin func(inputs [MaxJoinInputs]any, count int, output any)
	// PropagateGuarded binds a retargetable wrapper output to the owner of
	// input. The binding is exclusive only when input has one effectively
	// exclusive owner and output gets a Read guard entry (see Guard).
	PropagateGuarded func(input, output any)
	// Retarget sets the retargeted bit of the owner with this token.
	Retarget func(index uint8, generation uint64)
	// Owner returns the exclusive owner token of input (ReadAllBegin).
	Owner func(input any) ReadToken
	// ReadAll revalidates token, and then adopts a complete io.ReadAll
	// result into the owner of token only (ReadAllEnd).
	ReadAll func(input any, data []byte, token ReadToken)
}

// ReadToken is the owner token that ReadAllBegin takes before the first read of
// io.ReadAll (rule (f) of the reader binding rules in the internal/taint/store
// package doc). Only the request package makes it and reads its fields: they
// are a copy of a store reader token. Store holds a pointer, thus a token needs
// no allocation. The zero value is not OK.
type ReadToken struct {
	Store      any
	Generation uint64
	Index      uint8
	Entry      uint8
	OK         bool
}

var registered atomic.Pointer[Callbacks]

// Register installs reader callbacks during package initialization. It does
// nothing when a callback is nil.
func Register(callbacks Callbacks) {
	if callbacks.Propagate == nil || callbacks.PropagateShared == nil || callbacks.PropagateJoin == nil ||
		callbacks.PropagateGuarded == nil || callbacks.Retarget == nil ||
		callbacks.Owner == nil || callbacks.ReadAll == nil {
		return
	}
	registered.Store(&callbacks)
}

// Propagate transfers reader ownership from input to output. The binding of
// output is exclusive only when input has one effectively exclusive owner.
// Use it only for a wrapper that user code cannot retarget.
func Propagate(input, output any) {
	callback := registered.Load()
	if callback != nil {
		callback.Propagate(input, output)
	}
}

// PropagateShared transfers reader ownership from input to output. The
// binding of output is never exclusive.
func PropagateShared(input, output any) {
	callback := registered.Load()
	if callback != nil {
		callback.PropagateShared(input, output)
	}
}

// MaxJoinInputs is the maximum number of inputs of an exclusive reader that
// reads from more than one input (for example io.MultiReader).
const MaxJoinInputs = 8

// PropagateJoin transfers reader ownership from the inputs of a reader that
// reads from more than one input (for example io.MultiReader) to output.
// inputs holds the first min(count, MaxJoinInputs) inputs, and count is the
// number of inputs of output. The binding of output is exclusive only when
// count is 1 to MaxJoinInputs, and all the inputs have the same effectively
// exclusive owner. The inputs are checked and bound in one call, thus no
// proof is kept between two calls.
func PropagateJoin(inputs [MaxJoinInputs]any, count int, output any) {
	callback := registered.Load()
	if callback != nil {
		callback.PropagateJoin(inputs, count, output)
	}
}

// PropagateGuarded transfers reader ownership from input to a wrapper output
// that user code can retarget. The binding of output is exclusive only when
// input has one effectively exclusive owner and output gets a Read guard
// entry. Each Read method of output must call CheckRead first.
func PropagateGuarded(input, output any) {
	callback := registered.Load()
	if callback != nil {
		callback.PropagateGuarded(input, output)
	}
}

// ReadAllBegin returns the exclusive owner token of input. The io.ReadAll
// aspect calls it before the first read. The token is OK only when a complete
// lookup finds exactly one owner of input, with an effectively exclusive
// binding.
func ReadAllBegin(input any) ReadToken {
	callback := registered.Load()
	if callback == nil {
		return ReadToken{}
	}
	return callback.Owner(input)
}

// ReadAllEnd adopts a complete io.ReadAll result into the owner of token,
// without changing its slice identity. The io.ReadAll aspect calls it after
// the reads. It returns at once when token is not OK. Else the callback
// adopts data only when the owner of input is still the exclusive owner of
// token (reader binding rule (f)).
func ReadAllEnd(token ReadToken, input any, data []byte) {
	if !token.OK {
		return
	}
	if callback := registered.Load(); callback != nil {
		callback.ReadAll(input, data, token)
	}
}

// eface is the layout of an empty interface value.
type eface struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}

// words returns the type word and the data word of value as comparison keys.
// It does not allocate, and it never converts the words back to pointers.
func words(value any) (typ, data uintptr) {
	header := (*eface)(unsafe.Pointer(&value))
	return uintptr(header.typ), uintptr(header.data)
}

// Same reports whether a and b have the same dynamic type and the same data
// word. For pointer values, this is the same type and the same address. It
// never uses == on the values, thus it cannot panic on an uncomparable type.
func Same(a, b any) bool {
	aType, aData := words(a)
	bType, bData := words(b)
	return aType == bType && aData == bData
}

// guardEntry is one Read guard (see the Read guard in the internal/taint/store
// package doc). It is immutable after publication. It keeps strong references
// to self and input, thus no other object can get their addresses while the
// entry exists.
type guardEntry struct {
	self       any    // the guarded wrapper
	input      any    // the proven input of the wrapper
	generation uint64 // the owner generation
	index      uint8  // the owner slot
}

const (
	guardSlots = 128
	guardProbe = 4
)

// guardCount is not less than the number of published entries. It is
// incremented before an entry is published and decremented after it is
// removed.
var guardCount atomic.Int32
var guards [guardSlots]atomic.Pointer[guardEntry]

func guardStart(data uintptr) int { return int((data >> 4) % guardSlots) }

// CheckRead checks the target of a guarded wrapper before the wrapper reads
// from it. self is the wrapper and target is its current input. If self has
// a Read guard and target is not its proven input, CheckRead sets the
// retargeted bit of the owner, then removes the guard. If the callback that
// sets the bit fails, CheckRead sets the bit of RetargetLost first (fail
// closed). It is the only code
// on the Read path of the wrappers: when no guard exists, it is one atomic
// load and one branch. It checks all the probe slots, thus it also checks an
// entry of self that a concurrent Guard call adds and then removes.
func CheckRead(self, target any) {
	if guardCount.Load() != 0 {
		checkRead(self, target)
	}
}

func checkRead(self, target any) {
	_, data := words(self)
	if data == 0 {
		return
	}
	start := guardStart(data)
	for probe := 0; probe < guardProbe; probe++ {
		slot := &guards[(start+probe)%guardSlots]
		entry := slot.Load()
		if entry == nil || !Same(entry.self, self) || Same(entry.input, target) {
			continue
		}
		// Set the bit before a byte of the new target flows.
		retarget(entry.index, entry.generation)
		if slot.CompareAndSwap(entry, nil) {
			guardCount.Add(-1)
		}
	}
}

// retargetLost is true after a Retarget callback did not return normally (it
// panicked). Then the retargeted bit of its owner can be missing, and the
// wrapper could look exclusive with bytes of a new target. Fail closed: the bit
// is sticky for the life of the process, and while it is set, no guarded
// binding is effectively exclusive (RetargetLost, reader binding rule (a2)). It
// is set before CheckRead returns, thus before a byte of the new target flows.
var retargetLost atomic.Bool

// RetargetLost reports whether a Retarget callback failed. When it is true,
// the request package reports no guarded binding as effectively exclusive.
func RetargetLost() bool { return retargetLost.Load() }

// ResetRetargetLostForTest clears the bit of RetargetLost. Only tests call
// it.
func ResetRetargetLostForTest() { retargetLost.Store(false) }

//go:noinline
func retarget(index uint8, generation uint64) {
	done := false
	defer func() {
		_ = recover()
		if !done {
			retargetLost.Store(true)
		}
	}()
	if callback := registered.Load(); callback != nil {
		callback.Retarget(index, generation)
	}
	done = true
}

// Guard adds a Read guard for the wrapper self, with its proven input and the
// token of its owner. It returns false when self is not a pointer, when self
// already has a guard, or when the probe slots are full. Only the request
// package calls it, before it makes the exclusive binding of self.
//
// Invariant: when Guard returns true, no other entry of self exists and no
// other call adds one while this entry exists. After the insertion, Guard
// scans the probe slots again. If it finds another entry of self, it removes
// its own entry and returns false. The atomic operations are sequentially
// consistent, thus of two concurrent calls for the same self, at least one
// sees the entry of the other. Both calls can return false (a safe miss).
func Guard(self, input any, index uint8, generation uint64) bool {
	_, data := words(self)
	if data == 0 {
		return false
	}
	start := guardStart(data)
	if guardOf(self, start, nil) {
		return false
	}
	if hook := guardHookForTest.Load(); hook != nil {
		(*hook)()
	}
	entry := &guardEntry{self: self, input: input, generation: generation, index: index}
	guardCount.Add(1)
	for probe := 0; probe < guardProbe; probe++ {
		slot := &guards[(start+probe)%guardSlots]
		if !slot.CompareAndSwap(nil, entry) {
			continue
		}
		if !guardOf(self, start, entry) {
			return true
		}
		// A concurrent call added an entry of self too.
		if slot.CompareAndSwap(entry, nil) {
			guardCount.Add(-1)
		}
		return false
	}
	guardCount.Add(-1)
	return false
}

// guardHookForTest runs in Guard after the first duplicate check and before
// the insertion. Only tests set it.
var guardHookForTest atomic.Pointer[func()]

// SetGuardHookForTest makes each Guard call run hook after its first
// duplicate check and before its insertion, until restore is called. Only
// tests call it.
func SetGuardHookForTest(hook func()) (restore func()) {
	guardHookForTest.Store(&hook)
	return func() { guardHookForTest.Store(nil) }
}

// guardOf reports whether a probe slot from start has an entry of self that
// is not except.
func guardOf(self any, start int, except *guardEntry) bool {
	for probe := 0; probe < guardProbe; probe++ {
		if entry := guards[(start+probe)%guardSlots].Load(); entry != nil && entry != except && Same(entry.self, self) {
			return true
		}
	}
	return false
}

// Unguard removes the Read guard of self, if it exists.
func Unguard(self any) {
	_, data := words(self)
	if data == 0 {
		return
	}
	start := guardStart(data)
	for probe := 0; probe < guardProbe; probe++ {
		slot := &guards[(start+probe)%guardSlots]
		if entry := slot.Load(); entry != nil && Same(entry.self, self) && slot.CompareAndSwap(entry, nil) {
			guardCount.Add(-1)
		}
	}
}

// ReleaseOwner removes all the Read guards of the owner with this token. The
// request package calls it after the owner stops being active.
func ReleaseOwner(index uint8, generation uint64) {
	if guardCount.Load() == 0 {
		return
	}
	for slot := range guards {
		entry := guards[slot].Load()
		if entry != nil && entry.index == index && entry.generation == generation && guards[slot].CompareAndSwap(entry, nil) {
			guardCount.Add(-1)
		}
	}
}

// GuardCountForTest returns the guard counter. Only tests call it.
func GuardCountForTest() int { return int(guardCount.Load()) }

// GuardEntriesForTest returns the number of slots of the guard table that
// have an entry. Only tests call it.
func GuardEntriesForTest() int {
	entries := 0
	for slot := range guards {
		if guards[slot].Load() != nil {
			entries++
		}
	}
	return entries
}

// GuardEntriesOfForTest returns the number of entries of the wrapper self.
// Only tests call it.
func GuardEntriesOfForTest(self any) int {
	entries := 0
	for slot := range guards {
		if entry := guards[slot].Load(); entry != nil && Same(entry.self, self) {
			entries++
		}
	}
	return entries
}
