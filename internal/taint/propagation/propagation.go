// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package propagation implements bounded owner-separated range transforms and
// publication for named string and byte operations.
//
// It uses the process store fast gate ([request.ActiveStore]), then
// [store.Store.MayContain] and [store.Store.Lookup] with fixed
// [store.MaxSnapshotOwners] fanout. Source IDs remain owner-local because
// every publication revalidates the contributing owner through [store.Entry.Handle]
// and publishes ranges back into that same owner. TryLock behavior is inherited
// from the store; contention is a safe drop.
//
// Disabled, no-active, and untainted paths add no heap allocation. The only
// heap allocation on a tainted path is one exact-length clone for non-aliasing
// string outputs. Byte results are adopted as-is and are never replaced. Their
// audited caller must prove that each result starts at its allocation base and
// that its capacity describes the complete retained allocation. An interior
// byte slice must never be passed as a non-alias result.
package propagation

import (
	"strings"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

const (
	// maxWindows bounds the number of non-empty window outputs published per call.
	maxWindows = 32
	// maxInputs bounds the number of inputs inspected by coarse operations.
	maxInputs = 16
)

// stringAlias reports whether result is a non-empty substring window of input.
// Pointers are used only as comparison keys and are never converted back.
func stringAlias(input, result string) bool {
	if len(input) == 0 || len(result) == 0 {
		return false
	}
	base := uintptr(unsafe.Pointer(unsafe.StringData(input)))
	ptr := uintptr(unsafe.Pointer(unsafe.StringData(result)))
	end := ptr + uintptr(len(result))
	return ptr >= base && end <= base+uintptr(len(input)) && end >= ptr
}

// bytesAlias reports whether result is a non-empty subslice window of input.
func bytesAlias(input, result []byte) bool {
	if len(input) == 0 || len(result) == 0 {
		return false
	}
	base := uintptr(unsafe.Pointer(unsafe.SliceData(input)))
	ptr := uintptr(unsafe.Pointer(unsafe.SliceData(result)))
	end := ptr + uintptr(len(result))
	return ptr >= base && end <= base+uintptr(len(input)) && end >= ptr
}

// withinByteBounds reports whether result len and cap fit the byte root limits.
func withinByteBounds(result []byte) bool {
	return len(result) >= 2 && len(result) <= store.MaxRootBytes && cap(result) <= store.MaxRootBytes
}

// deriveStringWindows derives result into every live owner in snapshot. result
// must already be a window of a live root; derivation records the window only.
func deriveStringWindow(result string, snapshot *store.Snapshot, s *store.Store) {
	key, ok := store.StringKey(result)
	if !ok {
		return
	}
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		owner.Derive(key, entry.Root)
	}
}

// deriveBytesWindow derives result into every live owner in snapshot.
func deriveBytesWindow(result []byte, snapshot *store.Snapshot, s *store.Store) {
	key, ok := store.BytesKey(result)
	if !ok {
		return
	}
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		owner.Derive(key, entry.Root)
	}
}

// CopyString is the exact copy primitive for string operations. It derives when
// result aliases a safe input window, and otherwise clones result once to exact
// length on a tainted path and adopts that same clone independently for every
// contributing owner. It returns the managed clone when it clones, and result
// otherwise.
func CopyString(input, result string) string {
	if len(result) != len(input) || len(result) > store.MaxRootBytes {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	key, ok := store.StringKey(input)
	if !ok || !s.MayContain(key) {
		return result
	}
	return copyStringHit(s, key, input, result)
}

//go:noinline
func copyStringHit(s *store.Store, key store.Key, input, result string) string {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return result
	}
	if stringAlias(input, result) {
		deriveStringWindow(result, &snapshot, s)
		return result
	}
	if len(result) < 2 {
		return result
	}
	clone := strings.Clone(result)
	publishStringCopy(clone, uint32(len(input)), &snapshot, s)
	return clone
}

// publishStringCopy adopts clone for every live owner using each owner's input
// ranges sliced to the clone length. Every owner adopts the same clone.
func publishStringCopy(clone string, inputLen uint32, snapshot *store.Snapshot, s *store.Store) {
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		if !ranges.Slice(&resultSet, entry.Ranges.Limit(), &entry.Ranges, inputLen, 0, uint32(len(clone))).Valid {
			continue
		}
		owner.AdoptString(clone, &resultSet)
	}
}

// StringWindows derives at most maxWindows non-empty output windows of input
// into every live owner. Outputs that do not alias input are skipped. Empty
// outputs remain untainted.
func StringWindows(input string, outputs []string) {
	s := request.ActiveStore()
	if s == nil {
		return
	}
	key, ok := store.StringKey(input)
	if !ok || !s.MayContain(key) {
		return
	}
	stringWindowsHit(s, key, input, outputs)
}

//go:noinline
func stringWindowsHit(s *store.Store, key store.Key, input string, outputs []string) {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return
	}
	published := 0
	for outputIndex, output := range outputs {
		if outputIndex >= maxWindows {
			break
		}
		if len(output) == 0 || !stringAlias(input, output) {
			continue
		}
		deriveStringWindow(output, &snapshot, s)
		published++
		if published >= maxWindows {
			break
		}
	}
}

// RepeatString is the exact repeat primitive. It derives when count is one and
// result aliases input, and otherwise clones result once to exact length on a
// tainted path (isolating static backing such as strings.Repeat fast paths) and
// adopts that same clone for every owner using ranges.Repeat.
func RepeatString(input, result string, count int) string {
	if len(result) > store.MaxRootBytes {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	key, ok := store.StringKey(input)
	if !ok || !s.MayContain(key) {
		return result
	}
	return repeatStringHit(s, key, input, result, count)
}

//go:noinline
func repeatStringHit(s *store.Store, key store.Key, input, result string, count int) string {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return result
	}
	if count == 1 {
		if !stringAlias(input, result) {
			return result
		}
		deriveStringWindow(result, &snapshot, s)
		return result
	}
	if len(result) < 2 {
		return result
	}
	clone := strings.Clone(result)
	publishStringRepeat(clone, uint32(len(input)), count, &snapshot, s)
	return clone
}

func publishStringRepeat(clone string, inputLen uint32, count int, snapshot *store.Snapshot, s *store.Store) {
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		if !ranges.Repeat(&resultSet, entry.Ranges.Limit(), &entry.Ranges, inputLen, count).Valid {
			continue
		}
		if !resultSet.ValidFor(uint32(len(clone))) {
			continue
		}
		owner.AdoptString(clone, &resultSet)
	}
}

// CoarseString is the coarse string primitive. It inspects at most maxInputs
// inputs and publishes one whole-output range per owner using ranges.Coarse
// semantics: the source is the first contributing range in input order and
// marks are intersected across every contributing range. It clones result once
// to exact length on a tainted path and adopts that same clone for every owner.
func CoarseString(result string, inputs ...string) string {
	if len(result) < 2 || len(result) > store.MaxRootBytes || len(inputs) == 0 {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	return coarseStringHit(s, result, inputs)
}

//go:noinline
func coarseStringHit(s *store.Store, result string, inputs []string) string {
	var owners [store.MaxSnapshotOwners]coarseOwner
	ownerCount := 0
	inspected := len(inputs)
	if inspected > maxInputs {
		inspected = maxInputs
	}
	for i := 0; i < inspected; i++ {
		input := inputs[i]
		key, ok := store.StringKey(input)
		if !ok || !s.MayContain(key) {
			continue
		}
		var snapshot store.Snapshot
		if !s.Lookup(key, &snapshot) {
			continue
		}
		for j := 0; j < snapshot.Len(); j++ {
			entry, ok := snapshot.At(j)
			if !ok {
				continue
			}
			owner := coarseMatch(owners[:ownerCount], entry)
			if owner == nil {
				if ownerCount >= len(owners) {
					continue
				}
				owners[ownerCount].entry = *entry
				owner = &owners[ownerCount]
				ownerCount++
			}
			coarseAccumulate(owner, &entry.Ranges)
		}
	}
	if ownerCount == 0 {
		return result
	}
	clone := strings.Clone(result)
	for i := 0; i < ownerCount; i++ {
		o := &owners[i]
		if !o.found {
			continue
		}
		owner, ok := o.entry.Handle(s)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		var coarseRange [1]ranges.Range
		coarseRange[0] = ranges.Range{Length: uint32(len(clone)), SourceID: o.source, Marks: o.marks}
		if !ranges.AdoptCanonical(&resultSet, ranges.DefaultLimit, coarseRange[:], uint32(len(clone))).Valid {
			continue
		}
		owner.AdoptString(clone, &resultSet)
	}
	return clone
}

// CopyBytes is the exact equal-length copy primitive for byte operations. It
// derives when result aliases a safe input window. Otherwise, the audited
// caller must prove that result starts at its allocation base and its capacity
// describes the complete retained allocation. CopyBytes adopts that result as
// is, with its visible capacity charged, and never replaces it.
func CopyBytes(input, result []byte) []byte {
	if len(result) != len(input) {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	key, ok := store.BytesKey(input)
	if !ok || !s.MayContain(key) {
		return result
	}
	return copyBytesHit(s, key, input, result)
}

//go:noinline
func copyBytesHit(s *store.Store, key store.Key, input, result []byte) []byte {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return result
	}
	if bytesAlias(input, result) {
		deriveBytesWindow(result, &snapshot, s)
		return result
	}
	if !withinByteBounds(result) {
		return result
	}
	publishBytesCopy(result, uint32(len(input)), &snapshot, s)
	return result
}

func publishBytesCopy(result []byte, inputLen uint32, snapshot *store.Snapshot, s *store.Store) {
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		if !ranges.Slice(&resultSet, entry.Ranges.Limit(), &entry.Ranges, inputLen, 0, uint32(len(result))).Valid {
			continue
		}
		owner.AdoptBytes(result, &resultSet)
	}
}

// ByteWindows derives at most maxWindows non-empty output windows of input
// into every live owner. Outputs that do not alias input are skipped.
func ByteWindows(input []byte, outputs [][]byte) {
	s := request.ActiveStore()
	if s == nil {
		return
	}
	key, ok := store.BytesKey(input)
	if !ok || !s.MayContain(key) {
		return
	}
	byteWindowsHit(s, key, input, outputs)
}

//go:noinline
func byteWindowsHit(s *store.Store, key store.Key, input []byte, outputs [][]byte) {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return
	}
	published := 0
	for outputIndex, output := range outputs {
		if outputIndex >= maxWindows {
			break
		}
		if len(output) == 0 || !bytesAlias(input, output) {
			continue
		}
		deriveBytesWindow(output, &snapshot, s)
		published++
		if published >= maxWindows {
			break
		}
	}
}

// RepeatBytes is the exact repeat primitive for byte operations. It derives when
// count is one and result aliases input. Otherwise, its audited caller must
// prove that result starts at its allocation base and its capacity describes
// the complete retained allocation. RepeatBytes adopts that result as-is using
// ranges.Repeat and never replaces it.
func RepeatBytes(input, result []byte, count int) []byte {
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	key, ok := store.BytesKey(input)
	if !ok || !s.MayContain(key) {
		return result
	}
	return repeatBytesHit(s, key, input, result, count)
}

//go:noinline
func repeatBytesHit(s *store.Store, key store.Key, input, result []byte, count int) []byte {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return result
	}
	if count == 1 {
		if !bytesAlias(input, result) {
			return result
		}
		deriveBytesWindow(result, &snapshot, s)
		return result
	}
	if !withinByteBounds(result) {
		return result
	}
	publishBytesRepeat(result, uint32(len(input)), count, &snapshot, s)
	return result
}

func publishBytesRepeat(result []byte, inputLen uint32, count int, snapshot *store.Snapshot, s *store.Store) {
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		if !ranges.Repeat(&resultSet, entry.Ranges.Limit(), &entry.Ranges, inputLen, count).Valid {
			continue
		}
		if !resultSet.ValidFor(uint32(cap(result))) {
			continue
		}
		owner.AdoptBytes(result, &resultSet)
	}
}

// CoarseBytes is the coarse byte primitive. It inspects at most maxInputs
// inputs and publishes one whole-output range per owner using ranges.Coarse
// semantics. Its audited caller must prove that result starts at its allocation
// base and its capacity describes the complete retained allocation. CoarseBytes
// adopts that result as-is and never replaces it.
func CoarseBytes(result []byte, inputs ...[]byte) []byte {
	s := request.ActiveStore()
	if s == nil || len(inputs) == 0 {
		return result
	}
	if coarseBytesAlias(s, result, inputs) || !withinByteBounds(result) {
		return result
	}
	return coarseBytesHit(s, result, inputs)
}

//go:noinline
func coarseBytesAlias(s *store.Store, result []byte, inputs [][]byte) bool {
	aliased := false
	inspected := min(len(inputs), maxInputs)
	for i := 0; i < inspected; i++ {
		input := inputs[i]
		if !bytesAlias(input, result) {
			continue
		}
		aliased = true
		key, ok := store.BytesKey(input)
		if !ok || !s.MayContain(key) {
			continue
		}
		var snapshot store.Snapshot
		if s.Lookup(key, &snapshot) && snapshot.Len() > 0 {
			deriveBytesWindow(result, &snapshot, s)
		}
	}
	return aliased
}

//go:noinline
func coarseBytesHit(s *store.Store, result []byte, inputs [][]byte) []byte {
	var owners [store.MaxSnapshotOwners]coarseOwner
	ownerCount := 0
	inspected := len(inputs)
	if inspected > maxInputs {
		inspected = maxInputs
	}
	for i := 0; i < inspected; i++ {
		input := inputs[i]
		key, ok := store.BytesKey(input)
		if !ok || !s.MayContain(key) {
			continue
		}
		var snapshot store.Snapshot
		if !s.Lookup(key, &snapshot) {
			continue
		}
		for j := 0; j < snapshot.Len(); j++ {
			entry, ok := snapshot.At(j)
			if !ok {
				continue
			}
			owner := coarseMatch(owners[:ownerCount], entry)
			if owner == nil {
				if ownerCount >= len(owners) {
					continue
				}
				owners[ownerCount].entry = *entry
				owner = &owners[ownerCount]
				ownerCount++
			}
			coarseAccumulate(owner, &entry.Ranges)
		}
	}
	if ownerCount == 0 {
		return result
	}
	for i := 0; i < ownerCount; i++ {
		o := &owners[i]
		if !o.found {
			continue
		}
		owner, ok := o.entry.Handle(s)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		var coarseRange [1]ranges.Range
		coarseRange[0] = ranges.Range{Length: uint32(len(result)), SourceID: o.source, Marks: o.marks}
		if !ranges.AdoptCanonical(&resultSet, ranges.DefaultLimit, coarseRange[:], uint32(cap(result))).Valid {
			continue
		}
		owner.AdoptBytes(result, &resultSet)
	}
	return result
}

// coarseOwner accumulates ranges.Coarse state for one owner. The entry is the
// first entry seen for the owner and is used only to revalidate it at adoption.
type coarseOwner struct {
	entry  store.Entry
	found  bool
	source ranges.SourceID
	marks  uint64
}

func coarseMatch(owners []coarseOwner, entry *store.Entry) *coarseOwner {
	for i := range owners {
		o := &owners[i]
		if o.entry.OwnerIndex == entry.OwnerIndex && o.entry.OwnerGen == entry.OwnerGen && o.entry.OwnerID == entry.OwnerID {
			return o
		}
	}
	return nil
}

// coarseAccumulate applies ranges.Coarse semantics: the first contributing range
// supplies the source and every contributing range intersects the marks.
func coarseAccumulate(o *coarseOwner, set *ranges.Set) {
	for i := 0; i < set.Len(); i++ {
		r, ok := set.At(i)
		if !ok {
			continue
		}
		if !o.found {
			o.source = r.SourceID
			o.marks = r.Marks
			o.found = true
		} else {
			o.marks &= r.Marks
		}
	}
}
