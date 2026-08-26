// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"bytes"
	"unicode/utf8"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// JoinBytes propagates bytes.Join ranges. It inspects at most sixteen elements.
// A larger join uses coarse provenance from that bounded prefix.
//
// bytes.Join always returns a fresh allocation: a single element is copied, and
// a multi-element result is built in a new backing array. The audited caller
// must therefore prove that result starts at its allocation base and that its
// capacity describes the complete retained allocation. JoinBytes adopts that
// result as-is and never clones or replaces it.
func JoinBytes(elements [][]byte, separator, result []byte) []byte {
	if len(result) == 0 || !withinByteBounds(result) {
		return result
	}
	s := request.ActiveStore()
	if s == nil || !mayContainJoinedBytes(s, elements, separator) {
		return result
	}
	return joinBytesHit(s, elements, separator, result)
}

//go:noinline
func joinBytesHit(s *store.Store, elements [][]byte, separator, result []byte) []byte {
	var inputs [maxInputs + 1][]byte
	inputCount := min(len(elements), maxInputs)
	if len(elements) > maxInputs {
		inputCount = maxInputs - 1 // Reserve one coarse-input slot for separator provenance.
	}
	copy(inputs[:inputCount], elements[:inputCount])
	inputs[inputCount] = separator
	var owners [store.MaxSnapshotOwners]store.Entry
	ownerCount := collectBytesOwners(s, inputs[:inputCount+1], &owners)
	if ownerCount == 0 {
		return result
	}
	if len(elements) > maxInputs {
		recordDropped()
		return coarseBytesHit(s, result, inputs[:inputCount+1])
	}

	recordExecuted()
	for ownerIndex := 0; ownerIndex < ownerCount; ownerIndex++ {
		entry := &owners[ownerIndex]
		limit := entry.Ranges.Limit()
		var current ranges.Set
		var currentLen uint32
		var separatorSet ranges.Set
		separatorRanges := bytesOwnerRanges(s, separator, entry, &separatorSet)
		valid := true
		for elementIndex, element := range elements {
			var elementSet ranges.Set
			elementRanges := bytesOwnerRanges(s, element, entry, &elementSet)
			var next ranges.Set
			outcome := ranges.Concat(&next, limit, setPointer(&current), currentLen, elementRanges, uint32(len(element)))
			if !outcome.Valid {
				valid = false
				break
			}
			current = next
			currentLen += uint32(len(element))
			if elementIndex+1 < len(elements) {
				outcome = ranges.Concat(&next, limit, setPointer(&current), currentLen, separatorRanges, uint32(len(separator)))
				if !outcome.Valid {
					valid = false
					break
				}
				current = next
				currentLen += uint32(len(separator))
			}
		}
		// Partial fanout: a failed owner does not undo successful publications.
		if !valid || currentLen != uint32(len(result)) || current.Len() == 0 {
			continue
		}
		if !current.ValidFor(uint32(cap(result))) {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		owner.AdoptBytes(result, &current)
	}
	return result
}

// ReplaceBytes propagates bytes.Replace and bytes.ReplaceAll. Copied and
// replacement segments are exact for at most thirty-two matches, including
// empty-old and invalid-UTF-8 semantics that exactly match bytes.Replace. Larger
// replacements use coarse provenance from the input and replacement value.
//
// bytes.Replace always returns a fresh copy, even when the value is unchanged.
// The audited caller must prove that result starts at its allocation base and
// that its capacity describes the complete retained allocation. ReplaceBytes
// adopts that result as-is and never clones or replaces it.
func ReplaceBytes(input, old, replacement, result []byte, count int) []byte {
	if len(result) == 0 || !withinByteBounds(result) {
		return result
	}
	s := request.ActiveStore()
	if s == nil || !mayContainBytes(s, input) && !mayContainBytes(s, replacement) {
		return result
	}
	return replaceBytesHit(s, input, old, replacement, result, count)
}

//go:noinline
func replaceBytesHit(s *store.Store, input, old, replacement, result []byte, count int) []byte {
	var owners [store.MaxSnapshotOwners]store.Entry
	var coarseInputs [2][]byte
	coarseInputs[0] = input
	coarseInputs[1] = replacement
	ownerCount := collectBytesOwners(s, coarseInputs[:], &owners)
	if ownerCount == 0 {
		return result
	}
	if uint64(len(input)) > uint64(^uint32(0)) {
		recordDropped()
		return coarseBytesHit(s, result, coarseInputs[:])
	}
	segments, segmentCount, exact := mapReplaceByteSegments(input, old, count)
	if !exact {
		recordDropped()
		return coarseBytesHit(s, result, coarseInputs[:])
	}
	recordExecuted()
	for ownerIndex := 0; ownerIndex < ownerCount; ownerIndex++ {
		entry := &owners[ownerIndex]
		var inputSet, replacementSet ranges.Set
		inputRanges := bytesOwnerRanges(s, input, entry, &inputSet)
		replacementRanges := bytesOwnerRanges(s, replacement, entry, &replacementSet)
		var mapped [2*maxReplaceMatches + 1]ranges.Segment
		var total uint32
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex++ {
			segment := segments[segmentIndex]
			if segment.replacement {
				mapped[segmentIndex] = ranges.Segment{
					Part: ranges.Part{Ranges: replacementRanges, Length: uint32(len(replacement))},
					High: uint32(len(replacement)),
				}
				total += uint32(len(replacement))
			} else {
				mapped[segmentIndex] = ranges.Segment{
					Part: ranges.Part{Ranges: inputRanges, Length: uint32(len(input))},
					Low:  segment.low, High: segment.high,
				}
				total += segment.high - segment.low
			}
		}
		if total != uint32(len(result)) {
			continue
		}
		var resultSet ranges.Set
		outcome := ranges.Compose(&resultSet, entry.Ranges.Limit(), mapped[:segmentCount])
		if !outcome.Valid || resultSet.Len() == 0 {
			continue
		}
		if !resultSet.ValidFor(uint32(cap(result))) {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		owner.AdoptBytes(result, &resultSet)
	}
	return result
}

// mapReplaceByteSegments mirrors bytes.Replace segmentation for at most
// maxReplaceMatches matches. Empty old advances one UTF-8 rune at a time, with
// invalid UTF-8 treated as a single-byte rune, exactly like bytes.Replace. The
// boolean is false when the match count exceeds the exact bound.
func mapReplaceByteSegments(input, old []byte, count int) ([2*maxReplaceMatches + 1]replaceSegment, int, bool) {
	var segments [2*maxReplaceMatches + 1]replaceSegment
	if count == 0 {
		segments[0] = replaceSegment{high: uint32(len(input))}
		return segments, 1, true
	}
	remaining := count
	if remaining < 0 {
		remaining = maxReplaceMatches + 1
	}
	last := 0
	matches := 0
	if len(old) == 0 {
		for position := 0; remaining != 0; {
			if matches >= maxReplaceMatches {
				return segments, 0, false
			}
			segments[2*matches] = replaceSegment{low: uint32(last), high: uint32(position)}
			segments[2*matches+1] = replaceSegment{replacement: true}
			matches++
			remaining--
			last = position
			if position == len(input) {
				break
			}
			_, width := utf8.DecodeRune(input[position:])
			if width == 0 {
				width = 1
			}
			position += width
		}
	} else {
		for remaining != 0 {
			relative := bytes.Index(input[last:], old)
			if relative < 0 {
				break
			}
			if matches >= maxReplaceMatches {
				return segments, 0, false
			}
			position := last + relative
			segments[2*matches] = replaceSegment{low: uint32(last), high: uint32(position)}
			segments[2*matches+1] = replaceSegment{replacement: true}
			matches++
			remaining--
			last = position + len(old)
		}
	}
	segments[2*matches] = replaceSegment{low: uint32(last), high: uint32(len(input))}
	return segments, 2*matches + 1, true
}

// ValidUTF8Bytes propagates bytes.ToValidUTF8 copied and replacement segments.
// It maps at most thirty-two invalid runs exactly and uses coarse provenance
// beyond that bound. The audited caller must prove that result starts at its
// allocation base and that its capacity describes the complete allocation.
func ValidUTF8Bytes(input, replacement, result []byte) []byte {
	if len(result) == 0 || !withinByteBounds(result) {
		return result
	}
	s := request.ActiveStore()
	if s == nil || !mayContainBytes(s, input) && !mayContainBytes(s, replacement) {
		return result
	}
	return validUTF8BytesHit(s, input, replacement, result)
}

//go:noinline
func validUTF8BytesHit(s *store.Store, input, replacement, result []byte) []byte {
	var owners [store.MaxSnapshotOwners]store.Entry
	var coarseInputs [2][]byte
	coarseInputs[0], coarseInputs[1] = input, replacement
	ownerCount := collectBytesOwners(s, coarseInputs[:], &owners)
	if ownerCount == 0 {
		return result
	}
	if uint64(len(input)) > uint64(^uint32(0)) {
		recordDropped()
		return coarseBytesHit(s, result, coarseInputs[:])
	}
	segments, segmentCount, exact := mapValidUTF8Segments(input)
	if !exact {
		recordDropped()
		return coarseBytesHit(s, result, coarseInputs[:])
	}
	recordExecuted()
	for ownerIndex := 0; ownerIndex < ownerCount; ownerIndex++ {
		entry := &owners[ownerIndex]
		var inputSet, replacementSet ranges.Set
		inputRanges := bytesOwnerRanges(s, input, entry, &inputSet)
		replacementRanges := bytesOwnerRanges(s, replacement, entry, &replacementSet)
		var mapped [2*maxReplaceMatches + 1]ranges.Segment
		var total uint32
		for segmentIndex := 0; segmentIndex < segmentCount; segmentIndex++ {
			segment := segments[segmentIndex]
			if segment.replacement {
				mapped[segmentIndex] = ranges.Segment{
					Part: ranges.Part{Ranges: replacementRanges, Length: uint32(len(replacement))},
					High: uint32(len(replacement)),
				}
				total += uint32(len(replacement))
			} else {
				mapped[segmentIndex] = ranges.Segment{
					Part: ranges.Part{Ranges: inputRanges, Length: uint32(len(input))},
					Low:  segment.low, High: segment.high,
				}
				total += segment.high - segment.low
			}
		}
		if total != uint32(len(result)) {
			continue
		}
		var resultSet ranges.Set
		outcome := ranges.Compose(&resultSet, entry.Ranges.Limit(), mapped[:segmentCount])
		if !outcome.Valid || resultSet.Len() == 0 || !resultSet.ValidFor(uint32(cap(result))) {
			continue
		}
		owner, ok := entry.Handle(s)
		if ok {
			owner.AdoptBytes(result, &resultSet)
		}
	}
	return result
}

func mapValidUTF8Segments(input []byte) ([2*maxReplaceMatches + 1]replaceSegment, int, bool) {
	var segments [2*maxReplaceMatches + 1]replaceSegment
	segmentCount := 0
	copiedStart := 0
	for index := 0; index < len(input); {
		if input[index] < utf8.RuneSelf {
			index++
			continue
		}
		_, width := utf8.DecodeRune(input[index:])
		if width > 1 {
			index += width
			continue
		}
		if segmentCount+2 > len(segments)-1 {
			return segments, 0, false
		}
		segments[segmentCount] = replaceSegment{low: uint32(copiedStart), high: uint32(index)}
		segmentCount++
		segments[segmentCount] = replaceSegment{replacement: true}
		segmentCount++
		for index < len(input) {
			if input[index] < utf8.RuneSelf {
				break
			}
			_, width = utf8.DecodeRune(input[index:])
			if width > 1 {
				break
			}
			index++
		}
		copiedStart = index
	}
	segments[segmentCount] = replaceSegment{low: uint32(copiedStart), high: uint32(len(input))}
	return segments, segmentCount + 1, true
}

// CaseBytes propagates a Unicode case transform on bytes. An aliasing unchanged
// result derives exact input ranges. ASCII inputs with unchanged byte length
// keep exact positions. Other changed results use coarse ranges. The audited
// caller must prove that a non-alias result starts at its allocation base and
// that its capacity describes the complete retained allocation. CaseBytes adopts
// that result as-is and never clones or replaces it.
func CaseBytes(input, result []byte) []byte {
	if len(result) == 0 || !withinByteBounds(result) {
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
	return caseBytesHit(s, key, input, result)
}

//go:noinline
func caseBytesHit(s *store.Store, key store.Key, input, result []byte) []byte {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return result
	}
	recordExecuted()
	if bytesAlias(input, result) {
		deriveBytesWindow(result, &snapshot, s)
		return result
	}
	exact := len(input) == len(result) && asciiBytes(input)
	if !exact {
		recordCoarse()
	}
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, ok := snapshot.At(entryIndex)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		var outcome ranges.Outcome
		if exact {
			outcome = ranges.Copy(&resultSet, entry.Ranges.Limit(), &entry.Ranges, uint32(len(input)))
		} else {
			outcome = ranges.Coarse(&resultSet, entry.Ranges.Limit(), uint32(len(result)), []ranges.Part{{
				Ranges: &entry.Ranges, Length: uint32(len(input)),
			}})
		}
		if !outcome.Valid || resultSet.Len() == 0 {
			continue
		}
		if !resultSet.ValidFor(uint32(cap(result))) {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		owner.AdoptBytes(result, &resultSet)
	}
	return result
}

func asciiBytes(value []byte) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			return false
		}
	}
	return true
}

// collectBytesOwners gathers at most store.MaxSnapshotOwners distinct live owner
// entries contributing to inputs. The owners array is filled by pointer to keep
// the large ranges.Set values off the return stack.
func collectBytesOwners(s *store.Store, inputs [][]byte, owners *[store.MaxSnapshotOwners]store.Entry) int {
	ownerCount := 0
	for _, input := range inputs {
		key, ok := store.BytesKey(input)
		if !ok || !s.MayContain(key) {
			continue
		}
		var snapshot store.Snapshot
		if !s.Lookup(key, &snapshot) {
			continue
		}
		for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
			entry, ok := snapshot.At(entryIndex)
			if !ok || matchingOwner(owners[:ownerCount], entry) {
				continue
			}
			if ownerCount >= len(owners) {
				continue
			}
			owners[ownerCount] = *entry
			ownerCount++
		}
	}
	return ownerCount
}

//go:noinline
func bytesOwnerRanges(s *store.Store, value []byte, owner *store.Entry, dst *ranges.Set) *ranges.Set {
	key, ok := store.BytesKey(value)
	if !ok || !s.MayContain(key) {
		return nil
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return nil
	}
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, ok := snapshot.At(entryIndex)
		if !ok {
			continue
		}
		if entry.OwnerIndex == owner.OwnerIndex && entry.OwnerGen == owner.OwnerGen && entry.OwnerID == owner.OwnerID {
			*dst = entry.Ranges
			return dst
		}
	}
	return nil
}

func mayContainBytes(s *store.Store, value []byte) bool {
	key, ok := store.BytesKey(value)
	return ok && s.MayContain(key)
}

func mayContainJoinedBytes(s *store.Store, elements [][]byte, separator []byte) bool {
	inspected := min(len(elements), maxInputs)
	for index := 0; index < inspected; index++ {
		if mayContainBytes(s, elements[index]) {
			return true
		}
	}
	return mayContainBytes(s, separator)
}
