// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"strings"
	"unicode/utf8"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

const maxReplaceMatches = 32

// JoinString propagates strings.Join ranges. It inspects at most sixteen
// elements. A larger join uses coarse provenance from that bounded prefix.
func JoinString(elements []string, separator, result string) string {
	if len(result) == 0 || len(result) > store.MaxRootBytes {
		return result
	}
	if len(elements) == 1 && stringAlias(elements[0], result) {
		StringWindow(elements[0], result)
		return result
	}
	s := request.ActiveStore()
	if s == nil || !mayContainJoinedString(s, elements, separator) {
		return result
	}
	return joinStringHit(s, elements, separator, result)
}

//go:noinline
func joinStringHit(s *store.Store, elements []string, separator, result string) string {
	var inputs [maxInputs + 1]string
	inputCount := min(len(elements), maxInputs)
	if len(elements) > maxInputs {
		inputCount = maxInputs - 1 // Reserve one coarse-input slot for separator provenance.
	}
	copy(inputs[:inputCount], elements[:inputCount])
	inputs[inputCount] = separator
	var owners [store.MaxSnapshotOwners]store.Entry
	ownerCount := collectStringOwners(s, inputs[:inputCount+1], &owners)
	if ownerCount == 0 || len(result) < 2 {
		return result
	}
	if len(elements) > maxInputs {
		recordDropped()
		return coarseStringHit(s, result, inputs[:inputCount+1])
	}

	recordExecuted()
	clone := strings.Clone(result)
	for ownerIndex := 0; ownerIndex < ownerCount; ownerIndex++ {
		entry := &owners[ownerIndex]
		limit := entry.Ranges.Limit()
		var current ranges.Set
		var currentLen uint32
		var separatorSet ranges.Set
		separatorRanges := stringOwnerRanges(s, separator, entry, &separatorSet)
		valid := true
		for elementIndex, element := range elements {
			var elementSet ranges.Set
			elementRanges := stringOwnerRanges(s, element, entry, &elementSet)
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
		if !valid || currentLen != uint32(len(clone)) || current.Len() == 0 {
			continue
		}
		owner, ok := entry.Handle(s)
		if ok {
			owner.AdoptString(clone, &current)
		}
	}
	return clone
}

// ReplaceString propagates strings.Replace and strings.ReplaceAll. Copied and
// replacement segments are exact for at most thirty-two matches. Larger
// replacements use coarse provenance from the input and replacement value.
func ReplaceString(input, old, replacement, result string, count int) string {
	if len(result) == 0 || len(result) > store.MaxRootBytes {
		return result
	}
	if stringAlias(input, result) {
		StringWindow(input, result)
		return result
	}
	s := request.ActiveStore()
	if s == nil || !mayContainString(s, input) && !mayContainString(s, replacement) {
		return result
	}
	return replaceStringHit(s, input, old, replacement, result, count)
}

type replaceSegment struct {
	low         uint32
	high        uint32
	replacement bool
}

//go:noinline
func replaceStringHit(s *store.Store, input, old, replacement, result string, count int) string {
	var owners [store.MaxSnapshotOwners]store.Entry
	ownerCount := collectStringOwners(s, []string{input, replacement}, &owners)
	if ownerCount == 0 || len(result) < 2 {
		return result
	}
	if uint64(len(input)) > uint64(^uint32(0)) {
		recordDropped()
		return coarseStringHit(s, result, []string{input, replacement})
	}
	segments, segmentCount, exact := mapReplaceSegments(input, old, count)
	if !exact {
		recordDropped()
		return coarseStringHit(s, result, []string{input, replacement})
	}
	recordExecuted()
	clone := strings.Clone(result)
	for ownerIndex := 0; ownerIndex < ownerCount; ownerIndex++ {
		entry := &owners[ownerIndex]
		var inputSet, replacementSet ranges.Set
		inputRanges := stringOwnerRanges(s, input, entry, &inputSet)
		replacementRanges := stringOwnerRanges(s, replacement, entry, &replacementSet)
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
		if total != uint32(len(clone)) {
			continue
		}
		var resultSet ranges.Set
		outcome := ranges.Compose(&resultSet, entry.Ranges.Limit(), mapped[:segmentCount])
		if !outcome.Valid || !resultSet.ValidFor(uint32(len(clone))) || resultSet.Len() == 0 {
			continue
		}
		owner, ok := entry.Handle(s)
		if ok {
			owner.AdoptString(clone, &resultSet)
		}
	}
	return clone
}

func mapReplaceSegments(input, old string, count int) ([2*maxReplaceMatches + 1]replaceSegment, int, bool) {
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
	if old == "" {
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
			_, width := utf8.DecodeRuneInString(input[position:])
			if width == 0 {
				width = 1
			}
			position += width
		}
	} else {
		for remaining != 0 {
			relative := strings.Index(input[last:], old)
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

func collectStringOwners(s *store.Store, inputs []string, owners *[store.MaxSnapshotOwners]store.Entry) int {
	ownerCount := 0
	for _, input := range inputs {
		key, ok := store.StringKey(input)
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

func mayContainJoinedString(s *store.Store, elements []string, separator string) bool {
	inspected := min(len(elements), maxInputs)
	for index := 0; index < inspected; index++ {
		if mayContainString(s, elements[index]) {
			return true
		}
	}
	return mayContainString(s, separator)
}

func mayContainString(s *store.Store, value string) bool {
	key, ok := store.StringKey(value)
	return ok && s.MayContain(key)
}

func matchingOwner(owners []store.Entry, entry *store.Entry) bool {
	for index := range owners {
		owner := &owners[index]
		if owner.OwnerIndex == entry.OwnerIndex && owner.OwnerGen == entry.OwnerGen && owner.OwnerID == entry.OwnerID {
			return true
		}
	}
	return false
}

//go:noinline
func stringOwnerRanges(s *store.Store, value string, owner *store.Entry, dst *ranges.Set) *ranges.Set {
	key, ok := store.StringKey(value)
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

func setPointer(set *ranges.Set) *ranges.Set {
	if set == nil || set.Len() == 0 {
		return nil
	}
	return set
}
