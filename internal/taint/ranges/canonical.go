// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges

// Canonicalize validates raw ranges and writes a canonical set to dst.
//
// Overlap precedence follows raw input order: bytes already claimed by an
// earlier input range are removed from every later range. The surviving ranges
// are then sorted by byte offset, adjacent equal-provenance ranges are merged,
// and ranges after the effective output limit are dropped. Input work is
// bounded by MaxCanonicalInput. dst may alias storage used by raw.
func Canonicalize(dst *Set, limit Limit, raw []Range, valueLen uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	limit = normalizedLimit(limit)
	if len(raw) > MaxCanonicalInput {
		reset(dst, limit)
		return Outcome{}
	}

	// Validate the complete input before computing or publishing any result.
	for _, r := range raw {
		end, ok := checkedEnd(r)
		if !ok || end > valueLen || !validMarks(r.Marks) {
			reset(dst, limit)
			return Outcome{}
		}
	}

	// accepted remains sorted and non-overlapping. For each candidate, subtract
	// the accepted union in one pass, then merge its sorted surviving fragments
	// back into accepted. This is O(n²), including adversarial overlaps.
	var first [maxCanonicalFragments]Range
	var second [maxCanonicalFragments]Range
	var fragments [maxCanonicalFragments]Range
	accepted := &first
	scratch := &second
	acceptedCount := 0
	for _, candidate := range raw {
		fragmentCount := subtractAccepted(fragments[:], candidate, accepted[:acceptedCount])
		if acceptedCount+fragmentCount > len(scratch) {
			reset(dst, limit)
			return Outcome{}
		}
		acceptedCount = mergeSorted(scratch[:], accepted[:acceptedCount], fragments[:fragmentCount])
		accepted, scratch = scratch, accepted
	}
	canonical := accepted[:acceptedCount]

	// Merge adjacent ranges only when their complete provenance is equal.
	mergedCount := 0
	for _, r := range canonical {
		if mergedCount > 0 {
			previous := &canonical[mergedCount-1]
			previousEnd, _ := checkedEnd(*previous)
			if previousEnd == r.Start && previous.SourceID == r.SourceID && previous.Marks == r.Marks {
				combined := uint64(previous.Length) + uint64(r.Length)
				if combined > uint64(^uint32(0)) {
					reset(dst, limit)
					return Outcome{}
				}
				previous.Length = uint32(combined)
				continue
			}
		}
		canonical[mergedCount] = r
		mergedCount++
	}

	var result Set
	result.limit = limit
	keep := mergedCount
	if keep > int(limit) {
		keep = int(limit)
	}
	copy(result.items[:keep], canonical[:keep])
	result.count = uint8(keep)
	*dst = result
	return Outcome{Valid: true, Truncated: mergedCount > keep}
}

func subtractAccepted(dst []Range, candidate Range, accepted []Range) int {
	candidateEnd, _ := checkedEnd(candidate)
	cursor := candidate.Start
	count := 0
	for _, blocker := range accepted {
		blockerEnd, _ := checkedEnd(blocker)
		if blockerEnd <= cursor {
			continue
		}
		if blocker.Start >= candidateEnd {
			break
		}
		if blocker.Start > cursor {
			dst[count] = candidate
			dst[count].Start = cursor
			dst[count].Length = min(blocker.Start, candidateEnd) - cursor
			count++
		}
		if blockerEnd > cursor {
			cursor = blockerEnd
		}
		if cursor >= candidateEnd {
			return count
		}
	}
	if cursor < candidateEnd {
		dst[count] = candidate
		dst[count].Start = cursor
		dst[count].Length = candidateEnd - cursor
		count++
	}
	return count
}

func mergeSorted(dst, left, right []Range) int {
	leftIndex, rightIndex, count := 0, 0, 0
	for leftIndex < len(left) && rightIndex < len(right) {
		if left[leftIndex].Start <= right[rightIndex].Start {
			dst[count] = left[leftIndex]
			leftIndex++
		} else {
			dst[count] = right[rightIndex]
			rightIndex++
		}
		count++
	}
	count += copy(dst[count:], left[leftIndex:])
	count += copy(dst[count:], right[rightIndex:])
	return count
}
