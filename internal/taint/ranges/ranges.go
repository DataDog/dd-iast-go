// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package ranges provides bounded byte-range provenance algebra.
//
// It has no global state, instrumentation dependency, or unsafe operation.
// Functions drop invalid results instead of panicking. Copying a Set is correct
// but copies approximately 1.5 KiB; pass it by pointer on hot paths.
package ranges

import "github.com/DataDog/dd-iast-go/internal/model/constants"

const (
	// DefaultLimit matches the cross-language default maximum range count.
	DefaultLimit = 10
	// GuaranteedLimit is the number of ranges that the production store must
	// provide for every admitted value.
	GuaranteedLimit = 10
	// HardLimit is the largest configured range limit accepted by Go IAST.
	HardLimit = 64
	// MaxCanonicalInput bounds canonicalization work for composed operations.
	MaxCanonicalInput = 3 * HardLimit

	maxCanonicalFragments = 2*MaxCanonicalInput - 1
)

// This assignment fails to compile if the highest 1-based vulnerability bit
// cannot fit in a uint64.
const _ uint64 = 1 << constants.VulnerabilityTypeCount

// SourceID identifies a source in one request-local source table. Zero is a
// valid source identifier.
type SourceID uint16

// Limit is a normalized range-count limit in [1, HardLimit].
type Limit uint8

// ClampLimit clamps n to the supported range. Zero selects the minimum limit;
// callers that need the configured default must pass DefaultLimit explicitly.
func ClampLimit(n uint64) Limit {
	if n < 1 {
		return 1
	}
	if n > HardLimit {
		return HardLimit
	}
	return Limit(n)
}

// Range describes tainted bytes in [Start, Start+Length). Marks uses the
// 1-based numeric vulnerability type as its bit position; bit zero is unused.
type Range struct {
	Start    uint32
	Length   uint32
	SourceID SourceID
	Marks    uint64
}

// Outcome describes a range operation. Invalid operations publish an empty
// destination and return Valid=false. Truncated reports deterministic tail
// dropping at the effective range limit.
type Outcome struct {
	Valid     bool
	Truncated bool
}

// Set is a canonical, fixed-capacity transient algebra value. Its zero value is
// an empty set with DefaultLimit. Phase 2 stores compact inline/pool ranges, not
// one Set per value entry. Use read-only accessors; mutation is performed by
// package operations.
type Set struct {
	items [HardLimit]Range
	count uint8
	limit Limit
}

// AdoptCanonical validates and copies already-canonical compact storage in
// O(n). It avoids the larger scratch space needed to resolve arbitrary raw
// overlaps. Input longer than HardLimit is invalid. dst may alias input.
func AdoptCanonical(dst *Set, limit Limit, input []Range, valueLen uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	limit = normalizedLimit(limit)
	if len(input) > HardLimit || !validCanonicalSlice(input, valueLen) {
		reset(dst, limit)
		return Outcome{}
	}
	var result Set
	result.limit = limit
	keep := min(len(input), int(limit))
	copy(result.items[:keep], input[:keep])
	result.count = uint8(keep)
	*dst = result
	return Outcome{Valid: true, Truncated: len(input) > keep}
}

// Len returns the number of ranges. It returns zero for a nil receiver.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return int(s.count)
}

// Limit returns the set's effective limit. It returns DefaultLimit for a nil or
// zero-value receiver.
func (s *Set) Limit() Limit {
	if s == nil {
		return DefaultLimit
	}
	return normalizedLimit(s.limit)
}

// At returns the range at index i. It is nil-safe and never panics.
func (s *Set) At(i int) (Range, bool) {
	if s == nil || i < 0 || i >= int(s.count) {
		return Range{}, false
	}
	return s.items[i], true
}

// CopyTo copies ranges in output order to dst and returns the number copied.
// It does not allocate. A short destination receives a prefix.
func (s *Set) CopyTo(dst []Range) int {
	if s == nil {
		return 0
	}
	return copy(dst, s.items[:s.count])
}

// ValidFor reports whether the set satisfies all canonical invariants for a
// value of valueLen bytes.
func (s *Set) ValidFor(valueLen uint32) bool {
	if !s.structurallyValid() {
		return false
	}
	for i := 0; i < int(s.count); i++ {
		end, _ := checkedEnd(s.items[i])
		if end > valueLen {
			return false
		}
	}
	return true
}

func (s *Set) structurallyValid() bool {
	if s == nil || int(s.count) > HardLimit || int(s.count) > int(normalizedLimit(s.limit)) {
		return false
	}
	var previous Range
	var previousEnd uint32
	for i := 0; i < int(s.count); i++ {
		r := s.items[i]
		end, ok := checkedEnd(r)
		if !ok || !validMarks(r.Marks) {
			return false
		}
		if i > 0 {
			if r.Start < previousEnd {
				return false
			}
			if r.Start == previousEnd && r.SourceID == previous.SourceID && r.Marks == previous.Marks {
				return false
			}
		}
		previous = r
		previousEnd = end
	}
	return true
}

func normalizedLimit(limit Limit) Limit {
	if limit == 0 {
		return DefaultLimit
	}
	if limit > HardLimit {
		return HardLimit
	}
	return limit
}

func reset(dst *Set, limit Limit) {
	if dst == nil {
		return
	}
	*dst = Set{limit: normalizedLimit(limit)}
}

func validMarks(marks uint64) bool {
	if marks&1 != 0 {
		return false
	}
	if constants.VulnerabilityTypeCount == 63 {
		return true
	}
	return marks>>uint(constants.VulnerabilityTypeCount+1) == 0
}

func validCanonicalSlice(input []Range, valueLen uint32) bool {
	var previous Range
	var previousEnd uint32
	for i, r := range input {
		end, ok := checkedEnd(r)
		if !ok || end > valueLen || !validMarks(r.Marks) {
			return false
		}
		if i > 0 {
			if r.Start < previousEnd {
				return false
			}
			if r.Start == previousEnd && r.SourceID == previous.SourceID && r.Marks == previous.Marks {
				return false
			}
		}
		previous = r
		previousEnd = end
	}
	return true
}

func checkedEnd(r Range) (uint32, bool) {
	if r.Length == 0 {
		return 0, false
	}
	end := r.Start + r.Length
	if end < r.Start {
		return 0, false
	}
	return end, true
}
