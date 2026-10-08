// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges

import "github.com/DataDog/dd-iast-go/internal/model/constants"

// MarkBit returns the secure-mark bit for vulnerability and whether the
// vulnerability value is valid. Bit zero is never returned.
func MarkBit(vulnerability constants.VulnerabilityType) (uint64, bool) {
	if vulnerability == 0 || uint(vulnerability) > constants.VulnerabilityTypeCount || vulnerability >= 64 {
		return 0, false
	}
	return uint64(1) << vulnerability, true
}

// HasMark reports whether marks contains vulnerability's secure mark. Invalid
// vulnerability values are never considered marked.
func HasMark(marks uint64, vulnerability constants.VulnerabilityType) bool {
	bit, ok := MarkBit(vulnerability)
	return ok && marks&bit != 0
}

// MarkAll adds vulnerability's secure mark to every range in src.
func MarkAll(dst, src *Set, vulnerability constants.VulnerabilityType) Outcome {
	return markWhere(dst, src, vulnerability, 0, false)
}

// MarkSource adds vulnerability's secure mark only to ranges attributed to
// source. Source ID zero is valid.
func MarkSource(dst, src *Set, source SourceID, vulnerability constants.VulnerabilityType) Outcome {
	return markWhere(dst, src, vulnerability, source, true)
}

func markWhere(dst, src *Set, vulnerability constants.VulnerabilityType, source SourceID, filter bool) Outcome {
	if dst == nil {
		return Outcome{}
	}
	if src == nil {
		reset(dst, DefaultLimit)
		return Outcome{}
	}
	if !src.structurallyValid() {
		reset(dst, src.Limit())
		return Outcome{}
	}
	bit, ok := MarkBit(vulnerability)
	if !ok {
		reset(dst, src.Limit())
		return Outcome{}
	}
	var builder orderedBuilder
	builder.init(src.Limit())
	for i := 0; i < int(src.count); i++ {
		r := src.items[i]
		if !filter || r.SourceID == source {
			r.Marks |= bit
		}
		builder.append(r)
	}
	return builder.publish(dst)
}

// UnsafeFor keeps only ranges that are not marked safe for vulnerability. It
// preserves every other secure mark.
func UnsafeFor(dst, src *Set, vulnerability constants.VulnerabilityType) Outcome {
	if dst == nil {
		return Outcome{}
	}
	if src == nil {
		reset(dst, DefaultLimit)
		return Outcome{}
	}
	if !src.structurallyValid() {
		reset(dst, src.Limit())
		return Outcome{}
	}
	bit, ok := MarkBit(vulnerability)
	if !ok {
		reset(dst, src.Limit())
		return Outcome{}
	}
	var result Set
	result.limit = src.Limit()
	for i := 0; i < int(src.count); i++ {
		r := src.items[i]
		if r.Marks&bit == 0 {
			result.items[result.count] = r
			result.count++
		}
	}
	*dst = result
	return Outcome{Valid: true}
}
