// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package redaction converts report-owned taint snapshots to bounded wire
// sources and evidence parts without exposing sensitive source values.
package redaction

import (
	"strings"
	"unicode/utf8"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/model/truncation"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

const sourceComparisonBudget = 1 << 20

// Result contains event-local sources and value parts with local source
// indexes. It is suitable for a spans.TaintedCommit after vulnerability-
// specific sensitive intervals are applied.
type Result struct {
	Sources []spans.TaintedSource
	Parts   []model.ValuePart
}

// BuildSources converts a complete snapshot using configured source name/value
// redaction. It returns false if a snapshot accessor or source index is invalid.
func BuildSources(snapshot *evidence.Snapshot) (Result, bool) {
	return BuildWithSensitive(snapshot, nil, false)
}

// BuildWithSensitive additionally redacts vulnerability-specific byte
// intervals. Intervals must be sorted, non-overlapping, non-empty, in bounds,
// and no more numerous than MaxSensitiveIntervals. fullySensitive is the
// conservative fallback for analyzer failure. Sink intervals are ignored when
// redaction is disabled. Invalid snapshot data or intervals return false.
func BuildWithSensitive(snapshot *evidence.Snapshot, intervals []Interval, fullySensitive bool) (Result, bool) {
	if snapshot == nil || snapshot.SourceCount() > spans.MaxEventSources || snapshot.PartCount() > evidence.MaxParts || !validIntervals(snapshot.Value(), intervals) {
		return Result{}, false
	}
	if !config.RedactionEnabled {
		intervals = nil
		fullySensitive = false
	}

	sensitive := make([]bool, snapshot.SourceCount())
	for index := 0; index < snapshot.SourceCount(); index++ {
		source, ok := snapshot.SourceAt(index)
		if !ok {
			return Result{}, false
		}
		sensitive[index] = config.RedactionEnabled && (fullySensitive || sourceSensitive(source))
	}
	for index := 0; index < snapshot.PartCount(); index++ {
		part, ok := snapshot.PartAt(index)
		if !ok || part.Source < -1 || part.Source >= int16(snapshot.SourceCount()) {
			return Result{}, false
		}
		if part.Source >= 0 && !sensitive[part.Source] && overlapsSensitive(part.Start, part.Length, intervals) {
			sensitive[part.Source] = true
		}
	}

	result, patterns, ok := buildWireSources(snapshot, sensitive)
	if !ok {
		return Result{}, false
	}
	parts, overflow, ok := buildParts(snapshot, sensitive, patterns, intervals, fullySensitive)
	if !ok {
		return Result{}, false
	}
	if overflow {
		if !config.RedactionEnabled {
			return Result{}, false
		}
		for index := range sensitive {
			sensitive[index] = true
		}
		result, patterns, ok = buildWireSources(snapshot, sensitive)
		if !ok {
			return Result{}, false
		}
		parts, overflow, ok = buildParts(snapshot, sensitive, patterns, nil, true)
		if !ok || overflow {
			return Result{}, false
		}
	}
	result.Parts = parts
	return result, true
}

func buildWireSources(snapshot *evidence.Snapshot, sensitive []bool) (Result, []string, bool) {
	result := Result{Sources: make([]spans.TaintedSource, snapshot.SourceCount())}
	patterns := make([]string, snapshot.SourceCount())
	for index := 0; index < snapshot.SourceCount(); index++ {
		source, ok := snapshot.SourceAt(index)
		if !ok {
			return Result{}, nil, false
		}
		identity := spans.SourceIdentity{Origin: source.Origin, Name: source.Name, Value: source.Value}
		var wire model.Source
		if sensitive[index] {
			wire = model.NewSourceRedactedString(source.Origin, source.Name, alphanumericPattern(len(source.Value)))
			patterns[index] = wire.Pattern
		} else {
			wire = model.NewSourceString(source.Origin, source.Name, source.Value)
		}
		result.Sources[index] = spans.TaintedSource{Identity: identity, Model: wire}
	}
	return result, patterns, true
}

func buildParts(snapshot *evidence.Snapshot, sensitive []bool, patterns []string, intervals []Interval, fullySensitive bool) ([]model.ValuePart, bool, bool) {
	parts := make([]model.ValuePart, 0, min(snapshot.PartCount()+2*len(intervals), evidence.MaxParts))
	remainingCharacters := config.TruncationMaxValue
	remainingComparisons := sourceComparisonBudget
	intervalIndex := 0
	for index := 0; index < snapshot.PartCount(); index++ {
		part, ok := snapshot.PartAt(index)
		if !ok {
			return nil, false, false
		}
		if part.Length == 0 || part.Start > uint32(len(snapshot.Value())) || part.Length > uint32(len(snapshot.Value()))-part.Start {
			return nil, false, false
		}
		partEnd := part.Start + part.Length
		if fullySensitive || part.Source >= 0 && sensitive[part.Source] {
			if len(parts) >= evidence.MaxParts {
				return nil, true, true
			}
			value, _ := snapshot.PartValue(part)
			output, truncated, valid := buildPart(snapshot, part, value, fullySensitive, sensitive, patterns, &remainingComparisons, &remainingCharacters)
			if !valid {
				return nil, false, false
			}
			parts = append(parts, output)
			if truncated {
				return parts, false, true
			}
			continue
		}
		position := part.Start
		for intervalIndex < len(intervals) && intervals[intervalIndex].Start+intervals[intervalIndex].Length <= position {
			intervalIndex++
		}
		for position < partEnd {
			for intervalIndex < len(intervals) && intervals[intervalIndex].Start+intervals[intervalIndex].Length <= position {
				intervalIndex++
			}
			sinkSensitive := fullySensitive
			next := partEnd
			if !sinkSensitive && intervalIndex < len(intervals) {
				interval := intervals[intervalIndex]
				intervalEnd := interval.Start + interval.Length
				if interval.Start <= position && position < intervalEnd {
					sinkSensitive = true
					next = min(next, intervalEnd)
				} else if position < interval.Start {
					next = min(next, interval.Start)
				}
			}
			if len(parts) >= evidence.MaxParts {
				return nil, true, true
			}
			value := snapshot.Value()[position:next]
			output, truncated, valid := buildPart(snapshot, part, value, sinkSensitive, sensitive, patterns, &remainingComparisons, &remainingCharacters)
			if !valid {
				return nil, false, false
			}
			parts = append(parts, output)
			if truncated {
				return parts, false, true
			}
			position = next
		}
	}
	return parts, false, true
}

func buildPart(snapshot *evidence.Snapshot, part evidence.Part, value string, sinkSensitive bool, sensitive []bool, patterns []string, comparisons *int, characters *uint64) (model.ValuePart, bool, bool) {
	redacted := sinkSensitive || part.Source >= 0 && sensitive[part.Source]
	var truncated model.TruncatedSide
	if redacted {
		value, truncated = truncateRedactedEvidence(value, characters)
	} else {
		value, truncated = truncateEvidence(value, characters)
	}
	if part.Source < 0 {
		if redacted {
			return model.ValuePart{Pattern: strings.Repeat("*", len(value)), Redacted: true, Truncated: truncated}, truncated != model.TruncatedSideNone, true
		}
		return model.ValuePart{Value: value, Truncated: truncated}, truncated != model.TruncatedSideNone, true
	}
	sourceIndex := int(part.Source)
	if sourceIndex >= len(sensitive) {
		return model.ValuePart{}, false, false
	}
	marks := markTypes(part.Marks)
	if !redacted {
		return model.ValuePart{Value: value, SourceIndex: &sourceIndex, SecureMarks: marks, Truncated: truncated}, truncated != model.TruncatedSideNone, true
	}
	source, ok := snapshot.SourceAt(sourceIndex)
	if !ok {
		return model.ValuePart{}, false, false
	}
	pattern := mappedPattern(value, source.Value, patterns[sourceIndex], comparisons)
	return model.ValuePart{Pattern: pattern, Redacted: true, SourceIndex: &sourceIndex, SecureMarks: marks, Truncated: truncated}, truncated != model.TruncatedSideNone, true
}

func truncateRedactedEvidence(value string, remaining *uint64) (string, model.TruncatedSide) {
	if remaining == nil {
		return "", model.TruncatedSideRight
	}
	if uint64(len(value)) <= *remaining {
		*remaining -= uint64(len(value))
		return value, model.TruncatedSideNone
	}
	result := value[:int(*remaining)]
	*remaining = 0
	return result, model.TruncatedSideRight
}

func truncateEvidence(value string, remaining *uint64) (string, model.TruncatedSide) {
	if remaining == nil {
		return "", model.TruncatedSideRight
	}
	result, truncatedValue := truncation.String(value, *remaining)
	consumed := uint64(utf8.RuneCountInString(result))
	if consumed > *remaining {
		consumed = *remaining
	}
	*remaining -= consumed
	if truncatedValue {
		return result, model.TruncatedSideRight
	}
	return result, model.TruncatedSideNone
}

func validIntervals(value string, intervals []Interval) bool {
	if len(intervals) > MaxSensitiveIntervals {
		return false
	}
	var previousEnd uint32
	for index, interval := range intervals {
		if interval.Length == 0 || interval.Start > uint32(len(value)) || interval.Length > uint32(len(value))-interval.Start || index > 0 && interval.Start < previousEnd {
			return false
		}
		previousEnd = interval.Start + interval.Length
	}
	return true
}

func overlapsSensitive(start, length uint32, intervals []Interval) bool {
	end := start + length
	for _, interval := range intervals {
		intervalEnd := interval.Start + interval.Length
		if interval.Start >= end {
			return false
		}
		if intervalEnd > start {
			return true
		}
	}
	return false
}

func sourceSensitive(source evidence.Source) bool {
	return config.RedactionNamePattern != nil && config.RedactionNamePattern.MatchString(source.Name) ||
		config.RedactionValuePattern != nil && config.RedactionValuePattern.MatchString(source.Value)
}

func mappedPattern(value, sourceValue, sourcePattern string, remaining *int) string {
	if len(value) == 0 {
		return ""
	}
	cost := 2*len(sourceValue) + len(value)
	if remaining == nil || cost < 0 || cost > *remaining {
		return strings.Repeat("*", len(value))
	}
	*remaining -= cost
	offset := strings.Index(sourceValue, value)
	if offset < 0 || strings.Contains(sourceValue[offset+1:], value) || offset > len(sourcePattern) || len(value) > len(sourcePattern)-offset {
		return strings.Repeat("*", len(value))
	}
	return sourcePattern[offset : offset+len(value)]
}

func alphanumericPattern(length int) string {
	if length <= 0 {
		return ""
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var builder strings.Builder
	builder.Grow(length)
	for index := 0; index < length; index++ {
		builder.WriteByte(alphabet[index%len(alphabet)])
	}
	return builder.String()
}

func markTypes(marks uint64) []constants.VulnerabilityType {
	if marks == 0 {
		return nil
	}
	result := make([]constants.VulnerabilityType, 0, 2)
	for value := uint(1); value <= constants.VulnerabilityTypeCount; value++ {
		vulnerability := constants.VulnerabilityType(value)
		if ranges.HasMark(marks, vulnerability) {
			result = append(result, vulnerability)
		}
	}
	return result
}
