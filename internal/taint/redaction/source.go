// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package redaction converts report-owned taint snapshots to bounded wire
// sources and evidence parts without exposing sensitive source values.
package redaction

import (
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
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
	if snapshot == nil || snapshot.SourceCount() > spans.MaxEventSources || snapshot.PartCount() > evidence.MaxParts {
		return Result{}, false
	}
	result := Result{
		Sources: make([]spans.TaintedSource, snapshot.SourceCount()),
		Parts:   make([]model.ValuePart, snapshot.PartCount()),
	}
	sensitive := make([]bool, snapshot.SourceCount())
	patterns := make([]string, snapshot.SourceCount())
	for index := 0; index < snapshot.SourceCount(); index++ {
		source, ok := snapshot.SourceAt(index)
		if !ok {
			return Result{}, false
		}
		identity := spans.SourceIdentity{Origin: source.Origin, Name: source.Name, Value: source.Value}
		sensitive[index] = config.RedactionEnabled && sourceSensitive(source)
		var wire model.Source
		if sensitive[index] {
			wire = model.NewSourceRedactedString(source.Origin, source.Name, alphanumericPattern(len(source.Value)))
			patterns[index] = wire.Pattern
		} else {
			wire = model.NewSourceString(source.Origin, source.Name, source.Value)
		}
		result.Sources[index] = spans.TaintedSource{Identity: identity, Model: wire}
	}

	remainingComparisons := sourceComparisonBudget
	for index := 0; index < snapshot.PartCount(); index++ {
		part, ok := snapshot.PartAt(index)
		if !ok {
			return Result{}, false
		}
		value, ok := snapshot.PartValue(part)
		if !ok {
			return Result{}, false
		}
		if part.Source < 0 {
			result.Parts[index] = model.NewValuePartString(value)
			continue
		}
		sourceIndex := int(part.Source)
		if sourceIndex >= len(result.Sources) {
			return Result{}, false
		}
		marks := markTypes(part.Marks)
		if !sensitive[sourceIndex] {
			result.Parts[index] = model.NewValuePartTaintedString(value, sourceIndex, marks)
			continue
		}
		source, _ := snapshot.SourceAt(sourceIndex)
		pattern := mappedPattern(value, source.Value, patterns[sourceIndex], &remainingComparisons)
		result.Parts[index] = model.NewValuePartTaintedRedactedString(pattern, sourceIndex, marks)
	}
	return result, true
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
