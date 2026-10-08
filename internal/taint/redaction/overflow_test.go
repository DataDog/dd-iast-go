// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/stretchr/testify/require"
)

func TestSensitiveIntervalsOverflowRedactsCompleteEvidence(t *testing.T) {
	configureRedaction(t, true, "never-match", "never-match")
	previousRanges := config.MaxRangeCount
	config.MaxRangeCount = evidence.MaxAttributedParts
	t.Cleanup(func() { config.MaxRangeCount = previousRanges })
	// The tainted parts alternate: a part of the source, then a foreign
	// part. A clean gap of 4 bytes is before and after each tainted part.
	source := evidence.Source{Origin: constants.OriginHttpRequestParameter, Name: "parameter", Value: "xx"}
	var builder strings.Builder
	var segments []evidence.Segment
	var intervals []Interval
	for index := range evidence.MaxTaintedParts {
		builder.WriteString("abcd")
		intervals = append(intervals, Interval{Start: uint32(builder.Len() - 2), Length: 1})
		segment := evidence.Segment{Start: uint32(builder.Len()), Length: 2, Source: source, Foreign: index%2 == 1}
		segments = append(segments, segment)
		builder.WriteString("xx")
	}
	builder.WriteString("abcd")
	intervals = append(intervals, Interval{Start: uint32(builder.Len() - 2), Length: 1})
	value := builder.String()
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = uint64(len(value))
	t.Cleanup(func() { config.TruncationMaxValue = previous })
	snapshot, status := evidence.Build(testOwner, value, segments)
	require.Equal(t, evidence.StatusCollected, status)
	require.Equal(t, 2*evidence.MaxTaintedParts+1, snapshot.PartCount())

	// Each interval splits a literal gap into three parts. The added parts
	// exceed the event bound and must trigger complete redaction.
	require.Greater(t, snapshot.PartCount()+2*len(intervals), evidence.MaxParts)
	result, ok := BuildWithSensitive(snapshot, intervals, false)
	require.True(t, ok)
	require.Len(t, result.Parts, snapshot.PartCount())
	require.Len(t, result.Sources, 1)
	require.True(t, result.Sources[0].Model.Redacted)
	require.Empty(t, result.Sources[0].Model.Value)
	for _, part := range result.Parts {
		require.True(t, part.Redacted)
		require.Empty(t, part.Value)
		require.Equal(t, model.TruncatedSideNone, part.Truncated)
	}
	require.Equal(t, strings.Repeat("*", len(value)), normalizeParts(result.Parts))
}

func TestLiteralEvidenceUsesRemainingCharacterBudget(t *testing.T) {
	configureRedaction(t, false, "never-match", "never-match")
	snapshot := compositeSnapshot(t, "prefix", "secret", "suffix")
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = 3
	t.Cleanup(func() { config.TruncationMaxValue = previous })
	result, ok := BuildSources(snapshot)
	require.True(t, ok)
	require.Len(t, result.Parts, 1)
	require.Equal(t, "pre", result.Parts[0].Value)
	require.Nil(t, result.Parts[0].SourceIndex)
	require.False(t, result.Parts[0].Redacted)
	require.Equal(t, model.TruncatedSideRight, result.Parts[0].Truncated)
}
