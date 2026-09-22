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
	source := managedSource(t, "parameter", "xx")
	values := make([]string, evidence.MaxJoinedValues)
	for index := range values {
		values[index] = source
	}
	value := strings.Join(values, "abcd")
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = uint64(len(value))
	t.Cleanup(func() { config.TruncationMaxValue = previous })
	snapshot, status := evidence.CollectJoinedStrings(values, "abcd", value, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, evidence.StatusCollected, status)
	require.Equal(t, 2*len(values)-1, snapshot.PartCount())

	// Each interval splits a literal gap into three parts. The four added
	// parts exceed the event bound and must trigger complete redaction.
	result, ok := BuildWithSensitive(snapshot, []Interval{{Start: 3, Length: 1}, {Start: 9, Length: 1}}, false)
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
