// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"bytes"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"
)

func TestTruncateStringIfNeeded(t *testing.T) {
	for _, test := range []struct {
		name              string
		maxValue          uint64
		input             string
		expectedValue     string
		expectedTruncated TruncatedSide
	}{
		{name: "empty", maxValue: 3, input: "", expectedValue: "", expectedTruncated: TruncatedSideNone},
		{name: "empty at zero limit", maxValue: 0, input: "", expectedValue: "", expectedTruncated: TruncatedSideNone},
		{name: "non-empty at zero limit", maxValue: 0, input: "a", expectedValue: "", expectedTruncated: TruncatedSideRight},
		{name: "below limit", maxValue: 3, input: "ab", expectedValue: "ab", expectedTruncated: TruncatedSideNone},
		{name: "at limit", maxValue: 3, input: "abc", expectedValue: "abc", expectedTruncated: TruncatedSideNone},
		{name: "above limit", maxValue: 3, input: "abcd", expectedValue: "abc", expectedTruncated: TruncatedSideRight},
		{name: "multibyte below limit", maxValue: 3, input: "éé", expectedValue: "éé", expectedTruncated: TruncatedSideNone},
		{name: "multibyte at limit", maxValue: 3, input: "ééé", expectedValue: "ééé", expectedTruncated: TruncatedSideNone},
		{name: "multibyte above limit", maxValue: 2, input: "ééé", expectedValue: "éé", expectedTruncated: TruncatedSideRight},
	} {
		t.Run(test.name, func(t *testing.T) {
			setTruncationMaxValue(t, test.maxValue)

			value, truncated := truncateStringIfNeeded(test.input)

			require.Equal(t, test.expectedValue, value)
			require.Equal(t, test.expectedTruncated, truncated)
		})
	}
}

func TestConstructorsTruncateStrings(t *testing.T) {
	setTruncationMaxValue(t, 3)

	const (
		longValue      = "abcd"
		truncatedValue = "abc"
		sourceIndex    = 7
	)
	origin := constants.OriginHttpRequestParameter
	secureMarks := []constants.VulnerabilityType{constants.VulnerabilityTypeXss}

	t.Run("evidence value", func(t *testing.T) {
		require.Equal(t, &Evidence{
			Value:     truncatedValue,
			Truncated: TruncatedSideRight,
		}, NewEvidenceString(longValue))
	})

	t.Run("redacted evidence pattern", func(t *testing.T) {
		require.Equal(t, &Evidence{
			Pattern:   truncatedValue,
			Redacted:  true,
			Truncated: TruncatedSideRight,
		}, NewEvidenceRedactedString(longValue))
	})

	t.Run("value part", func(t *testing.T) {
		require.Equal(t, ValuePart{
			Value:     truncatedValue,
			Truncated: TruncatedSideRight,
		}, NewValuePartString(longValue))
	})

	t.Run("redacted value part", func(t *testing.T) {
		require.Equal(t, ValuePart{
			Pattern:   truncatedValue,
			Redacted:  true,
			Truncated: TruncatedSideRight,
		}, NewValuePartRedactedString(longValue))
	})

	t.Run("tainted value part", func(t *testing.T) {
		require.Equal(t, ValuePart{
			Value:       truncatedValue,
			Truncated:   TruncatedSideRight,
			SourceIndex: new(sourceIndex),
			SecureMarks: secureMarks,
		}, NewValuePartTaintedString(longValue, sourceIndex, secureMarks))
	})

	t.Run("redacted tainted value part", func(t *testing.T) {
		require.Equal(t, ValuePart{
			Pattern:     truncatedValue,
			Redacted:    true,
			Truncated:   TruncatedSideRight,
			SourceIndex: new(sourceIndex),
			SecureMarks: secureMarks,
		}, NewValuePartTaintedRedactedString(longValue, sourceIndex, secureMarks))
	})

	t.Run("source value", func(t *testing.T) {
		require.Equal(t, Source{
			Origin:    origin,
			Name:      "query",
			Value:     truncatedValue,
			Truncated: TruncatedSideRight,
		}, NewSourceString(origin, "query", longValue))
	})

	t.Run("redacted source pattern", func(t *testing.T) {
		require.Equal(t, Source{
			Origin:    origin,
			Name:      "query",
			Pattern:   truncatedValue,
			Redacted:  true,
			Truncated: TruncatedSideRight,
		}, NewSourceRedactedString(origin, "query", longValue))
	})
}

func TestTruncatedStringsMarshalMsg(t *testing.T) {
	setTruncationMaxValue(t, 3)

	for _, test := range []struct {
		name     string
		value    msgp.Marshaler
		expected string
	}{
		{
			name:     "source",
			value:    new(NewSourceString(constants.OriginHttpRequestParameter, "query", "abcd")),
			expected: `{"origin":"http.request.parameter","name":"query","value":"abc","truncated":"right"}`,
		},
		{
			name:     "evidence",
			value:    NewEvidenceString("abcd"),
			expected: `{"value":"abc","truncated":"right"}`,
		},
		{
			name:     "value part",
			value:    new(NewValuePartTaintedRedactedString("abcd", 7, []constants.VulnerabilityType{constants.VulnerabilityTypeXss})),
			expected: `{"pattern":"abc","redacted":true,"truncated":"right","source":7,"secure_marks":["XSS"]}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.value.MarshalMsg(nil)
			require.NoError(t, err)

			var decoded bytes.Buffer
			remainder, err := msgp.UnmarshalAsJSON(&decoded, encoded)
			require.NoError(t, err)
			require.Empty(t, remainder)
			require.JSONEq(t, test.expected, decoded.String())
		})
	}
}

// setTruncationMaxValue must not be called by parallel tests because the
// production setting it temporarily replaces is package-global.
func setTruncationMaxValue(t *testing.T, maxValue uint64) {
	t.Helper()
	previousMaxValue := config.TruncationMaxValue
	config.TruncationMaxValue = maxValue
	t.Cleanup(func() { config.TruncationMaxValue = previousMaxValue })
}
