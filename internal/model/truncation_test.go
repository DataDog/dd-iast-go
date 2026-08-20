// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model_test

import (
	"bytes"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"
)

func TestConstructorsTruncateStrings(t *testing.T) {
	setTruncationMaxValue(t, 3)

	const (
		longValue      = "abcd"
		truncatedValue = "abc"
		sourceIndex    = 7
	)
	origin := constants.OriginHttpRequestParameter
	secureMarks := []constants.VulnerabilityType{constants.VulnerabilityTypeXss}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{
			name: "evidence value",
			got:  model.NewEvidenceString(longValue),
			want: &model.Evidence{Value: truncatedValue, Truncated: model.TruncatedSideRight},
		},
		{
			name: "redacted evidence pattern",
			got:  model.NewEvidenceRedactedString(longValue),
			want: &model.Evidence{Pattern: truncatedValue, Redacted: true, Truncated: model.TruncatedSideRight},
		},
		{
			name: "value part",
			got:  model.NewValuePartString(longValue),
			want: model.ValuePart{Value: truncatedValue, Truncated: model.TruncatedSideRight},
		},
		{
			name: "redacted value part",
			got:  model.NewValuePartRedactedString(longValue),
			want: model.ValuePart{Pattern: truncatedValue, Redacted: true, Truncated: model.TruncatedSideRight},
		},
		{
			name: "tainted value part",
			got:  model.NewValuePartTaintedString(longValue, sourceIndex, secureMarks),
			want: model.ValuePart{Value: truncatedValue, Truncated: model.TruncatedSideRight, SourceIndex: new(sourceIndex), SecureMarks: secureMarks},
		},
		{
			name: "redacted tainted value part",
			got:  model.NewValuePartTaintedRedactedString(longValue, sourceIndex, secureMarks),
			want: model.ValuePart{Pattern: truncatedValue, Redacted: true, Truncated: model.TruncatedSideRight, SourceIndex: new(sourceIndex), SecureMarks: secureMarks},
		},
		{
			name: "source value",
			got:  model.NewSourceString(origin, "query", longValue),
			want: model.Source{Origin: origin, Name: "query", Value: truncatedValue, Truncated: model.TruncatedSideRight},
		},
		{
			name: "redacted source pattern",
			got:  model.NewSourceRedactedString(origin, "query", longValue),
			want: model.Source{Origin: origin, Name: "query", Pattern: truncatedValue, Redacted: true, Truncated: model.TruncatedSideRight},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, test.got)
		})
	}
}

func TestTruncatedStringsMarshalMsg(t *testing.T) {
	setTruncationMaxValue(t, 3)

	tests := []struct {
		name  string
		value msgp.Marshaler
		want  string
	}{
		{
			name:  "source",
			value: new(model.NewSourceString(constants.OriginHttpRequestParameter, "query", "abcd")),
			want:  `{"origin":"http.request.parameter","name":"query","value":"abc","truncated":"right"}`,
		},
		{
			name:  "evidence",
			value: model.NewEvidenceString("abcd"),
			want:  `{"value":"abc","truncated":"right"}`,
		},
		{
			name:  "value part",
			value: new(model.NewValuePartTaintedRedactedString("abcd", 7, []constants.VulnerabilityType{constants.VulnerabilityTypeXss})),
			want:  `{"pattern":"abc","redacted":true,"truncated":"right","source":7,"secure_marks":["XSS"]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.value.MarshalMsg(nil)
			require.NoError(t, err)

			var decoded bytes.Buffer
			remainder, err := msgp.UnmarshalAsJSON(&decoded, encoded)
			require.NoError(t, err)
			require.Empty(t, remainder)
			require.JSONEq(t, test.want, decoded.String())
		})
	}
}

func setTruncationMaxValue(t *testing.T, maxValue uint64) {
	t.Helper()
	previousMaxValue := config.TruncationMaxValue
	config.TruncationMaxValue = maxValue
	t.Cleanup(func() { config.TruncationMaxValue = previousMaxValue })
}
