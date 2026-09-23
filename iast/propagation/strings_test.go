// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestInstrumentedPropagationTelemetry(t *testing.T) {
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	registered := strings.Count(string(contents), "\n  - id:")
	require.Equal(t, uint(registered), telemetry.InstrumentedPropagation)
}

func activeString(t *testing.T, value string) string {
	return activeStringSource(t, "input", value)
}

func activeStringSource(t *testing.T, name, value string) string {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	return taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: name}, value)
}

func requireTaintedStrings(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		if value == "" {
			continue
		}
		var observed []taint.Range
		require.Truef(t, taint.VisitString(value, func(r taint.Range) bool {
			observed = append(observed, r)
			return true
		}), "value %q is not tainted", value)
		require.Len(t, observed, 1)
		require.Zero(t, observed[0].Start)
		require.Equal(t, uint32(len(value)), observed[0].Length)
		require.Equal(t, taint.OriginHttpRequestParameter, observed[0].Source.Origin)
		require.Equal(t, "input", observed[0].Source.Name)
	}
}

func TestStringWindowOperations(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	value := activeString(t, "  alpha,beta  ")

	clone := testapp.Clone(value)
	requireTaintedStrings(t, clone)
	allocations := testing.AllocsPerRun(100, func() { clone = testapp.Clone(value) })
	require.Equal(t, 1.0, allocations, "tainted strings.Clone must allocate once")
	before, after, found := testapp.Cut(value, ",")
	require.True(t, found)
	requireTaintedStrings(t, before, after)
	withoutPrefix, found := testapp.CutPrefix(value, "  ")
	require.True(t, found)
	withoutSuffix, found := testapp.CutSuffix(value, "  ")
	require.True(t, found)
	requireTaintedStrings(t, withoutPrefix, withoutSuffix)
	requireTaintedStrings(t, testapp.Split(value, ",")...)
	requireTaintedStrings(t, testapp.SplitN(value, ",", 2)...)
	requireTaintedStrings(t, testapp.SplitAfter(value, ",")...)
	requireTaintedStrings(t, testapp.SplitAfterN(value, ",", 2)...)
	requireTaintedStrings(t, slices.Collect(testapp.SplitSeq(value, ","))...)
	requireTaintedStrings(t, slices.Collect(testapp.SplitAfterSeq(value, ","))...)
	requireTaintedStrings(t, slices.Collect(testapp.Lines(value))...)
	requireTaintedStrings(t, testapp.Fields(value)...)
	requireTaintedStrings(t, testapp.FieldsFunc(value, unicode.IsSpace)...)
	requireTaintedStrings(t, slices.Collect(testapp.FieldsSeq(value))...)
	requireTaintedStrings(t, slices.Collect(testapp.FieldsFuncSeq(value, unicode.IsSpace))...)
	requireTaintedStrings(t,
		testapp.Trim(value, " "),
		testapp.TrimSpace(value),
		testapp.TrimLeft(value, " "),
		testapp.TrimRight(value, " "),
		testapp.TrimPrefix(value, "  "),
		testapp.TrimSuffix(value, "  "),
		testapp.TrimFunc(value, unicode.IsSpace),
		testapp.TrimLeftFunc(value, unicode.IsSpace),
		testapp.TrimRightFunc(value, unicode.IsSpace),
	)
}

func TestCoarseStringOperations(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	value := activeString(t, "Attack Value")
	requireTaintedStrings(t,
		testapp.ToLower(value),
		testapp.ToUpper(value),
		testapp.ToTitle(value),
		testapp.Map(func(r rune) rune { return r + 1 }, value),
		testapp.ToValidUTF8(value, "?"),
		testapp.ReplacerReplace(value),
		testapp.Sprint("prefix:", value),
		testapp.Sprintf("value=%s", value),
		testapp.Sprintln(value),
		testapp.QueryEscape(value),
		testapp.PathEscape(value),
		testapp.Quote(value),
		testapp.QuoteToASCII(value),
		testapp.QuoteToGraphic(value),
	)

	queryEscaped := activeString(t, "Attack+Value")
	query, err := testapp.QueryUnescape(queryEscaped)
	require.NoError(t, err)
	requireTaintedStrings(t, query)
	pathEscaped := activeString(t, "Attack%20Value")
	path, err := testapp.PathUnescape(pathEscaped)
	require.NoError(t, err)
	requireTaintedStrings(t, path)
	quoted := activeString(t, `"Attack Value"`)
	unquoted, err := testapp.Unquote(quoted)
	require.NoError(t, err)
	requireTaintedStrings(t, unquoted)
}

func TestCoarseFormattingRecordsBoundedDrops(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	included := activeStringSource(t, "included", "attack")
	dropped := activeStringSource(t, "dropped", "drop")

	tests := []struct {
		name      string
		arguments []any
		want      string
		call      func([]any) string
	}{
		{
			name: "Sprint", arguments: append([]any{included}, append(make([]any, 15), dropped)...),
			want: included + strings.Repeat("x", 15) + dropped,
			call: func(arguments []any) string { return testapp.Sprint(arguments...) },
		},
		{
			name: "Sprintf", arguments: append([]any{included}, append(make([]any, 14), dropped)...),
			want: included + strings.Repeat("x", 14) + dropped,
			call: func(arguments []any) string {
				return testapp.Sprintf(strings.Repeat("%s", len(arguments)), arguments...)
			},
		},
		{
			name: "Sprintln", arguments: append([]any{included}, append(make([]any, 15), dropped)...),
			want: included + " " + strings.Repeat("x ", 15) + dropped + "\n",
			call: func(arguments []any) string { return testapp.Sprintln(arguments...) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for index := 1; index < len(test.arguments)-1; index++ {
				test.arguments[index] = "x"
			}
			before := telemetry.DroppedPropagation.Load()
			got := test.call(test.arguments)
			require.Equal(t, test.want, got)
			require.Equal(t, before+1, telemetry.DroppedPropagation.Load())
			sources := make(map[string]bool)
			require.True(t, taint.VisitString(got, func(observed taint.Range) bool {
				sources[observed.Source.Name] = true
				return true
			}))
			require.Equal(t, map[string]bool{"included": true}, sources)
		})
	}
}

func TestReplacerReplacementProvenanceIsUnsupported(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	replacement := activeString(t, "secret")
	result := testapp.ReplacerReplacement("plain", replacement)
	require.False(t, taint.IsTaintedString(result))
}

func TestCoarseOperationsPreserveErrors(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, test := range []struct {
		name  string
		value string
		call  func(string) (string, error)
	}{
		{name: "query unescape", value: "%zz", call: testapp.QueryUnescape},
		{name: "path unescape", value: "%zz", call: testapp.PathUnescape},
		{name: "unquote", value: `"unterminated`, call: testapp.Unquote},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := activeString(t, test.value)
			result, err := test.call(value)
			require.Error(t, err)
			require.Empty(t, result)
			require.False(t, taint.IsTaintedString(result))
		})
	}
}

func TestIndirectStringCallIsUnsupported(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	value := activeString(t, "attacker")
	require.True(t, taint.IsTaintedString(testapp.Clone(value)))
	result := testapp.IndirectClone(value)
	require.False(t, taint.IsTaintedString(result))
}
