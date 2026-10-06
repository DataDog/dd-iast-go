// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import (
	"regexp"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
)

func TestBuildSourcesRedactsSensitiveName(t *testing.T) {
	configureRedaction(t, true, `(?i)password`, `never-match`)
	snapshot := sourceSnapshot(t, "password", "attacker")
	result, ok := BuildSources(snapshot)
	if !ok || len(result.Sources) != 1 || len(result.Parts) != 1 {
		t.Fatalf("BuildSources = %#v, %t", result, ok)
	}
	source := result.Sources[0]
	if source.Identity.Value != "attacker" || source.Model.Value != "" || !source.Model.Redacted || len(source.Model.Pattern) != len("attacker") {
		t.Fatalf("unexpected redacted source: %#v", source)
	}
	part := result.Parts[0]
	if part.SourceIndex == nil || *part.SourceIndex != 0 || !part.Redacted || part.Value != "" || part.Pattern != source.Model.Pattern {
		t.Fatalf("unexpected redacted part: %#v", part)
	}
}

func TestBuildSourcesRedactsSensitiveValue(t *testing.T) {
	configureRedaction(t, true, `never-match`, `(?i)bearer`)
	snapshot := sourceSnapshot(t, "authorization", "Bearer secret")
	result, ok := BuildSources(snapshot)
	if !ok || !result.Sources[0].Model.Redacted {
		t.Fatal("sensitive value was not redacted")
	}
}

func TestBuildSourcesUsesByteLengthPatterns(t *testing.T) {
	configureRedaction(t, true, `password`, `never-match`)
	value := strings.Repeat("é", 10)
	result, ok := BuildSources(sourceSnapshot(t, "password", value))
	if !ok {
		t.Fatal("BuildSources failed")
	}
	if got := len(result.Sources[0].Model.Pattern); got != len(value) {
		t.Fatalf("pattern bytes = %d, want %d", got, len(value))
	}
}

func TestBuildSourcesFallsBackPastTruncatedSourcePattern(t *testing.T) {
	configureRedaction(t, true, `password`, `never-match`)
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = 250
	t.Cleanup(func() { config.TruncationMaxValue = previous })
	value := strings.Repeat("x", 300)
	result, ok := BuildSources(sourceSnapshot(t, "password", value))
	if !ok {
		t.Fatal("BuildSources failed")
	}
	if len(result.Sources[0].Model.Pattern) != 250 {
		t.Fatalf("wire source pattern length = %d, want 250", len(result.Sources[0].Model.Pattern))
	}
	if result.Parts[0].Pattern != strings.Repeat("*", 250) {
		t.Fatalf("evidence pattern = %q, want conservative fallback", result.Parts[0].Pattern)
	}
}

func TestBuildSourcesDisabledKeepsRawValue(t *testing.T) {
	configureRedaction(t, false, `password`, `attacker`)
	snapshot := sourceSnapshot(t, "password", "attacker")
	result, ok := BuildSources(snapshot)
	if !ok {
		t.Fatal("BuildSources failed")
	}
	if result.Sources[0].Model.Redacted || result.Sources[0].Model.Value != "attacker" {
		t.Fatalf("unexpected source: %#v", result.Sources[0].Model)
	}
	if result.Parts[0].Redacted || result.Parts[0].Value != "attacker" {
		t.Fatalf("unexpected part: %#v", result.Parts[0])
	}
}

func TestBuildWithSensitiveRedactsSourcesAndLiteralGaps(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	snapshot := compositeSnapshot(t, "SELECT '", "secret", "' AND 123")
	result, ok := BuildWithSensitive(snapshot, []Interval{{Start: 9, Length: 2}, {Start: 20, Length: 3}}, false)
	if !ok {
		t.Fatal("BuildWithSensitive failed")
	}
	if !result.Sources[0].Model.Redacted || normalizeParts(result.Parts) != "SELECT '******' AND ***" {
		t.Fatalf("sensitive result = source:%#v parts:%#v normalized:%q", result.Sources[0], result.Parts, normalizeParts(result.Parts))
	}
	for _, part := range result.Parts {
		if part.SourceIndex != nil && !part.Redacted {
			t.Fatalf("source occurrence remained raw: %#v", part)
		}
	}
}

func TestBuildWithSensitiveDisabledIgnoresSinkIntervals(t *testing.T) {
	configureRedaction(t, false, `secret`, `secret`)
	snapshot := compositeSnapshot(t, "SELECT '", "secret", "'")
	result, ok := BuildWithSensitive(snapshot, []Interval{{Start: 8, Length: 6}}, true)
	if !ok || result.Sources[0].Model.Redacted || normalizeParts(result.Parts) != "SELECT 'secret'" {
		t.Fatalf("disabled result = %#v, %t", result, ok)
	}
}

func TestBuildWithSensitiveAnalyzerFallbackRedactsEverything(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	snapshot := compositeSnapshot(t, "prefix", "secret", "suffix")
	result, ok := BuildWithSensitive(snapshot, nil, true)
	if !ok || !result.Sources[0].Model.Redacted || normalizeParts(result.Parts) != strings.Repeat("*", len("prefixsecretsuffix")) {
		t.Fatalf("fallback result = %#v, %t", result, ok)
	}
}

func TestBuildWithSensitiveUsesRunningTruncationBudget(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = 10
	t.Cleanup(func() { config.TruncationMaxValue = previous })
	result, ok := BuildWithSensitive(compositeSnapshot(t, "prefix", "secret", "suffix"), []Interval{{Start: 6, Length: 6}}, false)
	if !ok {
		t.Fatal("BuildWithSensitive failed")
	}
	retained := 0
	truncated := false
	for _, part := range result.Parts {
		retained += len([]rune(part.Value)) + len([]rune(part.Pattern))
		truncated = truncated || part.Truncated.String() == "right"
	}
	if retained != 10 || !truncated {
		t.Fatalf("retained characters = %d, truncated = %t, parts = %#v", retained, truncated, result.Parts)
	}
}

func TestBuildWithSensitiveBoundsMultibytePatterns(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = 250
	t.Cleanup(func() { config.TruncationMaxValue = previous })
	value := strings.Repeat("é", 250)
	result, ok := BuildWithSensitive(sourceSnapshot(t, "parameter", value), nil, true)
	if !ok || len(result.Parts) != 1 {
		t.Fatalf("BuildWithSensitive = %#v, %t", result, ok)
	}
	part := result.Parts[0]
	if len(part.Pattern) != 250 || part.Truncated != model.TruncatedSideRight {
		t.Fatalf("multibyte pattern = bytes:%d truncated:%v", len(part.Pattern), part.Truncated)
	}
}

func TestBuildWithSensitiveRejectsInvalidIntervals(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	snapshot := sourceSnapshot(t, "parameter", "secret")
	tooMany := make([]Interval, MaxSensitiveIntervals+1)
	for index := range tooMany {
		tooMany[index] = Interval{Start: uint32(index), Length: 1}
	}
	for _, intervals := range [][]Interval{{{Start: 1}}, {{Start: 5, Length: 2}}, {{Start: 3, Length: 2}, {Start: 1, Length: 1}}, tooMany} {
		if _, ok := BuildWithSensitive(snapshot, intervals, false); ok {
			t.Fatalf("accepted invalid intervals %#v", intervals)
		}
	}
}

func TestMappedPattern(t *testing.T) {
	pattern := alphanumericPattern(len("prefix-secret-suffix"))
	tests := []struct {
		name   string
		value  string
		source string
		budget int
		want   string
	}{
		{name: "unique", value: "secret", source: "prefix-secret-suffix", budget: 100, want: pattern[7:13]},
		{name: "missing", value: "changed", source: "prefix-secret-suffix", budget: 100, want: "*******"},
		{name: "ambiguous", value: "secret", source: "secret-secret", budget: 100, want: "******"},
		{name: "budget", value: "secret", source: "prefix-secret-suffix", budget: 1, want: "******"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			budget := test.budget
			got := mappedPattern(test.value, test.source, alphanumericPattern(len(test.source)), &budget)
			if got != test.want {
				t.Fatalf("mappedPattern = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAlphanumericPattern(t *testing.T) {
	pattern := alphanumericPattern(200)
	if len(pattern) != 200 || !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(pattern) {
		t.Fatalf("invalid pattern %q", pattern)
	}
	if alphanumericPattern(0) != "" || alphanumericPattern(-1) != "" {
		t.Fatal("non-positive pattern was not empty")
	}
}

func TestBuildSourcesRejectsNilSnapshot(t *testing.T) {
	if _, ok := BuildSources(nil); ok {
		t.Fatal("nil snapshot was accepted")
	}
}

var testOwner = evidence.OwnerIdentity{ID: 1, Generation: 1}

// sourceSnapshot returns the snapshot of a value that is one source.
func sourceSnapshot(t *testing.T, name, value string) *evidence.Snapshot {
	t.Helper()
	return segmentsSnapshot(t, value, evidence.Segment{
		Start: 0, Length: uint32(len(value)),
		Source: evidence.Source{Origin: constants.OriginHttpRequestParameter, Name: name, Value: value},
	})
}

// compositeSnapshot returns the snapshot of prefix+source+suffix, where only
// source is tainted.
func compositeSnapshot(t *testing.T, prefix, source, suffix string) *evidence.Snapshot {
	t.Helper()
	return segmentsSnapshot(t, prefix+source+suffix, evidence.Segment{
		Start: uint32(len(prefix)), Length: uint32(len(source)),
		Source: evidence.Source{Origin: constants.OriginHttpRequestParameter, Name: "parameter", Value: source},
	})
}

func segmentsSnapshot(t *testing.T, value string, segments ...evidence.Segment) *evidence.Snapshot {
	t.Helper()
	snapshot, status := evidence.Build(testOwner, value, segments)
	if status != evidence.StatusCollected {
		t.Fatalf("Build status = %v", status)
	}
	return snapshot
}

func normalizeParts(parts []model.ValuePart) string {
	var builder strings.Builder
	for _, part := range parts {
		if part.Redacted {
			builder.WriteString(strings.Repeat("*", len(part.Pattern)))
		} else {
			builder.WriteString(part.Value)
		}
	}
	return builder.String()
}

func configureRedaction(t *testing.T, enabled bool, name, value string) {
	t.Helper()
	previousEnabled := config.RedactionEnabled
	previousName := config.RedactionNamePattern
	previousValue := config.RedactionValuePattern
	config.RedactionEnabled = enabled
	config.RedactionNamePattern = regexp.MustCompile(name)
	config.RedactionValuePattern = regexp.MustCompile(value)
	t.Cleanup(func() {
		config.RedactionEnabled = previousEnabled
		config.RedactionNamePattern = previousName
		config.RedactionValuePattern = previousValue
	})
}

func BenchmarkMappedPattern(b *testing.B) {
	value := strings.Repeat("x", 1_024) + "secret"
	pattern := alphanumericPattern(len(value))
	b.ReportAllocs()
	for b.Loop() {
		budget := sourceComparisonBudget
		mappedPattern("secret", value, pattern, &budget)
	}
}
