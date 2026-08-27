// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
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

func TestMarkTypes(t *testing.T) {
	sql, _ := ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	command, _ := ranges.MarkBit(constants.VulnerabilityTypeCommandInjection)
	got := markTypes(sql | command)
	if len(got) != 2 || got[0] != constants.VulnerabilityTypeCommandInjection || got[1] != constants.VulnerabilityTypeSqlInjection {
		t.Fatalf("markTypes = %#v", got)
	}
	if markTypes(0) != nil {
		t.Fatal("zero marks were not nil")
	}
}

func TestBuildSourcesRejectsNilSnapshot(t *testing.T) {
	if _, ok := BuildSources(nil); ok {
		t.Fatal("nil snapshot was accepted")
	}
}

func sourceSnapshot(t *testing.T, name, value string) *evidence.Snapshot {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("request scope was not created")
	}
	t.Cleanup(func() {
		scope.Finish()
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	managed := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: name}, value)
	snapshot, status := evidence.CollectString(managed, constants.VulnerabilityTypeSqlInjection)
	if status != evidence.StatusCollected {
		t.Fatalf("CollectString status = %v", status)
	}
	return snapshot
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
