// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

func TestBuildRejectsMultipleOwnerSnapshot(t *testing.T) {
	configureRedaction(t, false, `never-match`, `never-match`)
	alpha := managedSource(t, "alpha", "alpha-value")
	bravo := managedSource(t, "bravo", "bravo-value")
	value := propagation.JoinString([]string{alpha, bravo}, "", alpha+bravo)
	snapshot, status := evidence.CollectString(value, constants.VulnerabilityTypeSqlInjection)
	if status != evidence.StatusCollected || snapshot.OwnerCount() != 2 {
		t.Fatalf("snapshot = %v owners:%d", status, snapshot.OwnerCount())
	}
	if result, ok := BuildSources(snapshot); ok {
		t.Fatalf("multi-owner snapshot was converted: %#v", result)
	}
	owner, _ := snapshot.OwnerAt(0)
	restricted, ok := snapshot.ForOwner(owner)
	if !ok {
		t.Fatal("ForOwner failed")
	}
	result, ok := BuildSources(restricted)
	if !ok || len(result.Sources) != 1 {
		t.Fatalf("single-owner result = %#v, %t", result, ok)
	}
}

func TestBuildRedactsForeignParts(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "redaction disabled", true: "redaction enabled"}[enabled], func(t *testing.T) {
			configureRedaction(t, enabled, `never-match`, `never-match`)
			alpha := managedSource(t, "alpha", "alpha-value")
			bravo := managedSource(t, "bravo", "bravo-value")
			value := propagation.JoinString([]string{alpha, " -- ", bravo}, "", alpha+" -- "+bravo)
			all, status := evidence.CollectString(value, constants.VulnerabilityTypeSqlInjection)
			if status != evidence.StatusCollected || all.OwnerCount() != 2 {
				t.Fatalf("snapshot = %v owners:%d", status, all.OwnerCount())
			}
			for index := range all.OwnerCount() {
				owner, _ := all.OwnerAt(index)
				snapshot, status := evidence.CollectStringFor(evidence.Target{Owner: owner, Known: true}, value, constants.VulnerabilityTypeSqlInjection)
				if status != evidence.StatusCollected {
					t.Fatalf("status = %v", status)
				}
				// The comment of the SQL analyzer is not sensitive.
				result, ok := BuildWithSensitive(snapshot, nil, false)
				if !ok || len(result.Sources) != 1 {
					t.Fatalf("result = %#v, %t", result, ok)
				}
				own, foreign := result.Sources[0].Identity.Value, "bravo-value"
				if own == foreign {
					foreign = "alpha-value"
				}
				text := normalizeParts(result.Parts)
				if len(text) != len(value) || strings.Contains(text, foreign) {
					t.Fatalf("evidence %q shows foreign value %q", text, foreign)
				}
				redacted := 0
				for _, part := range result.Parts {
					if strings.Contains(part.Value, foreign) {
						t.Fatalf("part %#v shows foreign value", part)
					}
					if part.Redacted && part.SourceIndex == nil {
						redacted++
					}
				}
				if redacted != 1 {
					t.Fatalf("foreign markers = %d, want 1: %#v", redacted, result.Parts)
				}
				if !enabled && !strings.Contains(text, own) {
					t.Fatalf("evidence %q hides own value %q", text, own)
				}
			}
		})
	}
}
