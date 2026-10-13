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
)

func TestBuildRedactsForeignParts(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "redaction disabled", true: "redaction enabled"}[enabled], func(t *testing.T) {
			configureRedaction(t, enabled, `never-match`, `never-match`)
			const own, foreign = "alpha-value", "bravo-value"
			value := own + " -- " + foreign
			// The snapshot of the owner of "alpha": the bytes of "bravo" are
			// tainted bytes of a different request.
			snapshot := segmentsSnapshot(t, value,
				evidence.Segment{Start: 0, Length: uint32(len(own)), Source: evidence.Source{Origin: constants.OriginHttpRequestParameter, Name: "alpha", Value: own}},
				evidence.Segment{Start: uint32(len(own) + 4), Length: uint32(len(foreign)), Foreign: true},
			)
			// The comment of the SQL analyzer is not sensitive.
			result, ok := BuildWithSensitive(snapshot, nil, false)
			if !ok || len(result.Sources) != 1 {
				t.Fatalf("result = %#v, %t", result, ok)
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
		})
	}
}
