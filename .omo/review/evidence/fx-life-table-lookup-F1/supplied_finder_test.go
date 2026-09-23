// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestReviewHashDelimiterCollision(t *testing.T) {
	// Given: every NUL can be either the separator or part of a source field.
	table := New()
	origin := constants.OriginHttpRequestParameter
	joined := "aa" + strings.Repeat("\x00aa", MaxSources)
	var firstHash uint32
	maxProbes, totalProbes := 0, 0
	for i := 0; i < MaxSources; i++ {
		separator := 2 + 3*i
		name, value := joined[:separator], joined[separator+1:]
		hash := table.hash(origin, name, value)
		if i == 0 {
			firstHash = hash
		}

		// When: each distinct source is inserted into the fixed index.
		result := table.Add(origin, name, value)
		// Then: full equality preserves provenance; count occupied probes.
		if result.Status != AddAdded || result.ID != SourceID(i) {
			t.Fatalf("tuple %d: result %+v, want new source ID %d", i, result, i)
		}
		probes := 0
		for ; probes < maxProbe; probes++ {
			if table.index[(hash+uint32(probes))&indexMask] == uint16(i+1) {
				break
			}
		}
		if probes == maxProbe {
			t.Fatalf("source %d not indexed", i)
		}
		probes++
		totalProbes += probes
		maxProbes = max(maxProbes, probes)
	}
	t.Logf("distinct tuples=%d; first hash slot=%d; final insertion probes=%d; total insertion probes=%d",
		MaxSources, firstHash, maxProbes, totalProbes)
	if maxProbes > 64 {
		t.Errorf("adversarial source tuple needs %d probes (target <=64)", maxProbes)
	}
}

func TestReviewCollisionReachableThroughLiveAnalysis(t *testing.T) {
	// Given: an active request analysis and distinct source names and values.
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	if !ok {
		t.Fatal("failed to acquire request analysis")
	}
	defer analysis.Finish()
	joined := "aa" + strings.Repeat("\x00aa", MaxSources)

	// When: a request submits tuples that differ only in where the NUL splits them.
	for i := 0; i < MaxSources; i++ {
		separator := 2 + 3*i
		name, value := joined[:separator], joined[separator+1:]
		parsed, err := url.ParseQuery(url.QueryEscape(name) + "=" + url.QueryEscape(value))
		if err != nil || parsed.Get(name) != value {
			t.Fatalf("source %d cannot be represented as a URL query: %v", i, err)
		}
		_, admitted := analysis.ManageString(
			constants.OriginHttpRequestParameter,
			name, value,
		)
		if !admitted {
			t.Fatalf("source %d rejected by live analysis", i)
		}
	}

	// Then: the vulnerable table path is reachable without bypassing admission.
	if got := analysis.SourceCount(); got != MaxSources {
		t.Fatalf("live analysis admitted %d sources, want %d", got, MaxSources)
	}
	t.Logf("live request admitted all %d colliding sources", analysis.SourceCount())
}
