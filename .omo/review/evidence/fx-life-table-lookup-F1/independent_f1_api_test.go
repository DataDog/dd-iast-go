// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestIndependentF1FormValueCollision(t *testing.T) {
	// Given: a sampled request and query fields whose NUL delimiter can move.
	oldEnabled := config.Enabled
	oldSampling := config.RequestSamplingPct
	oldMaxConcurrent := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	t.Cleanup(func() {
		config.Enabled = oldEnabled
		config.RequestSamplingPct = oldSampling
		config.MaxConcurrentRequests = oldMaxConcurrent
	})

	ctx, scope, created := Begin(context.Background())
	if !created {
		t.Fatal("failed to create active request scope")
	}
	t.Cleanup(scope.Finish)
	analysis, ok := scope.Analysis()
	if !ok {
		t.Fatal("active scope has no analysis")
	}

	const tupleCount = MaxSources
	joined := "p" + strings.Repeat("\x00", tupleCount+1) + "ok"
	names := make([]string, tupleCount)
	values := make([]string, tupleCount)
	var query strings.Builder
	for i := range tupleCount {
		separator := i + 1
		names[i], values[i] = joined[:separator], joined[separator+1:]
		if i != 0 {
			query.WriteByte('&')
		}
		query.WriteString(url.QueryEscape(names[i]))
		query.WriteByte('=')
		query.WriteString(url.QueryEscape(values[i]))
	}

	req := httptest.NewRequest("GET", "/?"+query.String(), nil).WithContext(ctx)

	// When: request-entry and form callbacks process the HTTP query.
	req.Header = EagerHTTP(
		ctx, &req.RequestURI, &req.URL.Path, &req.URL.RawQuery,
		req.Header, req.URL, req.Body,
	)
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parse generated query: %v", err)
	}
	if len(req.Form) != tupleCount {
		t.Fatalf("parsed %d form names, want %d", len(req.Form), tupleCount)
	}

	initialCount := analysis.SourceCount()
	req.Form, req.PostForm = ManageForm(ctx, req.Form, req.PostForm)
	if got := analysis.SourceCount(); got != initialCount {
		t.Fatalf("oversized map admitted %d sources, want none", got-initialCount)
	}
	admitCount := MaxSources - initialCount
	if admitCount <= 0 || admitCount > tupleCount {
		t.Fatalf("initial source count=%d leaves invalid capacity", initialCount)
	}

	origin := constants.OriginHttpRequestParameter
	for seedIndex := 0; seedIndex < 8; seedIndex++ {
		table := New()
		home := table.hash(origin, names[0], values[0])
		for i := range tupleCount {
			if got := table.hash(origin, names[i], values[i]); got != home {
				t.Fatalf("seed %d: tuple %d hashes to %d, want common slot %d", seedIndex, i, got, home)
			}
		}
	}

	table := &analysis.slot.table
	home := table.hash(origin, names[0], values[0])
	for i := 1; i < admitCount; i++ {
		if got := table.hash(origin, names[i], values[i]); got != home {
			t.Fatalf("tuple %d hashes to %d, want common slot %d", i, got, home)
		}
	}
	initialPrefix := 0
	for initialPrefix < maxProbe &&
		table.index[(home+uint32(initialPrefix))&indexMask] != 0 {
		initialPrefix++
	}
	if initialPrefix == maxProbe {
		t.Fatal("no empty index slot before parameter admission")
	}

	totalProbes, finalProbes := 0, 0
	for i := 0; i < admitCount; i++ {
		name, want := names[i], values[i]
		got := req.FormValue(name)
		if got != want {
			t.Fatalf("FormValue(%q) returned a different value", name)
		}
		if managed := ManageParameter(ctx, name, got); managed != want {
			t.Fatalf("parameter callback changed tuple %d value", i)
		}

		id := SourceID(initialCount + i)
		if count := analysis.SourceCount(); count != initialCount+i+1 {
			t.Fatalf("after tuple %d, source count=%d, want %d", i, count, initialCount+i+1)
		}
		probes := 0
		for ; probes < maxProbe; probes++ {
			if table.index[(home+uint32(probes))&indexMask] == uint16(id)+1 {
				break
			}
		}
		if probes == maxProbe {
			t.Fatalf("tuple %d was not indexed", i)
		}
		probes++
		totalProbes += probes
		finalProbes = probes

		source, exists := analysis.Source(id)
		if !exists || source.Origin != origin || source.Name != name || source.Value != want {
			t.Fatalf("tuple %d did not retain its distinct source identity", i)
		}
	}

	if got := analysis.SourceCount(); got != MaxSources {
		t.Fatalf("final source count=%d, want capacity %d", got, MaxSources)
	}
	wantTotal := admitCount*(admitCount+1)/2 + initialPrefix*admitCount
	if totalProbes != wantTotal {
		t.Fatalf("total probes=%d, want %d", totalProbes, wantTotal)
	}
	t.Logf("parsed query fields=%d; map-level sources admitted=%d; FormValue callbacks=%d",
		len(req.Form), 0, admitCount)
	t.Logf("initial sources=%d; common hash slot=%d; prior cluster=%d; final insertion probes=%d; total insertion probes=%d",
		initialCount, home, initialPrefix, finalProbes, totalProbes)
	t.Log("all delimiter-shift tuples shared one slot under eight fresh hash seeds")
}
