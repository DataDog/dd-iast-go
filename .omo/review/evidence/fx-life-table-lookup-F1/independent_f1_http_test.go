// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

type f1HTTPResult struct {
	err                  string
	requestTargetBytes   int
	rawQueryBytes        int
	parsedNames          int
	initialSources       int
	parameterCallbacks   int
	finalSources         int
	initialProbePrefix   int
	finalInsertionProbes int
	totalInsertionProbes int
}

func TestIndependentF1HTTPServerCollision(t *testing.T) {
	// Given: an HTTP request with distinct NUL-shifted query parameter tuples.
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

	for seedIndex := 0; seedIndex < 8; seedIndex++ {
		table := New()
		home := table.hash(constants.OriginHttpRequestParameter, names[0], values[0])
		for i := range tupleCount {
			if got := table.hash(constants.OriginHttpRequestParameter, names[i], values[i]); got != home {
				t.Fatalf("seed %d: tuple %d hashes to %d, want common slot %d", seedIndex, i, got, home)
			}
		}
	}

	observed := make(chan f1HTTPResult, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, incoming *http.Request) {
		result := f1HTTPResult{}
		fail := func(message string) {
			result.err = message
			observed <- result
			http.Error(w, message, http.StatusBadRequest)
		}

		ctx, scope, created := Begin(incoming.Context())
		if !created || scope == nil {
			fail("request scope was not created")
			return
		}
		defer scope.Finish()
		analysis, ok := scope.Analysis()
		if !ok {
			fail("request scope has no active analysis")
			return
		}

		// When: request-entry, form-map, and per-value source APIs process it.
		req := incoming.WithContext(ctx)
		req.Header = EagerHTTP(
			ctx, &req.RequestURI, &req.URL.Path, &req.URL.RawQuery,
			req.Header, req.URL, req.Body,
		)
		result.requestTargetBytes = len(req.RequestURI)
		result.rawQueryBytes = len(req.URL.RawQuery)
		if result.rawQueryBytes <= store.MaxRootBytes || result.requestTargetBytes <= store.MaxRootBytes {
			fail(fmt.Sprintf("request target is not oversized: target=%d query=%d", result.requestTargetBytes, result.rawQueryBytes))
			return
		}
		if err := req.ParseForm(); err != nil {
			fail(fmt.Sprintf("parse query form: %v", err))
			return
		}
		result.parsedNames = len(req.Form)
		if result.parsedNames != tupleCount {
			fail(fmt.Sprintf("parsed %d form names, want %d", result.parsedNames, tupleCount))
			return
		}

		result.initialSources = analysis.SourceCount()
		req.Form, req.PostForm = ManageForm(ctx, req.Form, req.PostForm)
		if got := analysis.SourceCount(); got != result.initialSources {
			fail(fmt.Sprintf("large form map admitted sources: before=%d after=%d", result.initialSources, got))
			return
		}
		admitCount := MaxSources - result.initialSources
		if admitCount <= 0 || admitCount > tupleCount {
			fail(fmt.Sprintf("initial source count %d leaves invalid capacity", result.initialSources))
			return
		}

		origin := constants.OriginHttpRequestParameter
		table := &analysis.slot.table
		home := table.hash(origin, names[0], values[0])
		for i := 1; i < admitCount; i++ {
			if got := table.hash(origin, names[i], values[i]); got != home {
				fail(fmt.Sprintf("tuple %d hashes to %d, want common slot %d", i, got, home))
				return
			}
		}
		for result.initialProbePrefix < maxProbe &&
			table.index[(home+uint32(result.initialProbePrefix))&indexMask] != 0 {
			result.initialProbePrefix++
		}
		if result.initialProbePrefix == maxProbe {
			fail("no empty index slot before parameter admission")
			return
		}

		for i := 0; i < admitCount; i++ {
			name, want := names[i], values[i]
			value := req.FormValue(name)
			if value != want {
				fail(fmt.Sprintf("FormValue returned a different value for tuple %d", i))
				return
			}
			if managed := ManageParameter(ctx, name, value); managed != want {
				fail(fmt.Sprintf("parameter callback changed tuple %d value", i))
				return
			}
			id := SourceID(result.initialSources + i)
			if count := analysis.SourceCount(); count != result.initialSources+i+1 {
				fail(fmt.Sprintf("after tuple %d, source count=%d", i, count))
				return
			}
			probes := 0
			for ; probes < maxProbe; probes++ {
				if table.index[(home+uint32(probes))&indexMask] == uint16(id)+1 {
					break
				}
			}
			if probes == maxProbe {
				fail(fmt.Sprintf("tuple %d was not indexed", i))
				return
			}
			probes++
			result.totalInsertionProbes += probes
			result.finalInsertionProbes = probes
			result.parameterCallbacks++

			source, exists := analysis.Source(id)
			if !exists || source.Origin != origin || source.Name != name || source.Value != want {
				fail(fmt.Sprintf("tuple %d did not retain its distinct source identity", i))
				return
			}
		}
		result.finalSources = analysis.SourceCount()
		minimumProbes := result.parameterCallbacks * (result.parameterCallbacks + 1) / 2
		if result.finalSources != MaxSources ||
			result.finalInsertionProbes <= 64 ||
			result.totalInsertionProbes < minimumProbes {
			fail(fmt.Sprintf("final sources=%d probes=%d, want %d sources, final probes >64, total probes >=%d",
				result.finalSources, result.totalInsertionProbes, MaxSources, minimumProbes))
			return
		}
		observed <- result
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = 5 * time.Second
	request, err := http.NewRequest(http.MethodGet, server.URL+"/?"+query.String(), nil)
	if err != nil {
		t.Fatalf("construct HTTP request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send generated HTTP request: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close HTTP response: %v", err)
	}
	result := <-observed
	if result.err != "" {
		t.Fatal(result.err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTP status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}
	t.Logf("accepted HTTP request target bytes=%d; raw query bytes=%d; parsed form names=%d",
		result.requestTargetBytes, result.rawQueryBytes, result.parsedNames)
	t.Logf("initial sources=%d; map-level additions=0; individual FormValue callbacks=%d; final sources=%d",
		result.initialSources, result.parameterCallbacks, result.finalSources)
	t.Logf("prior cluster=%d; final insertion probes=%d; total insertion probes=%d",
		result.initialProbePrefix, result.finalInsertionProbes, result.totalInsertionProbes)
	t.Log("all NUL-shift tuples shared one slot under eight fresh hash seeds")
}
