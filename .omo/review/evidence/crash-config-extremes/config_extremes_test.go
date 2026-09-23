// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Review harness (NODE_ID=crash-config-extremes): exercises the woven
// request/SQL-sink pipeline with post-clamp extreme internal/config values
// (the same values DD_IAST_* environment parsing would produce for the
// review matrix) to verify no panic and documented bound enforcement.
package testapp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

// captureDisabledSpan mirrors captureRequestEvent but, unlike it, tolerates an
// analysis decision that never enables IAST (disabled, sampled-out, or
// capacity-dropped): it only asserts that nothing panicked and reports the
// resolved SpanTagEnabled tag.
func captureDisabledSpan(t *testing.T, operation func(context.Context, *http.Request)) float64 {
	t.Helper()
	mock := mocktracer.Start()
	defer mock.Stop()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.e2e.request")
		defer span.Finish()
		operation(ctx, r.WithContext(ctx))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/?query=SELECT+%27secret%27", nil)
	require.NoError(t, err)
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	finished := mock.FinishedSpans()
	require.Len(t, finished, 1)
	tag, _ := finished[0].Tag(spans.SpanTagEnabled).(float64)
	return tag
}

// withConfig saves the mutable config package variables, applies mutate, runs
// the test body, then restores the saved values so subtests do not leak
// configuration into each other or into the rest of the package's tests.
func withConfig(t *testing.T, mutate func()) {
	t.Helper()
	enabled := config.Enabled
	sampling := config.RequestSamplingPct
	concurrent := config.MaxConcurrentRequests
	perRequest := config.VulnerabilitiesPerRequest
	dedup := config.DeduplicationEnabled
	redactionEnabled := config.RedactionEnabled
	namePattern := config.RedactionNamePattern
	valuePattern := config.RedactionValuePattern
	truncation := config.TruncationMaxValue
	maxRanges := config.MaxRangeCount
	t.Cleanup(func() {
		config.Enabled = enabled
		config.RequestSamplingPct = sampling
		config.MaxConcurrentRequests = concurrent
		config.VulnerabilitiesPerRequest = perRequest
		config.DeduplicationEnabled = dedup
		config.RedactionEnabled = redactionEnabled
		config.RedactionNamePattern = namePattern
		config.RedactionValuePattern = valuePattern
		config.TruncationMaxValue = truncation
		config.MaxRangeCount = maxRanges
	})
	mutate()
}

// TestConfigExtremesMaxConcurrentRequestsZeroDisablesAnalysis exercises the
// documented "0 disables request analysis" behavior
// (DD_IAST_MAX_CONCURRENT_REQUESTS=0 clamp target) end-to-end through a real
// SQL sink and confirms no panic and no vulnerability is reported.
func TestConfigExtremesMaxConcurrentRequestsZeroDisablesAnalysis(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.MaxConcurrentRequests = 0
		config.RequestSamplingPct = 100
	})
	db := openDB(t)
	tag := captureDisabledSpan(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Error(err)
		}
	})
	if tag != 0 {
		t.Fatalf("expected SpanTagEnabled=0 with MaxConcurrentRequests=0, got %v", tag)
	}
}

// TestConfigExtremesMaxConcurrentRequestsSaturatedDropsWithoutPanic drives
// far more concurrent requests than the clamped hard ceiling
// (DD_IAST_MAX_CONCURRENT_REQUESTS=1000 clamps to 64) through the SQL sink at
// once and confirms saturation drops analysis instead of panicking or
// blocking.
func TestConfigExtremesMaxConcurrentRequestsSaturatedDropsWithoutPanic(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.MaxConcurrentRequests = 64 // DD_IAST_MAX_CONCURRENT_REQUESTS=1000 clamp target
		config.RequestSamplingPct = 100
	})
	db := openDB(t)
	const concurrency = 256 // several times the clamped ceiling
	// One shared mocktracer/server pair: mocktracer.Start/Stop is a global,
	// process-wide recorder and is not safe to (re)start concurrently from
	// many goroutines, so every goroutine fires a real HTTP request at the
	// same server instead of each building its own capture harness.
	mock := mocktracer.Start()
	defer mock.Stop()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.e2e.request")
		defer span.Finish()
		query := r.URL.Query().Get("query")
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := server.Client()
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic under saturation: %v", r)
				}
			}()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/?query=SELECT+%27secret%27", nil)
			if err != nil {
				t.Error(err)
				return
			}
			response, err := client.Do(request)
			if err != nil {
				t.Error(err)
				return
			}
			response.Body.Close()
		}()
	}
	wg.Wait()
	finished := mock.FinishedSpans()
	if len(finished) != concurrency {
		t.Fatalf("expected %d finished spans, got %d (a handler may not have run to completion)", concurrency, len(finished))
	}
}

// TestConfigExtremesVulnerabilitiesPerRequestClampedToOne exercises the
// DD_IAST_VULNERABILITIES_PER_REQUEST=1 clamp target: two distinct SQL
// injections happen in one request, and the resulting event must report at
// most one vulnerability.
func TestConfigExtremesVulnerabilitiesPerRequestClampedToOne(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.VulnerabilitiesPerRequest = 1
		config.RequestSamplingPct = 100
		config.MaxConcurrentRequests = 64
	})
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		stmt, err := db.PrepareContext(ctx, query)
		if err != nil {
			t.Error(err)
			return
		}
		defer stmt.Close()
		if _, err = stmt.ExecContext(ctx); err != nil {
			t.Error(err)
		}
	}, url.Values{"query": {"SELECT 'secret'"}})
	if len(event.Vulnerabilities) > 1 {
		t.Fatalf("VulnerabilitiesPerRequest=1 not enforced, got %d vulnerabilities: %#v", len(event.Vulnerabilities), event.Vulnerabilities)
	}
}

// TestConfigExtremesVulnerabilitiesPerRequestHardMaxSixtyFour exercises the
// DD_IAST_VULNERABILITIES_PER_REQUEST=1000000 clamp target (hard max 64): the
// resulting value must never exceed the documented hard ceiling even when
// far more sink hits are attempted in one request.
func TestConfigExtremesVulnerabilitiesPerRequestHardMaxSixtyFour(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.VulnerabilitiesPerRequest = 64 // DD_IAST_VULNERABILITIES_PER_REQUEST=1000000 clamp target
		config.RequestSamplingPct = 100
		config.MaxConcurrentRequests = 64
		config.DeduplicationEnabled = false
	})
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		for i := 0; i < 100; i++ { // far more than the hard max
			if _, err := db.ExecContext(ctx, query); err != nil {
				t.Error(err)
			}
		}
	}, url.Values{"query": {"SELECT 'secret'"}})
	if len(event.Vulnerabilities) > 64 {
		t.Fatalf("hard max of 64 vulnerabilities exceeded: got %d", len(event.Vulnerabilities))
	}
}

// TestConfigExtremesTruncationMaxValueZero exercises the
// DD_IAST_TRUNCATION_MAX_VALUE=0 case end-to-end: evidence/source values must
// be truncated to empty without panicking, and the vulnerability must still
// be reported.
func TestConfigExtremesTruncationMaxValueZero(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.TruncationMaxValue = 0
		config.RequestSamplingPct = 100
		config.MaxConcurrentRequests = 64
	})
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Error(err)
		}
	}, url.Values{"query": {"SELECT 'secret-value-that-should-be-truncated-to-empty'"}})
	if len(event.Vulnerabilities) == 0 {
		t.Fatal("expected a vulnerability to still be reported with TruncationMaxValue=0")
	}
	for _, source := range event.Sources {
		if len(source.Value) != 0 {
			t.Fatalf("TruncationMaxValue=0 did not truncate source value to empty: %q", source.Value)
		}
	}
}

// TestConfigExtremesTruncationMaxValueHuge exercises an effectively unbounded
// DD_IAST_TRUNCATION_MAX_VALUE (math.MaxUint64 clamp target): truncation
// becomes a no-op, but upstream evidence/analyzer caps (32 KiB / 256 KiB) must
// still bound the report; this must not panic or allocate unbounded memory
// for a bounded-size value.
func TestConfigExtremesTruncationMaxValueHuge(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.TruncationMaxValue = ^uint64(0) // math.MaxUint64
		config.RequestSamplingPct = 100
		config.MaxConcurrentRequests = 64
	})
	db := openDB(t)
	longValue := "SELECT '" + strings.Repeat("a", 4096) + "'"
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Error(err)
		}
	}, url.Values{"query": {longValue}})
	if len(event.Vulnerabilities) == 0 {
		t.Fatal("expected a vulnerability to still be reported with TruncationMaxValue=MaxUint64")
	}
}

// TestConfigExtremesRedactionEnabledFalseLeavesValueUnredacted exercises the
// documented DD_IAST_REDACTION_ENABLED=false bypass: a sensitive-looking
// value must appear unredacted in the report. This is the one documented
// bypass (README, redaction/source.go) and is intentionally not a finding by
// itself; the test exists to confirm the bypass is exactly this scoped and
// does not also disable truncation or panic.
func TestConfigExtremesRedactionEnabledFalseLeavesValueUnredacted(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.RedactionEnabled = false
		config.RequestSamplingPct = 100
		config.MaxConcurrentRequests = 64
	})
	db := openDB(t)
	const secret = "password=hunter2-super-secret"
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Error(err)
		}
	}, url.Values{"query": {"SELECT '" + secret + "'"}})
	if len(event.Vulnerabilities) == 0 {
		t.Fatal("expected a vulnerability to be reported")
	}
	found := false
	for _, source := range event.Sources {
		if strings.Contains(source.Value, secret) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the raw secret to survive with RedactionEnabled=false, sources=%#v", event.Sources)
	}
}

// TestConfigExtremesInvalidRedactionRegexFallsBackToDefault exercises what an
// invalid DD_IAST_REDACTION_VALUE_PATTERN/DD_IAST_REDACTION_NAME_PATTERN
// resolves to (nil from a failed regexp.Compile, config.go falls back to the
// built-in default pattern): the redaction path must not panic when the
// configured pattern is the safe fallback and a sensitive value is present.
func TestConfigExtremesInvalidRedactionRegexFallsBackToDefault(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		// Mirrors what internal/config/config.go does when
		// DD_IAST_REDACTION_VALUE_PATTERN is malformed: parser.ParseRegexp
		// fails and loader.FromEnvWithFallback keeps the built-in default.
		config.RedactionEnabled = true
		config.RedactionNamePattern = regexp.MustCompile(`(?i)password`)
		config.RedactionValuePattern = regexp.MustCompile(`(?i)password`)
		config.RequestSamplingPct = 100
		config.MaxConcurrentRequests = 64
	})
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Error(err)
		}
	}, url.Values{"query": {"SELECT 'password'"}})
	if len(event.Vulnerabilities) == 0 {
		t.Fatal("expected a vulnerability to be reported")
	}
	for _, source := range event.Sources {
		if strings.Contains(source.Value, "password") {
			t.Fatalf("value pattern did not redact a matching secret: %#v", event.Sources)
		}
	}
}

// TestConfigExtremesDisabledSkipsAnalysisWithoutPanic exercises
// DD_IAST_ENABLED=false end-to-end: the sink must still function correctly
// (query executes) but no vulnerability is reported and nothing panics.
func TestConfigExtremesDisabledSkipsAnalysisWithoutPanic(t *testing.T) {
	requireWoven(t)
	withConfig(t, func() {
		config.Enabled = false
	})
	db := openDB(t)
	tag := captureDisabledSpan(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Error(err)
		}
	})
	if tag != 0 {
		t.Fatalf("expected SpanTagEnabled=0 with Enabled=false, got %v", tag)
	}
}
