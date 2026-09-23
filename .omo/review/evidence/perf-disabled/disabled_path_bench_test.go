// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

func BenchmarkDisabledServerHook(b *testing.B) {
	setBenchmarkConfig(b, false, 100)
	benchmarkServerHook(b)
}

func BenchmarkSampledOutServerHook(b *testing.B) {
	setBenchmarkConfig(b, true, 0)
	benchmarkServerHook(b)
}

func BenchmarkDisabledApplicationHook(b *testing.B) {
	setBenchmarkConfig(b, false, 100)
	benchmarkApplicationHook(b)
}

func BenchmarkSampledOutApplicationHook(b *testing.B) {
	setBenchmarkConfig(b, true, 0)
	benchmarkApplicationHook(b)
}

func BenchmarkDisabledPropagationGates(b *testing.B) {
	setBenchmarkConfig(b, false, 100)
	benchmarkPropagationGates(b)
}

func BenchmarkSampledOutPropagationGates(b *testing.B) {
	setBenchmarkConfig(b, true, 0)
	benchmarkPropagationGates(b)
}

func setBenchmarkConfig(b *testing.B, enabled bool, sampling int) {
	b.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = enabled
	config.RequestSamplingPct = sampling
	config.MaxConcurrentRequests = 64
	b.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
}

func benchmarkServerHook(b *testing.B) {
	request := hookRequest()
	b.ReportAllocs()
	for b.Loop() {
		runServerHook(request)
	}
}

func benchmarkApplicationHook(b *testing.B) {
	request := hookRequest()
	b.ReportAllocs()
	for b.Loop() {
		runApplicationHook(request)
	}
}

func benchmarkPropagationGates(b *testing.B) {
	b.Run("named-window", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			resultString = propagation.StringsTrimSpace("  clean  ")
		}
	})
	b.Run("operator-slice", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			resultString = propagation.StringSliceBounds("abcdef", 1, 5)
		}
	})
	b.Run("writer-state", func(b *testing.B) {
		var builder strings.Builder
		builder.WriteString("clean")
		b.ReportAllocs()
		for b.Loop() {
			resultString = propagation.BuilderString(&builder)
		}
	})
	b.Run("format-control", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			resultString = fmt.Sprintf("value=%s", "clean")
		}
	})
	b.Run("format-hook", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			resultString = propagation.FmtSprintf("value=%s", "clean")
		}
	})
	b.Run("sequence-control", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for value := range strings.SplitSeq("alpha,beta", ",") {
				resultString = value
			}
		}
	})
	b.Run("sequence-hook", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for value := range propagation.StringsSplitSeq("alpha,beta", ",") {
				resultString = value
			}
		}
	})
}

func hookRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/profile?format=json", nil)
	request.Header.Set("X-Request-ID", "benchmark-request")
	return request
}

func runServerHook(request *http.Request) {
	context, created := httpbridge.Begin(
		request.Context(), request.Method, request.RequestURI, request.Header,
	)
	defer httpbridge.Finish(context, created)
	if created {
		request = request.WithContext(context)
		var path, rawQuery *string
		if request.URL != nil {
			path = &request.URL.Path
			rawQuery = &request.URL.RawQuery
		}
		request.Header = httpbridge.Eager(
			context, &request.RequestURI, path, rawQuery, request.Header, request.URL, request.Body,
		)
	}
}

func runApplicationHook(httpRequest *http.Request) {
	if httpRequest == nil {
		return
	}
	context, created := request.BeginContext(httpRequest.Context())
	defer request.FinishContext(context, created)
	if created {
		httpRequest = httpRequest.WithContext(context)
		var path, rawQuery *string
		if httpRequest.URL != nil {
			path = &httpRequest.URL.Path
			rawQuery = &httpRequest.URL.RawQuery
		}
		httpRequest.Header = request.EagerHTTP(
			context, &httpRequest.RequestURI, path, rawQuery, httpRequest.Header, httpRequest.URL, httpRequest.Body,
		)
	}
	spans.BindScopeContext(context)
}
