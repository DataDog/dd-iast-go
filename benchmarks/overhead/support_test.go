// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

// Shared benchmark support. IMPORTANT: these files are in package overhead,
// not overhead_test. The IAST aspects use a root-module package filter, and
// Orchestrion does not match the external test package (its import path is
// outside the module path prefix). Only package overhead (including its
// in-package _test.go files) is woven.
// This file, and the other shared workload files,
// depend only on the stdlib, the public taint package and the dd-trace-go
// mock tracer. The same files are used in the PR #39 tree and in the heapbits
// tree, so the workloads are equal.
//
// Why a real httptest server: the request scope of IAST is created by the
// woven net/http server (serverHandler.ServeHTTP and the tracer span) in both
// trees. A handler that runs behind a real httptest.Server gets exactly the
// same scope that a customer handler gets, with no internal import. The timed
// loop runs inside the handler, so the request is active during the loop. The
// server and the client round trip are set up before the first b.Loop call,
// and b.Loop starts the timer.

import (
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

// envTaintLive selects the "taint live elsewhere" variant: when it is "1", an
// active request holds a tainted value for the whole run of the process, while
// the workloads run. In the heapbits tree the taint gate is then on. The live
// request must be sampled (DD_IAST_REQUEST_SAMPLING=100): in each variant
// other than control (envExpect), the process fails when the live value is
// not tainted.
const (
	envTaintLive = "DD_IAST_BENCH_TAINT_LIVE"
	envExpect    = "DD_IAST_BENCH_EXPECT"
)

var (
	liveValue   string // keeps the tainted value reachable
	liveBytes   []byte
	liveTainted bool
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	flag.Parse()
	// Only a run with benchmarks needs the live request. The variant checks of
	// the runner (TestControlVariant, TestWovenVariant) must see a clean tracer.
	if os.Getenv(envTaintLive) != "1" || flag.Lookup("test.bench").Value.String() == "" {
		return m.Run()
	}
	stop := startTaintLive()
	defer stop()
	if !liveTainted && os.Getenv(envExpect) != "control" {
		os.Stderr.WriteString("taint live elsewhere: FAIL: the live value is NOT tainted; " +
			"use DD_IAST_REQUEST_SAMPLING=100, or set " + envExpect + "=control for the control variant\n")
		return 1
	}
	return m.Run()
}

// startTaintLive opens a request that stays active until stop is called. The
// request reads a parameter (a source) and keeps the tainted value.
func startTaintLive() (stop func()) {
	mt := mocktracer.Start()
	ready := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		liveValue = req.FormValue("live")
		liveBytes = taint.TaintBytes(req.Context(), taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "live-bytes"}, []byte("live-tainted-bytes"))
		liveTainted = taint.IsTaintedString(liveValue) && taint.IsTaintedBytes(liveBytes)
		close(ready)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, err := server.Client().Get(server.URL + "/live?live=attacker-controlled-value")
		if err == nil {
			response.Body.Close()
		}
	}()
	<-ready
	if liveTainted {
		os.Stderr.WriteString("taint live elsewhere: a tainted value is live in an active request\n")
	} else {
		os.Stderr.WriteString("taint live elsewhere: the live value is NOT tainted (correct for the control variant only)\n")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(release)
			<-finished
			server.Close()
			mt.Stop()
		})
	}
}

// runInRequest runs fn inside the handler of a sampled request, through a real
// httptest server, and waits until fn returns. The mock tracer must be started
// by the caller. It uses tb.Error, not tb.Fatal: fn runs in the handler
// goroutine.
func runInRequest(tb testing.TB, target string, fn func(ctx context.Context, req *http.Request)) {
	tb.Helper()
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer close(done)
		fn(req.Context(), req)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	response, err := server.Client().Get(server.URL + target)
	if err != nil {
		tb.Errorf("request failed: %v", err)
		return
	}
	response.Body.Close()
	<-done
}

// benchInRequest is the usual shape of a benchmark that needs an active
// request: it starts a mock tracer, runs the timed loop in a request handler.
func benchInRequest(b *testing.B, target string, fn func(ctx context.Context, req *http.Request)) {
	b.Helper()
	mt := mocktracer.Start()
	defer mt.Stop()
	runInRequest(b, target, fn)
}

// taintedParameter reports whether the "q" parameter of the request is tainted.
func taintedParameter(req *http.Request) bool {
	return taint.IsTaintedString(req.FormValue("q"))
}
