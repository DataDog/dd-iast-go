// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package http_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestIndependentLifeAdmissionDisconnect(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("reproducer requires Orchestrion instrumentation")
	}
	testConfig(t, 100, 1)

	started := make(chan *request.Scope, 1)
	canceled := make(chan struct{}, 1)
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/blocked" {
			started <- request.FromContext(req.Context())
			<-req.Context().Done()
			canceled <- struct{}{}
			<-release
			return
		}
		scope := request.FromContext(req.Context())
		if scope == nil {
			http.Error(w, "missing request scope", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprint(w, scope.Decision())
	})
	server := httptest.NewServer(handler)
	client := server.Client()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		close(release)
		server.Close()
	}()

	blocked, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/blocked", nil)
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() {
		resp, err := client.Do(blocked)
		if resp != nil {
			resp.Body.Close()
		}
		clientDone <- err
	}()

	var scope *request.Scope
	select {
	case scope = <-started:
		if scope == nil || !scope.Active() {
			t.Fatal("blocked handler did not acquire an active IAST analysis")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked handler did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not observe request cancellation")
	}
	select {
	case err := <-clientDone:
		if err == nil {
			t.Fatal("canceled client request unexpectedly completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled client call did not return")
	}
	if !scope.Active() {
		t.Fatal("analysis was released before the blocked handler returned")
	}

	resp, err := client.Get(server.URL + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("independent repro: canceled handler still active=%t; next decision=%s (Active=%d, CapacityDropped=%d)", scope.Active(), body, request.DecisionActive, request.DecisionCapacityDropped)
	if string(body) != fmt.Sprint(request.DecisionCapacityDropped) {
		t.Fatalf("probe decision = %s, want %d", body, request.DecisionCapacityDropped)
	}
}
