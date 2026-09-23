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

// Run with: go tool orchestrion go test ./iast/net/http -run TestLifeAdmissionDisconnect -count=1 -v
func TestLifeAdmissionDisconnect(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("reproducer requires Orchestrion instrumentation")
	}
	testConfig(t, 100, 1)
	for _, protocol := range []string{"HTTP1", "HTTP2"} {
		t.Run(protocol, func(t *testing.T) {
			started := make(chan *request.Scope, 1)
			canceled := make(chan struct{}, 1)
			release := make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/held" {
					started <- request.FromContext(req.Context())
					<-req.Context().Done()
					canceled <- struct{}{}
					<-release // A streaming or stalled handler that ignores disconnect.
					return
				}
				scope := request.FromContext(req.Context())
				_, _ = fmt.Fprint(w, scope.Decision())
			})
			var server *httptest.Server
			if protocol == "HTTP2" {
				server = httptest.NewUnstartedServer(handler)
				server.EnableHTTP2 = true
				server.StartTLS()
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			defer close(release)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			held, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/held", nil)
			if err != nil {
				t.Fatal(err)
			}
			client := server.Client()
			result := make(chan error, 1)
			go func() {
				resp, err := client.Do(held)
				if resp != nil {
					resp.Body.Close()
				}
				result <- err
			}()
			select {
			case scope := <-started:
				if scope == nil || !scope.Active() {
					t.Fatal("held request did not acquire a live IAST slot")
				}
				cancel()
				select {
				case <-canceled:
				case <-time.After(5 * time.Second):
					t.Fatal("server did not observe client cancellation")
				}
				if scope.Active() {
					t.Log("disconnected request still owns the single IAST slot")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("held handler did not start")
			}
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("canceled client call did not return")
			}
			probeCtx, stopProbe := context.WithTimeout(context.Background(), 5*time.Second)
			defer stopProbe()
			probe, err := http.NewRequestWithContext(probeCtx, http.MethodGet, server.URL+"/probe", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(probe)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("after disconnect: subsequent request decision=%s (Active=%d, CapacityDropped=%d)", body, request.DecisionActive, request.DecisionCapacityDropped)
			if string(body) != fmt.Sprint(request.DecisionActive) {
				t.Errorf("disconnected request blocks IAST admission for all subsequent requests: got %s, want %d", body, request.DecisionActive)
			}
		})
	}
}
