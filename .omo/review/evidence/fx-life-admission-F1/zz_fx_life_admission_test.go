// Phase-3 verification reproducer for life-admission-F1.
// Run with: GOTOOLCHAIN=go1.26.6 go tool orchestrion go test ./iast/net/http -run TestFxDisconnectSlotRetention -count=1 -v -timeout 4m
package http_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

// fxConfig pins IAST to 100% sampling with a single concurrent-analysis slot,
// by mutating the package config the same way the in-repo test helper does.
func fxConfig(t *testing.T, sampling, maxConcurrent int) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = sampling
	config.MaxConcurrentRequests = maxConcurrent
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
}

// fxHeldServer starts a server whose /held handler blocks after observing the
// request-context cancellation (i.e. after the server KNOWS the client is
// gone), simulating a streaming/long-polling handler that ignores disconnects.
func fxHeldServer(t *testing.T, http2 bool) (url string, client *http.Client, observed <-chan *request.Scope, release func()) {
	t.Helper()
	started := make(chan *request.Scope, 1)
	stop := make(chan struct{})
	releaseCh := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/held" {
			scope := request.FromContext(req.Context())
			started <- scope
			select {
			case <-req.Context().Done(): // server observed the disconnect
			case <-time.After(10 * time.Second):
			}
			<-releaseCh // handler stays in ServeHTTP after the disconnect
			return
		}
		scope := request.FromContext(req.Context())
		fmt.Fprint(w, scope.Decision())
	})
	var server *httptest.Server
	if http2 {
		server = httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(releaseCh) })
	t.Cleanup(func() { close(stop) })
	return server.URL, server.Client(), started, func() {}
}

func fxProbeDecision(t *testing.T, client *http.Client, url string) request.Decision {
	t.Helper()
	probeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url+"/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var d request.Decision
	fmt.Sscanf(string(body), "%d", &d)
	return d
}

func TestFxDisconnectSlotRetention(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("reproducer requires Orchestrion instrumentation")
	}
	fxConfig(t, 100, 1)
	t.Run("HTTP1-raw-socket-disconnect", func(t *testing.T) {
		url, _, started, _ := fxHeldServer(t, false)
		// Real client: raw TCP socket closed immediately after the request.
		var d net.Dialer
		conn, derr := d.DialContext(context.Background(), "tcp", url[len("http://"):])
		if derr != nil {
			t.Fatal(derr)
		}
		reqStr := "GET /held HTTP/1.1\r\nHost: " + url[len("http://"):] + "\r\nUser-Agent: fx-repro\r\n\r\n"
		if _, werr := conn.Write([]byte(reqStr)); werr != nil {
			t.Fatal(werr)
		}
		_ = conn.Close() // hard disconnect; server must cancel the request context
		var scope *request.Scope
		select {
		case ch := <-started:
			scope = ch
		case <-time.After(5 * time.Second):
			t.Fatal("held handler did not start")
		}
		// The handler blocks in <-req.Context().Done() first, so by the time
		// "started" fires we then wait for it to observe the cancellation.
		time.Sleep(500 * time.Millisecond)
		if scope == nil || !scope.Active() {
			t.Fatal("held request did not start with a live IAST slot")
		}
		time.Sleep(500 * time.Millisecond)
		if scope.Active() {
			t.Logf("CONFIRM-SIGNAL: after raw-socket disconnect was observed server-side, scope still Active (holds the only slot)")
		} else {
			t.Log("scope released on disconnect")
		}
		d2 := fxProbeDecision(t, http.DefaultClient, url)
		t.Logf("probe decision after disconnect = %d (Disabled=%d SampledOut=%d CapacityDropped=%d Active=%d)",
			d2, request.DecisionDisabled, request.DecisionSampledOut, request.DecisionCapacityDropped, request.DecisionActive)
		if d2 != request.DecisionActive {
			t.Errorf("FAIL-SIGNAL: disconnected request retains the slot; subsequent request capacity-dropped (got %d, want %d)", d2, request.DecisionActive)
		}
	})
	t.Run("HTTP2-cancel", func(t *testing.T) {
		url, client, started, _ := fxHeldServer(t, true)
		ctx, cancel := context.WithCancel(context.Background())
		hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/held", nil)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{}, 1)
		go func() {
			resp, rerr := client.Do(hreq)
			if rerr != nil {
				t.Log("client.Do error (expected on cancel):", rerr)
			}
			if resp != nil {
				resp.Body.Close()
			}
			done <- struct{}{}
		}()
		var scope *request.Scope
		select {
		case scope = <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("held handler did not start")
		}
		if scope == nil || !scope.Active() {
			t.Fatal("held request did not start with a live IAST slot")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("canceled client call did not return")
		}
		time.Sleep(500 * time.Millisecond)
		if scope.Active() {
			t.Logf("CONFIRM-SIGNAL: after client cancel (HTTP/2), scope still Active")
		} else {
			t.Log("scope released on cancel")
		}
		d2 := fxProbeDecision(t, client, url)
		t.Logf("probe decision after cancel = %d", d2)
		if d2 != request.DecisionActive {
			t.Errorf("FAIL-SIGNAL: disconnected request retains the slot; subsequent request capacity-dropped (got %d, want %d)", d2, request.DecisionActive)
		}
	})
}
