// Woven end-to-end reproducer for fx-life-owner-scope-F1. Run with:
//   DD_IAST_REQUEST_SAMPLING=100 go tool orchestrion go test ./fxwoven
// The customer-visible observable is taint.IsTaintedString on the request URI,
// which is only true when the server entry advice created a live scope and ran
// EagerHTTP on this dispatch.

package fxwoven

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/taint"
)

func capture(w http.ResponseWriter, r *http.Request) {
	select {
	case stored <- r:
	default:
	}
	if taint.IsTaintedString(r.RequestURI) {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusExpectationFailed)
}

var stored = make(chan *http.Request, 1)

func TestFXWovenRedispatchOfStoredRequestLosesSourceTaint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(capture))
	defer srv.Close()

	resp1, err := http.Get(srv.URL + "/first?q=secret")
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: status %d; expected 200 (URI tainted by server entry advice)", resp1.StatusCode)
	}
	storedReq := <-stored

		deadline := time.Now().Add(5 * time.Second)
	for taint.IsTaintedString(storedReq.RequestURI) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

		rec := httptest.NewRecorder()
	dispatch := http.HandlerFunc(capture)
	dispatch(rec, storedReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-dispatched request: status %d; expected 200 (entry advice should have created a fresh scope and tainted the URI)", rec.Code)
	}

	resp2, err := http.Get(srv.URL + "/second?q=secret")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("control fresh request: status %d; expected 200", resp2.StatusCode)
	}
}
