// Review reproducer for fx-store-binding-F1 (woven, direct dispatch fallback).
package http_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

// fxAliasBody is a customer body reader whose first field is the request URL.
type fxAliasBody struct {
	url.URL
	n int
}

func (*fxAliasBody) Read([]byte) (int, error) { return 0, io.EOF }
func (*fxAliasBody) Close() error             { return nil }

type fxObs struct {
	Aliased      bool `json:"aliased"`
	Active       bool `json:"active"`
	URLBound     int  `json:"url_bound"`
	BodyBound    int  `json:"body_bound"`
	QueryTainted bool `json:"query_tainted"`
}

func fxQueryEndpoint(w http.ResponseWriter, req *http.Request) {
	got := fxObs{}
	if s := request.FromContext(req.Context()); s != nil {
		got.Active = s.Active()
	}
	if v, ok := req.Body.(interface{ Read([]byte) (int, error) }); ok && req.URL != nil {
		got.Aliased = uintptr(unsafe.Pointer(req.URL)) == reflectPtr(v)
	}
	var refs [1]store.OwnerRef
	got.URLBound = request.LookupObject(req.URL, store.BindingURL, refs[:])
	got.BodyBound = request.LookupObject(req.Body, store.BindingReader, refs[:])
	got.QueryTainted = taintedFrom(req.URL.Query().Get("q"), taint.OriginHttpRequestParameter)
	_ = json.NewEncoder(w).Encode(got)
}

func reflectPtr(v any) uintptr {
	type iface struct{ _, data unsafe.Pointer }
	return uintptr((*iface)(unsafe.Pointer(&v)).data)
}

func fxDo(t *testing.T, req *http.Request) fxObs {
	rec := httptest.NewRecorder()
	fxQueryEndpoint(rec, req)
	var got fxObs
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestFxURLReaderAliasWoven(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	testConfig(t, 100, 4)

	control := fxDo(t, httptest.NewRequest(http.MethodGet, "/x?q=attacker", nil))
	t.Logf("control (httptest.NewRequest):   %+v", control)

	req := httptest.NewRequest(http.MethodGet, "/x?q=attacker", nil)
	body := &fxAliasBody{URL: *req.URL}
	req.URL, req.Body = &body.URL, body
	aliased := fxDo(t, req)
	t.Logf("aliased (URL embedded in Body): %+v", aliased)

	server := httptest.NewServer(http.HandlerFunc(fxQueryEndpoint))
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/x?q=attacker")
	if err != nil {
		t.Fatal(err)
	}
	var real fxObs
	_ = json.NewDecoder(resp.Body).Decode(&real)
	resp.Body.Close()
	t.Logf("real net/http server:           %+v", real)

	if !control.QueryTainted || !real.QueryTainted {
		t.Fatal("control lost taint; reproducer invalid")
	}
	if !aliased.QueryTainted {
		t.Errorf("FINDING: URL.Query taint lost when Body embeds URL at offset 0 (url_bound=%d body_bound=%d)", aliased.URLBound, aliased.BodyBound)
	}
}
