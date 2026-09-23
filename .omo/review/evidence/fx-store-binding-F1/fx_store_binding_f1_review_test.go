// Reviewer reproducer for store-binding-F1 (fx-store-binding-F1).

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
	"github.com/stretchr/testify/require"
)

// fxAliasBody is a customer-defined body whose FIRST field is a url.URL, so
// &body.URL == body.
type fxAliasBody struct {
	url.URL
	n int
}

func (*fxAliasBody) Read([]byte) (int, error) { return 0, io.EOF }
func (*fxAliasBody) Close() error             { return nil }

type fxObs struct {
	RawQueryTainted   bool `json:"raw_query_tainted"`
	QueryValueTainted bool `json:"query_value_tainted"`
	URLBound          int  `json:"url_bound"`
	BodyBound         int  `json:"body_bound"`
	Aliased           bool `json:"aliased"`
}

// fxEndpoint matches the application.http.Handler fallback join point.
func fxEndpoint(w http.ResponseWriter, req *http.Request) {
	var got fxObs
	var refs [4]store.OwnerRef
	got.URLBound = request.LookupObject(req.URL, store.BindingURL, refs[:])
	got.BodyBound = request.LookupObject(req.Body, store.BindingReader, refs[:])
	if b, ok := req.Body.(*fxAliasBody); ok {
		got.Aliased = uintptr(unsafe.Pointer(b)) == uintptr(unsafe.Pointer(req.URL))
	}
	got.RawQueryTainted = taint.IsTaintedString(req.URL.RawQuery)
	q := req.URL.Query() // woven net/url.URL.Query advice
	if v := q["q"]; len(v) == 1 {
		got.QueryValueTainted = taintedFrom(v[0], taint.OriginHttpRequestParameter)
	}
	_ = json.NewEncoder(w).Encode(got)
}

func fxRun(t *testing.T, req *http.Request) fxObs {
	t.Helper()
	rec := httptest.NewRecorder()
	fxEndpoint(rec, req)
	var got fxObs
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	return got
}

func TestFxURLReaderAlias(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 4)

	// Control 1: same fallback path, same body type, URL NOT aliased.
	ctrl := httptest.NewRequest(http.MethodGet, "/x?q=attack", nil)
	ctrl.Body = &fxAliasBody{}
	c := fxRun(t, ctrl)
	t.Logf("control-fallback-nonaliased: %+v", c)

	// Control 2: real net/http server (serverHandler entry).
	srv := httptest.NewServer(http.HandlerFunc(fxEndpoint))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/x?q=attack")
	require.NoError(t, err)
	var s fxObs
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&s))
	_ = resp.Body.Close()
	t.Logf("control-real-server: %+v", s)

	// Repro: fallback path, req.URL points at the body's embedded first field.
	req := httptest.NewRequest(http.MethodGet, "/x?q=attack", nil)
	body := &fxAliasBody{URL: *req.URL}
	req.URL = &body.URL
	req.Body = body
	a := fxRun(t, req)
	t.Logf("aliased-fallback: %+v", a)

	require.True(t, c.QueryValueTainted, "control lost query taint")
	require.True(t, s.QueryValueTainted, "real server lost query taint")
	require.True(t, a.Aliased)
	require.True(t, a.QueryValueTainted, "URL.Query taint lost when body aliases URL (store-binding-F1)")
}
