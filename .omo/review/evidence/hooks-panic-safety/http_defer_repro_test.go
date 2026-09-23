// Copy to iast/net/http/zz_review_panic_test.go in an isolated repository copy.
package http_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

type reviewPanicReader struct{ value any }

func (r reviewPanicReader) Read([]byte) (int, error) { panic(r.value) }

func TestReview_DeferredSourceAdviceMustNotReplaceHostPanic(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("requires woven stdlib")
	}
	hostFault := &struct{ kind string }{"host Read"}
	internalFault := &struct{ kind string }{"IAST Form"}
	makeRequest := func() *http.Request {
		req, err := http.NewRequestWithContext(context.Background(), "POST", "http://example.test/", io.NopCloser(reviewPanicReader{hostFault}))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	capture := func(req *http.Request) (caught any) {
		defer func() { caught = recover() }()
		_ = req.ParseForm()
		return nil
	}
	if got := capture(makeRequest()); got != hostFault {
		t.Fatalf("baseline host panic: type=%T value=%v", got, got)
	}
	t.Cleanup(func() {
		httpbridge.RegisterLazy(request.ManageForm, request.ManageParameter,
			request.ManageMultipartParameter, request.ManagePathParameter,
			request.ManageCookie, request.ManageMultipart)
	})
	httpbridge.RegisterLazy(
		func(_ context.Context, form, postForm map[string][]string) (map[string][]string, map[string][]string) {
			panic(internalFault)
		},
		request.ManageParameter, request.ManageMultipartParameter,
		request.ManagePathParameter, request.ManageCookie, request.ManageMultipart,
	)
	got := capture(makeRequest())
	if got != hostFault {
		t.Fatalf("host panic replaced: got type=%T value=%v; internal fault identical=%t", got, got, got == internalFault)
	}
}
