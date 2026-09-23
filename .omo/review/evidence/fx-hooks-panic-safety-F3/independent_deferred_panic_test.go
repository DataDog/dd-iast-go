// Copy to iast/net/http/zz_f3_independent_test.go in an isolated repository copy.
package http_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

type independentPanicBody struct{ fault any }

func (body independentPanicBody) Read([]byte) (int, error) { panic(body.fault) }

func recoverParseForm(req *http.Request) (fault any) {
	defer func() { fault = recover() }()
	_ = req.ParseForm()
	return nil
}

func newPanickingFormRequest(t *testing.T, ctx context.Context, fault any) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://example.test/form",
		io.NopCloser(independentPanicBody{fault: fault}),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = -1
	return req
}

func Test_RequestParseForm_preserves_body_panic_when_deferred_IAST_callback_fails(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("requires a woven build")
	}
	enabled := config.Enabled
	sampling := config.RequestSamplingPct
	maxConcurrent := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	t.Cleanup(func() {
		config.Enabled = enabled
		config.RequestSamplingPct = sampling
		config.MaxConcurrentRequests = maxConcurrent
	})
	ctx, _, created := request.Begin(context.Background())
	if !created || !request.FromContext(ctx).Active() {
		t.Fatal("could not establish an active IAST request scope")
	}
	t.Cleanup(func() { request.FinishContext(ctx, created) })

	hostFault := &struct{ origin string }{origin: "customer Body.Read"}
	if got := recoverParseForm(newPanickingFormRequest(t, ctx, hostFault)); got != hostFault {
		t.Fatalf("control changed host panic: got=%T %v", got, got)
	}
	t.Log("control retained the exact customer panic pointer with the registered callback")

	iastFault := &struct{ origin string }{origin: "IAST deferred Form"}
	httpbridge.RegisterLazy(
		func(context.Context, map[string][]string, map[string][]string) (map[string][]string, map[string][]string) {
			panic(iastFault)
		},
		request.ManageParameter,
		request.ManageMultipartParameter,
		request.ManagePathParameter,
		request.ManageCookie,
		request.ManageMultipart,
	)
	t.Cleanup(func() {
		httpbridge.RegisterLazy(
			request.ManageForm,
			request.ManageParameter,
			request.ManageMultipartParameter,
			request.ManagePathParameter,
			request.ManageCookie,
			request.ManageMultipart,
		)
	})

	got := recoverParseForm(newPanickingFormRequest(t, ctx, hostFault))
	if got != hostFault {
		t.Fatalf(
			"deferred IAST callback masked customer panic: got=%T %v; gotIAST=%t",
			got,
			fmt.Sprint(got),
			got == iastFault,
		)
	}
}
