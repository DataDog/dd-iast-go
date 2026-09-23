package http_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestReviewRepeatedMultipartParseDoesNotWriteForm(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires instrumented net/http")
	}
	testConfig(t, 100, 1)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("field", "attacker-input"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx, scope, created := request.Begin(req.Context())
	if !created {
		t.Fatal("scope not created")
	}
	defer scope.Finish()
	req = req.WithContext(ctx)
	if err := req.ParseMultipartForm(1024); err != nil {
		t.Fatal(err)
	}
	if len(req.Form["field"]) != 1 {
		t.Fatalf("unexpected form: %#v", req.Form)
	}
	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-start
		for range 1000 {
			_ = req.Form["field"][0]
		}
	}()
	close(start)
	for range 1000 {
		if err := req.ParseMultipartForm(1024); err != nil {
			t.Error(err)
			break
		}
	}
	<-done
}
