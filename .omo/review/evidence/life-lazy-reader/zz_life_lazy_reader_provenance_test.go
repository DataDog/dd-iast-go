package io_test

import (
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestReviewMultiReaderDoesNotTaintCleanPrefix(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires instrumented io")
	}
	ctx, _ := activeContext(t)
	clean := strings.NewReader("trusted-")
	dirty := strings.NewReader("attacker")
	if !request.BindReader(ctx, dirty) {
		t.Fatal("failed to bind untrusted reader")
	}
	data, err := io.ReadAll(io.MultiReader(clean, dirty))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "trusted-attacker" {
		t.Fatalf("unexpected result %q", data)
	}
	taint.VisitBytes(data, func(r taint.Range) bool {
		t.Logf("range [%d,%d) origin=%v source=%q", r.Start, r.Start+r.Length, r.Source.Origin, r.Source.Value)
		if r.Start < uint32(len("trusted-")) {
			t.Errorf("trusted prefix attributed to request body: [%d,%d)", r.Start, r.Start+r.Length)
		}
		return true
	})
}
