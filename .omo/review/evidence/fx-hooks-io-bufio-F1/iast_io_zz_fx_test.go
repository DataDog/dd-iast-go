package io_test

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestFXResetKeepsStaleOwner(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	ctxA, scopeA := activeContext(t)
	_, scopeB := activeContext(t)
	body := strings.NewReader("request-body-A")
	request.BindReader(ctxA, body)
	br := bufio.NewReader(body)
	_, _ = io.ReadAll(br)
	a, _ := scopeA.Analysis()
	before := a.SourceCount()
	br.Reset(strings.NewReader("SELECT 1 FROM clean_constant"))
	clean, _ := io.ReadAll(br)
	a, _ = scopeA.Analysis()
	b, _ := scopeB.Analysis()
	t.Logf("fx case=reset-while-owner-active tainted=%v ownerA.sources %d->%d ownerB.sources=%d", taint.IsTaintedBytes(clean), before, a.SourceCount(), b.SourceCount())
	scopeA.Finish()
	br.Reset(strings.NewReader("SELECT 2 FROM clean_constant"))
	afterFinish, _ := io.ReadAll(br)
	t.Logf("fx case=reset-after-owner-finish tainted=%v", taint.IsTaintedBytes(afterFinish))
}
