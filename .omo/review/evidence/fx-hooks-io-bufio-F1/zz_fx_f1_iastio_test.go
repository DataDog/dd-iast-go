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

func TestFxF1PooledReset(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	ctxA, scopeA := activeContext(t)
	bodyA := strings.NewReader("body-of-A")
	request.BindReader(ctxA, bodyA)
	pooled := bufio.NewReader(bodyA)
	a, _ := io.ReadAll(pooled)
	an, _ := scopeA.Analysis()
	before := an.SourceCount()
	pooled.Reset(strings.NewReader("SELECT name FROM constant_table"))
	c, _ := io.ReadAll(pooled)
	an, _ = scopeA.Analysis()
	fresh, _ := io.ReadAll(bufio.NewReader(strings.NewReader("SELECT name FROM constant_table")))
	t.Logf("case=A tainted=%v", taint.IsTaintedBytes(a))
	t.Logf("case=reset-constant tainted=%v ownerA.sources before=%d after=%d", taint.IsTaintedBytes(c), before, an.SourceCount())
	t.Logf("case=fresh-control tainted=%v", taint.IsTaintedBytes(fresh))
}
