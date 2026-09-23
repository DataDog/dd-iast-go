package propagation_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

// FX-F1 woven-surface reproducer, built with `go tool orchestrion go test`
// so the real woven join points (direct strings.Builder/bytes.Buffer
// replacements and the native buffer invalidation hook) are active. Plain
// stdlib calls only: this is what customer code looks like. Request B
// rebuilds a tainted string with a strings.Builder; request A concurrently
// writes clean data into its own bytes.Buffer. FX_F1_NO_A=1 is the control.
func TestFxF1WovenBuilderTaintWipedByUnrelatedBuffer(t *testing.T) {
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})

	ctxB, scopeB, created := request.Begin(context.Background())
	if !created {
		t.Fatal("expected request B scope")
	}
	t.Cleanup(scopeB.Finish)
	taintedB := taint.TaintString(ctxB, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, "attacker-input-value")

	if os.Getenv("FX_F1_NO_A") == "" {
		ctxA, scopeA, created := request.Begin(context.Background())
		if !created {
			t.Fatal("expected request A scope")
		}
		t.Cleanup(scopeA.Finish)
		_ = taint.TaintString(ctxA, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p"}, "unused")
	}

	var stop atomic.Bool
	var aWrites atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if os.Getenv("FX_F1_NO_A") != "" {
			return
		}
		var buf bytes.Buffer
		for !stop.Load() {
			buf.WriteString("clean-")
			if buf.Len() > 1024 {
				buf.Reset()
			}
			aWrites.Add(1)
		}
	}()

	const ops = 300
	lost := 0
	var b strings.Builder
	for i := 0; i < ops; i++ {
		b.Reset()
		b.WriteString(taintedB)
		for j := 0; j < 40; j++ {
			b.WriteByte('y')
		}
		if !taint.IsTaintedString(b.String()) {
			lost++
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("FX-F1-WOVEN: ops=%d lost-taint=%d A-unrelated-buffer-writes=%d", ops, lost, aWrites.Load())
	if lost > 0 {
		t.Errorf("BUG: request B lost woven builder taint on %d/%d checks while unrelated request A wrote clean data into its own buffer", lost, ops)
	}
}
