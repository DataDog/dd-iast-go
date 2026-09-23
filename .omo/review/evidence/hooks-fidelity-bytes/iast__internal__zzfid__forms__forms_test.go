package forms

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

// TestForms prints a deterministic transcript that must be byte-identical
// between `go test` (unwoven) and `go tool orchestrion go test` (woven).
func TestForms(t *testing.T) {
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	defer func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm }()
	t.Logf("woven=%v", built.WithOrchestrion)
	var transcript []string
	for _, active := range []bool{false, true} {
		in, inb := "a tt=ck\u00e9 ", []byte("By=tes ")
		var scope *request.Scope
		if active {
			ctx, s, ok := request.Begin(context.Background())
			if !ok {
				t.Fatal("no scope")
			}
			scope = s
			in = taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, in)
			inb = taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "b"}, inb)
			if !taint.IsTaintedString(in) || !taint.IsTaintedBytes(inb) {
				t.Fatal("inputs not tainted")
			}
		}
		Log = nil
		s, l, c := BuilderForms(in, inb)
		transcript = append(transcript, fmt.Sprintf("active=%v builder=%q len=%d cap=%d log=%v", active, s, l, c, Log))
		Log = nil
		bs, st := BufferForms(in, inb)
		transcript = append(transcript, fmt.Sprintf("active=%v buffer=%q st=%q log=%v", active, bs, st, Log))
		transcript = append(transcript, fmt.Sprintf("active=%v bytes=%q", active, BytesForms(inb)))
		if active {
			// Record whether propagation happened (woven only); not part of the fidelity transcript.
			t.Logf("builder result tainted=%v buffer result tainted=%v", taint.IsTaintedString(s), taint.IsTaintedString(bs))
			scope.Finish()
		}
	}
	t.Logf("TRANSCRIPT-BEGIN\n%s\nTRANSCRIPT-END", strings.Join(transcript, "\n"))
}
