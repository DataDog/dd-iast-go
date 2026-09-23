// Review-only reproducer for fx-perf-hotpath-F2 (independent of the finder's).
package propagation_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	hooks "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
)

var f2Sink string

// gatedBuilderWriteString is the hypothetical cheap gate from the proposed
// fix: skip bookkeeping when no writer state exists anywhere and the input is
// not a possible taint hit.
func gatedBuilderWriteString(b *strings.Builder, v string) (int, error) {
	if s := request.ActiveStore(); s == nil || !s.HasWriterStates() {
		if s == nil {
			return b.WriteString(v)
		}
		if key, ok := store.StringKey(v); !ok || !s.MayContain(key) {
			return b.WriteString(v)
		}
	}
	return hooks.BuilderWriteString(b, v)
}

func gatedBufferWriteString(b *bytes.Buffer, v string) (int, error) {
	if s := request.ActiveStore(); s == nil || !s.HasWriterStates() {
		if s == nil {
			return b.WriteString(v)
		}
		if key, ok := store.StringKey(v); !ok || !s.MayContain(key) {
			return b.WriteString(v)
		}
	}
	return hooks.BufferWriteString(b, v)
}

func f2Cases(b *testing.B, value string) {
	// A realistic clean template: a few small writes then String(), all through
	// the woven-equivalent wrappers for the hook variant.
	b.Run("builder/native", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var w strings.Builder
			w.WriteString(value)
			w.WriteString(value)
			w.WriteString(value)
			f2Sink = w.String()
		}
	})
	b.Run("builder/hook", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var w strings.Builder
			hooks.BuilderWriteString(&w, value)
			hooks.BuilderWriteString(&w, value)
			hooks.BuilderWriteString(&w, value)
			f2Sink = hooks.BuilderString(&w)
		}
	})
	b.Run("builder/gated", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var w strings.Builder
			gatedBuilderWriteString(&w, value)
			gatedBuilderWriteString(&w, value)
			gatedBuilderWriteString(&w, value)
			f2Sink = w.String()
		}
	})
	b.Run("buffer/native", func(b *testing.B) {
		b.ReportAllocs()
		var w bytes.Buffer
		for b.Loop() {
			w.Reset()
			w.WriteString(value)
			w.WriteString(value)
			w.WriteString(value)
			f2Sink = w.String()
		}
	})
	b.Run("buffer/hook", func(b *testing.B) {
		b.ReportAllocs()
		var w bytes.Buffer
		for b.Loop() {
			hooks.BufferReset(&w)
			hooks.BufferWriteString(&w, value)
			hooks.BufferWriteString(&w, value)
			hooks.BufferWriteString(&w, value)
			f2Sink = hooks.BufferString(&w)
		}
	})
	b.Run("buffer/gated", func(b *testing.B) {
		b.ReportAllocs()
		var w bytes.Buffer
		for b.Loop() {
			w.Reset()
			gatedBufferWriteString(&w, value)
			gatedBufferWriteString(&w, value)
			gatedBufferWriteString(&w, value)
			f2Sink = w.String()
		}
	})
}

func BenchmarkF2Writer(b *testing.B) {
	const value = "clean-template-fragment-0123456789" // 34 bytes, untainted
	prevE, prevS, prevM := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	defer func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = prevE, prevS, prevM }()

	b.Run("no-owner", func(b *testing.B) { f2Cases(b, value) })

	ctx, created := request.BeginContext(context.Background())
	if !created {
		b.Fatal("no owner")
	}
	if request.ActiveStore() == nil || request.ActiveStore().HasWriterStates() {
		b.Fatal("unexpected store state")
	}
	b.Run("active-clean-1", func(b *testing.B) { f2Cases(b, value) })

	// Owner holds an unrelated tainted value (typical: request parameters tainted).
	_ = taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, strings.Clone("attacker-controlled"))
	b.Run("active-unrelated-taint-1", func(b *testing.B) { f2Cases(b, value) })

	// Default MaxConcurrentRequests is 2: a second concurrent sampled request.
	ctx2, created2 := request.BeginContext(context.Background())
	if !created2 {
		b.Fatal("no second owner")
	}
	b.Run("active-clean-2", func(b *testing.B) { f2Cases(b, value) })

	// A tracked writer somewhere in the process defeats the global gate.
	var tracked strings.Builder
	hooks.BuilderWriteString(&tracked, taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p"}, strings.Clone("tainted-writer")))
	if !request.ActiveStore().HasWriterStates() {
		b.Fatal("tracked writer state not established")
	}
	b.Run("active-tracked-writer-elsewhere", func(b *testing.B) { f2Cases(b, value) })
	request.FinishContext(ctx2, created2)
	request.FinishContext(ctx, created)
}

// TestF2GatedPreservesProvenance checks the proposed gate does not lose taint:
// a tainted write into a fresh builder must still produce a tainted String().
func TestF2GatedPreservesProvenance(t *testing.T) {
	prevE, prevS := config.Enabled, config.RequestSamplingPct
	config.Enabled, config.RequestSamplingPct = true, 100
	defer func() { config.Enabled, config.RequestSamplingPct = prevE, prevS }()
	ctx, created := request.BeginContext(context.Background())
	if !created {
		t.Fatal("no owner")
	}
	defer request.FinishContext(ctx, created)
	tainted := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, strings.Clone("attacker"))
	var w strings.Builder
	gatedBuilderWriteString(&w, "SELECT ")
	gatedBuilderWriteString(&w, tainted)
	out := hooks.BuilderString(&w)
	if !request.IsTaintedString(out) {
		t.Fatalf("gated path lost taint for %q", out)
	}
	t.Logf("gated path kept taint on %q", out)
}
