package propagation_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func enableIAST(t *testing.T) {
	t.Helper()
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
}

// Customer-shaped code: plain bytes.Buffer calls, woven by orchestrion (no direct propagation.* calls).
func customerHandler(input string) (out string, caught any) {
	defer func() { caught = recover() }()
	var buf bytes.Buffer
	buf.WriteString("SELECT * FROM t WHERE a='")
	buf.WriteString(input) // tracked writer state is created here
	buf.WriteString("'")   // native prepend advice -> Invalidate -> callback -> Store.InvalidateBuffer
	return buf.String(), nil
}

// Same, but the trailing write goes through an io.Writer interface (not a woven direct call):
// no expectation marker, so Store.InvalidateBuffer takes lifecycleMu.RLock + writersMu.
func customerHandlerIface(input string) (out string, caught any) {
	defer func() { caught = recover() }()
	var buf bytes.Buffer
	buf.WriteString("SELECT * FROM t WHERE a='")
	buf.WriteString(input)
	var w io.Writer = &buf
	_, _ = w.Write([]byte("'"))
	return buf.String(), nil
}

func TestFX_F2_Control(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	enableIAST(t)
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("no scope")
	}
	defer scope.Finish()
	in := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, "attack")
	out, caught := customerHandler(in)
	t.Logf("control: out=%q caught=%v tainted=%t", out, caught, taint.IsTaintedString(out))
	if caught != nil || out != "SELECT * FROM t WHERE a='attack'" || !taint.IsTaintedString(out) {
		t.Fatalf("control failed")
	}
}

func runFault(t *testing.T, mode int32, iface bool) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	enableIAST(t)
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("no scope")
	}
	in := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, "attack")
	store.ReviewFault.Store(mode)
	h := customerHandler
	if iface {
		h = customerHandlerIface
	}
	out, caught := h(in)
	store.ReviewFault.Store(0)
	t.Logf("mode=%d iface=%t: out=%q caught=%T %v identical=%t", mode, iface, out, caught, caught, caught == any(store.ReviewFaultValue))
	done := make(chan struct{})
	go func() { scope.Finish(); close(done) }()
	select {
	case <-done:
		t.Logf("mode=%d: scope.Finish returned", mode)
	case <-time.After(3 * time.Second):
		t.Logf("mode=%d: scope.Finish BLOCKED >3s (lifecycleMu RLock leaked by panic)", mode)
	}
	if caught != nil {
		t.Errorf("mode=%d: IAST-internal panic escaped customer bytes.Buffer.WriteString (write aborted, out=%q)", mode, out)
	}
}

func TestFX_F2_FaultBeforeLocks(t *testing.T)      { runFault(t, 1, false) }
func TestFX_F2_FaultInsideLocks(t *testing.T)      { runFault(t, 2, false) }
func TestFX_F2_FaultBeforeLocksIface(t *testing.T) { runFault(t, 1, true) }
func TestFX_F2_FaultInsideLocksIface(t *testing.T) { runFault(t, 2, true) }

// Natural-reachability probe: no fault injection. Concurrent requests hammer the real
// invalidation callback with every Buffer method class, value copies, aliasing/overlapping
// backings, >MaxWriters buffers per owner, and cross-request shared buffers.
func TestFX_F2_NaturalStress(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	enableIAST(t)
	var shared bytes.Buffer
	var sharedMu sync.Mutex
	var wg sync.WaitGroup
	panics := make(chan any, 1024)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics <- r
				}
			}()
			for iter := 0; iter < 300; iter++ {
				ctx, scope, created := request.Begin(context.Background())
				in := fmt.Sprintf("v%d-%d", g, iter)
				if created {
					in = taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, in)
				}
				var bufs [12]bytes.Buffer
				for i := range bufs {
					bufs[i].WriteString(in)
					bufs[i].Grow(64 * i)
					bufs[i].WriteByte('x')
					bufs[i].WriteRune('é')
					bufs[i].Write([]byte(in))
				}
				cp := bufs[0] // value copy sharing backing
				cp.WriteString(in)
				_ = bufs[1].Bytes()
				_ = bufs[2].AvailableBuffer()
				_, _ = bufs[3].Peek(2)
				_ = bufs[4].Next(1)
				_, _ = bufs[5].ReadByte()
				_, _, _ = bufs[5].ReadRune()
				_, _ = bufs[6].ReadString('x')
				_, _ = bufs[6].ReadBytes('x')
				p := make([]byte, 3)
				_, _ = bufs[7].Read(p)
				bufs[8].Truncate(1)
				bufs[9].Reset()
				var sink bytes.Buffer
				_, _ = bufs[10].WriteTo(&sink)
				_, _ = sink.ReadFrom(&bufs[11])
				sharedMu.Lock()
				shared.WriteString(in)
				if shared.Len() > 1<<16 {
					shared.Reset()
				}
				sharedMu.Unlock()
				if iter%2 == 0 && created {
					scope.Finish()
				}
				bufs[0].WriteString("after-finish")
				if iter%2 == 1 && created {
					scope.Finish()
				}
			}
		}(g)
	}
	wg.Wait()
	close(panics)
	n := 0
	for p := range panics {
		n++
		t.Errorf("natural panic: %T %v", p, p)
	}
	t.Logf("natural stress: goroutines=16 iterations=300 panics=%d", n)
}
