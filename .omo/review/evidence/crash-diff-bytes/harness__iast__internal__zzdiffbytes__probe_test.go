package zzdiffbytes

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

// TestProbeBuilderStaleViewReuse: a Builder reset outside a wrapped call site
// (method value, interface, uninstrumented dependency) leaves writer state whose
// view has no anchor. If the allocator returns the old backing address for the
// rebuilt content with equal len/cap, the wrapped String may publish stale taint.
func TestProbeBuilderStaleViewReuse(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	setupConfig(t)
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("no scope")
	}
	defer scope.Finish()
	src := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, "' OR 1=1 --xxxxx")
	if !taint.IsTaintedString(src) {
		t.Fatal("source not tainted")
	}
	clean := strings.Repeat("c", len(src))
	h := &BldHolder{}
	reuse, fp := 0, 0
	for i := 0; i < 2000; i++ {
		h.B.WriteString(src) // woven: records writer state for view P1
		old := uintptr(unsafe.Pointer(unsafe.SliceData((*bldInternal)(unsafe.Pointer(&h.B)).buf)))
		reset := h.B.Reset // method value: not woven
		reset()
		runtime.GC()
		write := h.B.WriteString // method value: not woven
		write(clean)
		now := h.B.String() // woven: publishes writer state if view matches
		cur := uintptr(unsafe.Pointer(unsafe.SliceData((*bldInternal)(unsafe.Pointer(&h.B)).buf)))
		if cur == old {
			reuse++
		}
		if taint.IsTaintedString(now) {
			fp++
			if fp <= 3 {
				var got []taint.Range
				taint.VisitString(now, func(r taint.Range) bool { got = append(got, r); return true })
				t.Logf("iteration %d: FALSE POSITIVE value=%q (all clean bytes) ranges=%+v backingReused=%v", i, now, got, cur == old)
			}
		}
		h.B.Reset() // woven: clear state for the next iteration
	}
	t.Logf("iterations=2000 backingAddressReused=%d falsePositives=%d", reuse, fp)
	if fp > 0 {
		t.Errorf("stale Builder writer state published on clean content %d times", fp)
	}
}
