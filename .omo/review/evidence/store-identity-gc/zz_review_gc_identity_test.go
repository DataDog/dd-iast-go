// Review reproducers for node store-identity-gc. Not part of the product.
package propagation_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"unsafe"
	"weak"

	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func reviewBegin(t *testing.T) (context.Context, *request.Scope) {
	t.Helper()
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	_, ok := scope.Analysis()
	require.True(t, ok)
	return ctx, scope
}

func singleP(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
}

func strPtr(s string) uintptr { return uintptr(unsafe.Pointer(unsafe.StringData(s))) }
func bytPtr(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

var sink [][]byte // keeps same-size-class neighbours alive so spans stay partial

//go:noinline
func neighbours(size, n int) {
	for i := 0; i < n; i++ {
		sink = append(sink, make([]byte, size))
	}
}

// marchTo allocates noscan objects of size until one lands at target (returned
// as a clean reused allocation) or the budget is spent. All fillers stay alive
// so the allocator advances through free slots.
//
//go:noinline
func marchTo(target uintptr, size, budget int) ([]byte, int) {
	fillers := make([][]byte, 0, budget)
	for i := 0; i < budget; i++ {
		candidate := make([]byte, size)
		if bytPtr(candidate) == target {
			return candidate, i
		}
		fillers = append(fillers, candidate)
	}
	runtime.KeepAlive(fillers)
	return nil, -1
}

//go:noinline
func reviewTaint(ctx context.Context, value string) (uintptr, weak.Pointer[byte]) {
	managed := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"}, value)
	if !taint.IsTaintedString(managed) {
		panic("source not tainted")
	}
	return strPtr(managed), weak.Make(unsafe.StringData(managed))
}

// 1. Store roots: live owner => strong anchor prevents reuse; Finish => root
// collectable; reused address reads clean, including while another request is
// active (and possibly reusing the same owner slot).
func TestReviewStoreAddressReuseAfterFinish(t *testing.T) {
	singleP(t)
	ctxA, scopeA := reviewBegin(t)
	const size = 32
	neighbours(size, 64)
	pointer, anchor := reviewTaint(ctxA, strings.Repeat("A", size))
	neighbours(size, 64)

	runtime.GC()
	runtime.GC()
	require.NotNil(t, anchor.Value(), "live owner must retain root (strong anchor)")
	got, _ := marchTo(pointer, size, 50000)
	require.Nil(t, got, "address reused while owner live")
	t.Logf("owner live: 50000 same-class allocations after GC, root %#x never reused; weak pointer live=%v", pointer, anchor.Value() != nil)

	scopeA.Finish()
	ctxB, scopeB := reviewBegin(t)
	defer scopeB.Finish()
	_, _ = reviewTaint(ctxB, strings.Repeat("B", size))
	runtime.GC()
	runtime.GC()
	require.Nil(t, anchor.Value(), "finished owner must not retain root")
	reused, attempts := marchTo(pointer, size, 50000)
	if reused == nil {
		t.Skip("allocator did not reuse the address")
	}
	copy(reused, strings.Repeat("d", size))
	asString := unsafe.String(unsafe.SliceData(reused), len(reused))
	t.Logf("after Finish (request B active): root collected; address %#x reused after %d allocations; IsTaintedBytes=%v IsTaintedString=%v", pointer, attempts, taint.IsTaintedBytes(reused), taint.IsTaintedString(asString))
	require.False(t, taint.IsTaintedBytes(reused))
	require.False(t, taint.IsTaintedString(asString))
}

// 2. Bytes roots: same contract.
func TestReviewStoreBytesAddressReuseAfterFinish(t *testing.T) {
	singleP(t)
	ctx, scope := reviewBegin(t)
	const size = 48
	neighbours(size, 64)
	managed := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody}, bytes.Repeat([]byte("A"), size))
	require.True(t, taint.IsTaintedBytes(managed))
	pointer := bytPtr(managed)
	anchor := weak.Make(unsafe.SliceData(managed))
	managed = nil
	neighbours(size, 64)
	runtime.GC()
	require.NotNil(t, anchor.Value())
	scope.Finish()
	ctxB, scopeB := reviewBegin(t)
	defer scopeB.Finish()
	_ = taint.TaintBytes(ctxB, taint.Source{Origin: taint.OriginHttpRequestBody}, bytes.Repeat([]byte("B"), size))
	runtime.GC()
	runtime.GC()
	require.Nil(t, anchor.Value())
	reused, attempts := marchTo(pointer, size, 50000)
	if reused == nil {
		t.Skip("allocator did not reuse the address")
	}
	t.Logf("bytes: address %#x reused after %d allocations after Finish, IsTainted=%v", pointer, attempts, taint.IsTaintedBytes(reused))
	require.False(t, taint.IsTaintedBytes(reused))
}

// 3. strings.Builder writer views are keyed by (receiver, data pointer, len,
// cap) with no anchor on the builder's backing array. An indirect reset
// followed by an indirect write lets GC free the tracked backing; a new backing
// at the same address with equal len/cap makes the next direct String() return
// clean content carrying the stale source.
func TestReviewBuilderStaleViewAfterAddressReuse(t *testing.T) {
	for _, mode := range []string{"zero-assign", "method-value-reset"} {
		t.Run(mode, func(t *testing.T) {
			singleP(t)
			ctx, scope := reviewBegin(t)
			defer scope.Finish()
			input := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"}, "attack1234")
			require.True(t, taint.IsTaintedString(input))

			neighbours(16, 64)
			var b strings.Builder
			_, err := propagation.BuilderWriteString(&b, input) // direct, woven call
			require.NoError(t, err)
			neighbours(16, 64)
			raw := b.String()
			pointer, length, capacity := strPtr(raw), b.Len(), b.Cap()
			raw = ""
			first := propagation.BuilderString(&b) // direct, woven call
			require.True(t, taint.IsTaintedString(first), "sanity: direct builder string is tainted")
			first = ""

			switch mode {
			case "zero-assign":
				b = strings.Builder{} // plain assignment: not woven
			default:
				reset := b.Reset // method value: not woven (README)
				reset()
			}
			runtime.GC()
			runtime.GC()
			hit := false
			attempts := 0
			for ; attempts < 50000 && !hit; attempts++ {
				// No GC inside the loop: the dropped buffers stay allocated,
				// so each clean write advances to the next free 16-byte slot.
				b = strings.Builder{}
				_, _ = io.WriteString(&b, "cleanvalue") // interface call inside io: not woven
				hit = strPtr(b.String()) == pointer && b.Len() == length && b.Cap() == capacity
			}
			if !hit {
				t.Skip("allocator did not reuse the address")
			}
			out := propagation.BuilderString(&b) // direct, woven call feeding a sink
			var observed []taint.Range
			taint.VisitString(out, func(r taint.Range) bool { observed = append(observed, r); return true })
			t.Logf("mode=%s: tracked backing %#x (len %d cap %d) freed and reused by clean write after %d writes; BuilderString=%q tainted=%v ranges=%+v", mode, pointer, length, capacity, attempts, out, taint.IsTaintedString(out), observed)
			require.False(t, taint.IsTaintedString(out), "STALE TAINT: clean builder content %q reported with source %+v", out, observed)
		})
	}
}

// 4. Control: bytes.Buffer views carry an Anchor into the backing, so the
// tracked backing cannot be freed while the writer record exists.
func TestReviewBufferAnchorPreventsReuse(t *testing.T) {
	singleP(t)
	ctx, scope := reviewBegin(t)
	defer scope.Finish()
	input := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"}, "attack1234")
	neighbours(64, 64)
	var b bytes.Buffer
	_, err := propagation.BufferWriteString(&b, input)
	require.NoError(t, err)
	neighbours(64, 64)
	pointer := bytPtr(b.Bytes())
	capacity := b.Cap()
	b = bytes.Buffer{}
	runtime.GC()
	runtime.GC()
	got, _ := marchTo(pointer, capacity, 50000)
	require.Nil(t, got, "anchored buffer backing was reused")
	_, _ = io.WriteString(&b, "cleanvalue")
	out := propagation.BufferString(&b)
	require.False(t, taint.IsTaintedString(out))
	t.Logf("bytes.Buffer: tracked backing %#x (cap %d) not reused across 50000 same-class allocations after zero-assign+GC (writer Anchor retains it)", pointer, capacity)
}

// 3b. Same defect without GOMAXPROCS(1) or neighbour shaping: an ordinary
// handler loop that reuses one builder with a zero assignment and fmt.Fprintf.
func TestReviewBuilderStaleViewRealistic(t *testing.T) {
	ctx, scope := reviewBegin(t)
	defer scope.Finish()
	input := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "id"}, "1 OR 1=1--")
	var b strings.Builder
	_, _ = propagation.BuilderWriteString(&b, input) // woven: query built from the tainted id
	_ = propagation.BuilderString(&b)                // woven: first query sent to a sink
	falsePositives, iterations := 0, 0
	for i := 0; i < 20000 && falsePositives == 0; i++ {
		iterations++
		b = strings.Builder{}              // not woven
		fmt.Fprintf(&b, "%s", "SELECT 1;") // not woven; 9 bytes... padded below
		fmt.Fprintf(&b, "%s", "x")         // total 10 bytes, cap 16
		if i%100 == 0 {
			runtime.GC() // stands in for a natural GC cycle
		}
		query := propagation.BuilderString(&b) // woven: second query sent to a sink
		if taint.IsTaintedString(query) {
			falsePositives++
			t.Logf("iteration %d: clean query %q reported tainted", i, query)
		}
	}
	t.Logf("iterations=%d falsePositives=%d", iterations, falsePositives)
	require.Zero(t, falsePositives, "stale builder taint on reused backing")
}

// 3c. Cross-request: a builder shared through a pool/global. Request A writes
// tainted data and is still active; request B reuses the builder with an
// un-woven reset and clean writes; B's direct String() gets A's source.
var sharedBuilder strings.Builder

func TestReviewBuilderStaleViewCrossRequest(t *testing.T) {
	singleP(t)
	ctxA, scopeA := reviewBegin(t)
	defer scopeA.Finish()
	input := taint.TaintString(ctxA, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "reqA"}, "attack1234")
	_, _ = propagation.BuilderWriteString(&sharedBuilder, input)
	raw := sharedBuilder.String()
	pointer, length, capacity := strPtr(raw), sharedBuilder.Len(), sharedBuilder.Cap()
	raw = ""
	_ = propagation.BuilderString(&sharedBuilder)

	_, scopeB := reviewBegin(t) // request B, concurrent with A
	defer scopeB.Finish()
	sharedBuilder = strings.Builder{} // B: un-woven reset (e.g. inside a pool helper)
	runtime.GC()
	runtime.GC()
	hit := false
	attempts := 0
	for ; attempts < 50000 && !hit; attempts++ {
		sharedBuilder = strings.Builder{}
		_, _ = io.WriteString(&sharedBuilder, "cleanvalue")
		hit = strPtr(sharedBuilder.String()) == pointer && sharedBuilder.Len() == length && sharedBuilder.Cap() == capacity
	}
	if !hit {
		t.Skip("allocator did not reuse the address")
	}
	out := propagation.BuilderString(&sharedBuilder) // B: direct call feeding B's sink
	var observed []taint.Range
	taint.VisitString(out, func(r taint.Range) bool { observed = append(observed, r); return true })
	t.Logf("request B: clean %q after %d writes carries source %+v from request A", out, attempts, observed)
	require.False(t, taint.IsTaintedString(out), "CROSS-REQUEST STALE TAINT")
}
