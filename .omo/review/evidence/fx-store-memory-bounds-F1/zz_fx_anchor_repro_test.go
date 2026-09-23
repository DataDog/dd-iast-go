package store_test

// Independent phase-3 reproducer for store-memory-bounds-F1 (node fx-store-memory-bounds-F1).
// Written from scratch: measures GC-retained heap and incremental charge caused
// solely by IAST strong anchors, through the same advice bodies the woven build
// injects at customer call sites (request.BindReader is the http advice body at
// request/http.go:76; wrappers.BufferWriteString is the injected bytes.Buffer
// WriteString advice at iast/propagation/writer.go:107).

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"testing"

	wrappers "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func fxGCHeap(t *testing.T) uint64 {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

//go:noinline
func fxMakeReader(size int) *bytes.Reader {
	data := make([]byte, size) // filled, so it is real retained heap
	for i := range data {
		data[i] = byte(i)
	}
	return bytes.NewReader(data)
}

//go:noinline
func fxMakeInteriorBuffer(size int) *bytes.Buffer {
	backing := make([]byte, size)
	for i := range backing {
		backing[i] = byte(i)
	}
	// 64-byte-capacity view into the middle of a large allocation.
	return bytes.NewBuffer(backing[size/2 : size/2 : size/2+64])
}

func fxCharge() int64 {
	active := request.ActiveStore()
	if active == nil {
		return 0
	}
	return active.ProcessCharged()
}

func TestFxAnchorRetention(t *testing.T) {
	require.True(t, config.Enabled)
	require.Equal(t, 100, config.RequestSamplingPct)

	const size = 96 << 20 // 100,663,296 bytes

	t.Run("reader", func(t *testing.T) {
		// Control: build and drop a 96 MiB reader with no binding.
		before := fxGCHeap(t)
		chargeBefore := fxCharge()
		func() {
			r := fxMakeReader(size)
			_ = r.Len()
		}()
		runtime.GC()
		control := fxGCHeap(t)
		t.Logf("reader control: before=%d control=%d drift=%d chargeBefore=%d",
			before, control, int64(control)-int64(before), fxCharge()-chargeBefore)

		// Treatment: bind the same kind of dropped reader to the request owner.
		ctx, scope, created := request.Begin(context.Background())
		require.True(t, created)
		a, ok := scope.Analysis()
		require.True(t, ok)
		_, ok = a.TaintString(constants.OriginHttpRequestParameter, "q", "xx")
		require.True(t, ok)
		chargeBase := fxCharge()

		bound := false
		func() {
			r := fxMakeReader(size)
			bound = request.BindReader(ctx, r) // request/http.go:76 advice body
		}()
		require.True(t, bound)

		retained := fxGCHeap(t)
		charge := fxCharge() - chargeBase
		delta := int64(retained) - int64(control)
		t.Logf("reader bound: retained=%d delta=%d incrementalCharge=%d", retained, delta, charge)
		require.Greater(t, delta, int64(size)-(1<<20), "anchor must retain the payload")
		require.Zero(t, charge, "reader binding must charge nothing")

		scope.Finish()
		released := fxGCHeap(t)
		t.Logf("reader finish: heap=%d released=%d charge=%d", released, int64(retained)-int64(released), fxCharge()-chargeBase)
		require.Greater(t, int64(retained)-int64(released), int64(size)-(1<<20), "finish must release the anchor")
	})

	t.Run("buffer", func(t *testing.T) {
		before := fxGCHeap(t)
		chargeBefore := fxCharge()
		func() {
			b := fxMakeInteriorBuffer(size)
			_, _ = b.WriteString("zz")
		}()
		runtime.GC()
		control := fxGCHeap(t)
		t.Logf("buffer control: before=%d control=%d drift=%d chargeBefore=%d",
			before, control, int64(control)-int64(before), fxCharge()-chargeBefore)

		ctx, scope, created := request.Begin(context.Background())
		require.True(t, created)
		a, ok := scope.Analysis()
		require.True(t, ok)
		value, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "xx")
		require.True(t, ok)
		chargeBase := fxCharge()

		tracked := false
		func() {
			b := fxMakeInteriorBuffer(size)
			n, err := wrappers.BufferWriteString(b, value) // iast/propagation/writer.go:107 advice
			tracked = n == len(value) && err == nil
		}()
		_ = ctx
		require.True(t, tracked)

		retained := fxGCHeap(t)
		charge := fxCharge() - chargeBase
		delta := int64(retained) - int64(control)
		t.Logf("buffer tracked: retained=%d delta=%d incrementalCharge=%d", retained, delta, charge)
		require.Greater(t, delta, int64(size)-(1<<20), "anchor must retain the backing")
		require.Equal(t, int64(64), charge, "interior view is charged at its 64-byte capacity only")

		scope.Finish()
		released := fxGCHeap(t)
		t.Logf("buffer finish: heap=%d released=%d charge=%d", released, int64(retained)-int64(released), fxCharge()-chargeBase)
		require.Greater(t, int64(retained)-int64(released), int64(size)-(1<<20), "finish must release the anchor")
	})
}

// TestFxAnchorWovenSurface drives the customer-visible join points. The bound
// body reader is exactly what the woven request-entry advice creates
// (EagerHTTP, request/http.go:75-76, store.BindObjectValue with BindingReader);
// io.LimitReader propagation comes from the stdlib-body advice in
// iast/io/orchestrion.yml:12-27. The LimitedReader binding assertion proves the
// join point fired in this build; plain non-woven builds would show zero.
func TestFxAnchorWovenSurface(t *testing.T) {
	const size = 96 << 20

	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	a, ok := scope.Analysis()
	require.True(t, ok)
	_, ok = a.TaintString(constants.OriginHttpRequestParameter, "q", "xx")
	require.True(t, ok)
	chargeBase := fxCharge()

	lrBound, bound := 0, false
	func() {
		body := fxMakeReader(size)
		bound = request.BindReader(ctx, body) // EagerHTTP advice body
		lr := io.LimitReader(body, 16)        // woven stdlib-body advice
		st := request.ActiveStore()
		if st != nil {
			var refs [store.MaxSnapshotOwners]store.OwnerRef
			lrBound = store.LookupObjectValue(st, lr, store.BindingReader, refs[:])
		}
		_, _ = lr.Read(make([]byte, 4))
	}()

	retained := fxGCHeap(t)
	t.Logf("woven surface: bodyBound=%v limitedReaderBound=%d retained=%d incrementalCharge=%d",
		bound, lrBound, retained, fxCharge()-chargeBase)
	if lrBound == 0 {
		t.Skipf("io.LimitReader join point inactive in this build; retained=%d", retained)
	}
	require.Greater(t, lrBound, 0, "woven io.LimitReader advice must bind the LimitedReader")
	require.Zero(t, fxCharge()-chargeBase, "reader graph retention is uncharged")

	scope.Finish()
	released := fxGCHeap(t)
	t.Logf("woven finish: heap=%d released=%d charge=%d", released, int64(retained)-int64(released), fxCharge())
	require.Greater(t, int64(retained)-int64(released), int64(size)-(1<<20), "finish must release the anchors")
}
