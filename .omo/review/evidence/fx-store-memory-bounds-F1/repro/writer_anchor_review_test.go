package propagation_test

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"testing"

	testapp "github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

const reviewPayloadSize = 96 << 20

type reviewReadCloser struct {
	*bytes.Reader
}

func (*reviewReadCloser) Close() error { return nil }

type reviewMemory struct {
	heapAlloc uint64
	heapInuse uint64
}

func TestReviewReaderAnchorRetainsCallerAllocation(t *testing.T) {
	ctx, scope := reviewBeginScope(t)
	taintStore := request.ActiveStore()
	require.NotNil(t, taintStore)
	before := reviewMemoryAfterGC()
	chargeBefore := taintStore.ProcessCharged()

	require.True(t, reviewBindReader(ctx, reviewPayloadSize))

	retained := reviewMemoryAfterGC()
	retainedAlloc := reviewDelta(retained.heapAlloc, before.heapAlloc)
	retainedInuse := reviewDelta(retained.heapInuse, before.heapInuse)
	chargeDelta := taintStore.ProcessCharged() - chargeBefore
	fmt.Printf(
		"F1_READER payload_bytes=%d retained_heap_alloc_delta=%d retained_heap_inuse_delta=%d charge_delta=%d\n",
		reviewPayloadSize,
		retainedAlloc,
		retainedInuse,
		chargeDelta,
	)
	require.GreaterOrEqual(t, retainedAlloc, uint64(reviewPayloadSize))
	require.GreaterOrEqual(t, retainedInuse, uint64(reviewPayloadSize))
	require.Zero(t, chargeDelta)

	scope.Finish()
	released := reviewMemoryAfterGC()
	releasedAlloc := reviewDelta(retained.heapAlloc, released.heapAlloc)
	releasedInuse := reviewDelta(retained.heapInuse, released.heapInuse)
	fmt.Printf("F1_READER finish_released_heap_alloc=%d finish_released_heap_inuse=%d\n", releasedAlloc, releasedInuse)
	require.GreaterOrEqual(t, releasedInuse, uint64(reviewPayloadSize-(1<<20)))
}

func TestReviewBufferWriterAnchorRetainsCallerAllocationThroughWovenHook(t *testing.T) {
	require.True(t, built.WithOrchestrion, "run with go tool orchestrion")
	ctx, scope := reviewBeginScope(t)
	uri := "/search?q=untrusted"
	request.EagerHTTP(ctx, &uri, nil, nil, nil, nil, nil)
	require.True(t, taint.IsTaintedString(uri))

	taintStore := request.ActiveStore()
	require.NotNil(t, taintStore)
	before := reviewMemoryAfterGC()
	chargeBefore := taintStore.ProcessCharged()

	written, err, writerCharge := reviewWovenBufferWrite(uri, reviewPayloadSize)
	require.NoError(t, err)
	require.Equal(t, len(uri), written)
	require.Equal(t, int64(64), writerCharge)
	require.True(t, taintStore.HasWriterStates())

	retained := reviewMemoryAfterGC()
	retainedAlloc := reviewDelta(retained.heapAlloc, before.heapAlloc)
	retainedInuse := reviewDelta(retained.heapInuse, before.heapInuse)
	chargeDelta := taintStore.ProcessCharged() - chargeBefore
	fmt.Printf(
		"F1_BUFFER payload_bytes=%d retained_heap_alloc_delta=%d retained_heap_inuse_delta=%d charge_delta=%d writer_charge_delta=%d\n",
		reviewPayloadSize,
		retainedAlloc,
		retainedInuse,
		chargeDelta,
		writerCharge,
	)
	require.GreaterOrEqual(t, retainedAlloc, uint64(reviewPayloadSize))
	require.GreaterOrEqual(t, retainedInuse, uint64(reviewPayloadSize))
	require.Equal(t, int64(64), chargeDelta)

	scope.Finish()
	released := reviewMemoryAfterGC()
	releasedAlloc := reviewDelta(retained.heapAlloc, released.heapAlloc)
	releasedInuse := reviewDelta(retained.heapInuse, released.heapInuse)
	fmt.Printf("F1_BUFFER finish_released_heap_alloc=%d finish_released_heap_inuse=%d\n", releasedAlloc, releasedInuse)
	require.GreaterOrEqual(t, releasedInuse, uint64(reviewPayloadSize-(1<<20)))
}

func reviewBeginScope(t *testing.T) (context.Context, *request.Scope) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 2
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})

	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	require.NotNil(t, scope)
	t.Cleanup(scope.Finish)
	return ctx, scope
}

func reviewBindReader(ctx context.Context, size int) bool {
	backing := make([]byte, size)
	reader := &reviewReadCloser{Reader: bytes.NewReader(backing)}
	request.EagerHTTP(ctx, nil, nil, nil, nil, nil, reader)
	var refs [1]store.OwnerRef
	bound := request.LookupObject(reader, store.BindingReader, refs[:]) == 1
	runtime.KeepAlive(reader)
	return bound
}

func reviewWovenBufferWrite(input string, size int) (int, error, int64) {
	backing := make([]byte, size)
	buffer := bytes.NewBuffer(backing[:0:64])
	taintStore := request.ActiveStore()
	chargeBefore := taintStore.ProcessCharged()
	written, err := testapp.BufferWriteStringTo(buffer, input)
	chargeDelta := taintStore.ProcessCharged() - chargeBefore
	runtime.KeepAlive(backing)
	runtime.KeepAlive(buffer)
	return written, err, chargeDelta
}

func reviewMemoryAfterGC() reviewMemory {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return reviewMemory{heapAlloc: stats.HeapAlloc, heapInuse: stats.HeapInuse}
}

func reviewDelta(after, before uint64) uint64 {
	if after <= before {
		return 0
	}
	return after - before
}
