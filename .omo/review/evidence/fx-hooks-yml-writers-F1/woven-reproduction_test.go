package propagation_test

import (
	"runtime"
	"testing"

	testapp "github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestReviewIndependentWovenBufferAnchorRetainsLargeBacking(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is required for this reproduction")
	}
	input := activeBytes(t, []byte("tainted"))
	require.True(t, taint.IsTaintedBytes(input))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for range store.MaxWriters {
		written, err := testapp.BufferWriteIntoLargeBacking(input)
		require.NoError(t, err)
		require.Equal(t, len(input), written)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	taintStore := request.ActiveStore()
	require.NotNil(t, taintStore)
	charged := taintStore.ProcessCharged()
	writerStates := taintStore.HasWriterStates()
	t.Logf("woven heap increase=%d MiB, process charged=%d bytes, writer states=%t, writer calls=%d", retained>>20, charged, writerStates, store.MaxWriters)
	require.Greater(t, retained, int64(120<<20))
	require.GreaterOrEqual(t, charged, int64(store.MaxWriters*16))
	require.True(t, writerStates)
	runtime.KeepAlive(taintStore)
}
