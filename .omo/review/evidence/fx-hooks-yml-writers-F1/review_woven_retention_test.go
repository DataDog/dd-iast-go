// Independent reproducer copied from the private checkout.
// Run with:
// GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -count=1
// -timeout=5m ./iast/propagation -run TestReviewWovenBufferAnchorRetainsLargeBacking -v

package propagation_test

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestReviewWovenBufferAnchorRetainsLargeBacking(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is required for this reproduction")
	}
	input := activeBytes(t, []byte("tainted"))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for range store.MaxWriters {
		writeTaintedBufferIntoLargeBacking(t, input)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	charged := request.ActiveStore().ProcessCharged()
	t.Logf("retained=%d MiB charged=%d bytes writer-state=%t", retained>>20, charged, request.ActiveStore().HasWriterStates())
	require.Greater(t, retained, int64(120<<20))
	require.Less(t, charged, int64(1<<20))
	require.True(t, request.ActiveStore().HasWriterStates())
}

func writeTaintedBufferIntoLargeBacking(t *testing.T, input []byte) {
	t.Helper()
	backing := make([]byte, 16<<20)
	buffer := bytes.NewBuffer(backing[:0:16])
	written, err := buffer.Write(input)
	require.NoError(t, err)
	require.Equal(t, len(input), written)
	runtime.KeepAlive(buffer)
}
