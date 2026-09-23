package propagation_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestFXPropWriterF1ConfiguredOwnerFanout(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	require.Zero(t, writerbridge.ActiveCounter().Load())

	const owners = 60
	var builder strings.Builder
	builder.Grow(32 << 10)
	for index := range owners {
		input := activeStringSource(t, fmt.Sprintf("owner-%d", index), "abc")
		written, err := builder.WriteString(input)
		require.NoError(t, err)
		require.Equal(t, len(input), written)
	}

	store := request.ActiveStore()
	require.NotNil(t, store)
	t.Logf("owners=%d writer_records=%d process_charged_bytes=%d", owners, writerbridge.ActiveCounter().Load(), store.ProcessCharged())
	require.Equal(t, int32(owners), writerbridge.ActiveCounter().Load())
	require.Greater(t, store.ProcessCharged(), int64(4*(32<<10)))
}
