package propagation_test

import (
	"bytes"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestReviewBufferConsumptionDropsRemainingRanges(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("this review check requires instrumented stdlib methods")
	}
	for _, mode := range []string{"Read", "Next"} {
		t.Run(mode, func(t *testing.T) {
			// Given: a buffer with a tracked value and a nonzero unread tail.
			input := activeString(t, "attack")
			var buffer bytes.Buffer
			_, err := buffer.WriteString(input)
			require.NoError(t, err)
			require.True(t, taint.IsTaintedString(buffer.String()))

			// When: two bytes are consumed through a native exposure hook.
			if mode == "Read" {
				read := make([]byte, 2)
				n, err := buffer.Read(read)
				require.NoError(t, err)
				require.Equal(t, 2, n)
			} else {
				require.Equal(t, "at", string(buffer.Next(2)))
			}

			// Then: the unread bytes have their correct host value and no stale ranges.
			require.Equal(t, "tack", buffer.String())
			require.False(t, taint.IsTaintedString(buffer.String()))
		})
	}
}
