package propagation_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/stretchr/testify/require"
)

func TestReviewWriterOwnerFanoutBound(t *testing.T) {
	// Given: one builder with enough capacity for inputs from 60 active owners.
	s, _ := beginScope(t)
	var builder strings.Builder
	builder.Grow(32768)
	const owners = 60
	for i := 0; i < owners; i++ {
		owner := acquireOwner(t, s)
		input, _ := taintString(t, owner, "abc", []ranges.Range{{Length: 3, SourceID: ranges.SourceID(i)}})

		// When: each owner contributes through the supported direct write path.
		testBuilderWriteString(t, &builder, input)
	}

	// Then: one receiver may retain at most four owner records.
	t.Logf("writer records=%d, process charged bytes=%d", writerbridge.ActiveCounter().Load(), s.ProcessCharged())
	require.LessOrEqual(t, writerbridge.ActiveCounter().Load(), int32(4),
		"a single builder admitted writer records from 60 separate owners")
}
