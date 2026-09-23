package propagation_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestReviewFxSplitKeepsFirstNonEmptyAfterEmptyPrefix(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is required for this direct-call reproduction")
	}

	ctx := beginNativePropagation(t)

	t.Run("string", func(t *testing.T) {
		input := taint.TaintString(ctx, taint.Source{
			Origin: taint.OriginHttpRequestParameter,
			Name:   "review-string",
		}, strings.Repeat(",", 32)+"attack")
		require.True(t, taint.IsTaintedString(input))

		parts := testapp.Split(input, ",")
		require.Len(t, parts, 33)
		t.Logf("string part[32]=%q tainted=%t", parts[32], taint.IsTaintedString(parts[32]))
		require.True(t, taint.IsTaintedString(parts[32]))
	})

	t.Run("bytes", func(t *testing.T) {
		input := taint.TaintBytes(ctx, taint.Source{
			Origin: taint.OriginHttpRequestBody,
			Name:   "review-bytes",
		}, []byte(strings.Repeat(",", 32)+"attack"))
		require.True(t, taint.IsTaintedBytes(input))

		parts := testapp.BytesSplit(input, []byte(","))
		require.Len(t, parts, 33)
		t.Logf("bytes part[32]=%q tainted=%t", parts[32], taint.IsTaintedBytes(parts[32]))
		require.True(t, bytes.Equal(parts[32], []byte("attack")))
		require.True(t, taint.IsTaintedBytes(parts[32]))
	})
}
