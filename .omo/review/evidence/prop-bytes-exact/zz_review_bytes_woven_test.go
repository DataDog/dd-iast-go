package propagation_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func reviewBytesContext(t *testing.T) context.Context {
	t.Helper()
	require.True(t, built.WithOrchestrion, "this reproducer must run with instrumentation")
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, _, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(func() { request.FinishContext(ctx, true) })
	return ctx
}

func TestReviewWovenResliceWithinCapacity(t *testing.T) {
	// Given: a supported public byte source and a positive in-length control.
	ctx := reviewBytesContext(t)
	input := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody, Name: "body"}, []byte("01234567"))
	require.True(t, taint.IsTaintedBytes(input))
	short := input[:3:7]
	require.True(t, taint.IsTaintedBytes(short))
	clean := bytes.Clone([]byte("12345"))
	require.False(t, taint.IsTaintedBytes(clean))

	// When: direct three-index slicing and an allocation-preserving conversion.
	result := short[1:6:7]
	text := string(result)

	// Then: no mutation, budget exhaustion, or unsupported operation occurred.
	require.Equal(t, []byte("12345"), result)
	require.Equal(t, 6, cap(result))
	t.Logf("woven=%v input=%v short=%v result=%v converted=%v result=%q",
		built.WithOrchestrion, taint.IsTaintedBytes(input), taint.IsTaintedBytes(short),
		taint.IsTaintedBytes(result), taint.IsTaintedString(text), result)
	require.True(t, taint.IsTaintedBytes(result), "supported reslice lost source provenance")
	require.True(t, taint.IsTaintedString(text), "supported conversion lost source provenance")
}

func TestReviewWovenBufferAliasLimitation(t *testing.T) {
	// Given: a tracked mutable root handed to a later byte-buffer alias.
	ctx := reviewBytesContext(t)
	input := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody, Name: "body"}, []byte("attacker"))
	buffer := bytes.NewBuffer(input)
	require.True(t, taint.IsTaintedBytes(input))

	// When: native and direct supported buffer hooks execute a clean overwrite.
	buffer.Reset()
	n, err := buffer.WriteString("CLEAN!!!")
	require.NoError(t, err)
	require.Equal(t, 8, n)
	text := string(input)

	// Then: characterize the documented later-alias limitation, not a new finding.
	require.Equal(t, "CLEAN!!!", text)
	t.Logf("documented later-alias limitation: woven=%v overwritten=%q byteTainted=%v convertedTainted=%v",
		built.WithOrchestrion, text, taint.IsTaintedBytes(input), taint.IsTaintedString(text))
}
