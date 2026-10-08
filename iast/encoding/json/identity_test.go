// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// identityBody is a custom request body type. Its first field has the address
// of the body itself.
type identityBody struct {
	Buffer bytes.Buffer
	reads  int
}

func (b *identityBody) Read(p []byte) (int, error) { b.reads++; return b.Buffer.Read(p) }

// TestDecoderOfEmbeddedBufferIsNotAttributedToBody checks reader binding rule
// (d) (see the internal/taint/store package doc): a reader binding has the
// identity type plus address. The first field of a bound body has the address
// of the body, but it is another reader.
func TestDecoderOfEmbeddedBufferIsNotAttributedToBody(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctxA, scopeA, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scopeA.Finish)
	_, scopeB, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scopeB.Finish)

	body := &identityBody{}
	body.Buffer.WriteString(`{"value":"unrelated"}`)
	require.True(t, request.BindReader(ctxA, body))

	var destination struct{ Value string }
	require.NoError(t, json.NewDecoder(&body.Buffer).Decode(&destination))
	require.Equal(t, "unrelated", destination.Value)
	require.False(t, taint.IsTaintedString(destination.Value), "the bytes of the embedded buffer were attributed to the body owner")
	analysisA, ok := scopeA.Analysis()
	require.True(t, ok)
	require.Zero(t, analysisA.SourceCount())
	analysisB, ok := scopeB.Analysis()
	require.True(t, ok)
	require.Zero(t, analysisB.SourceCount())

	// Control: the body itself propagates where the variant supports
	// Decoder propagation.
	body.Buffer.WriteString(`{"value":"attack"}`)
	require.NoError(t, json.NewDecoder(body).Decode(&destination))
	require.Equal(t, "attack", destination.Value)
	require.Equal(t, decoderPropagates, taint.IsTaintedString(destination.Value))
	require.Equal(t, 0, body.Buffer.Len())
}
