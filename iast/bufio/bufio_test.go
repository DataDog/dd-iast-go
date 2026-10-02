// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bufio_test

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"

	iastbufio "github.com/DataDog/dd-iast-go/iast/bufio"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestPropagate(t *testing.T) {
	testPropagation(t, false)
}

func TestAutomaticPropagation(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	testPropagation(t, true)
}

func testPropagation(t *testing.T, automatic bool) {
	t.Helper()
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})

	for _, test := range []struct {
		name  string
		size  int
		bound bool
		want  bool
	}{
		{name: "small buffer", size: 16, bound: true, want: true},
		{name: "limit", size: 4096, bound: true, want: true},
		{name: "above limit", size: 4097, bound: true},
		{name: "unbound input", size: 4096},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, scope, created := request.Begin(context.Background())
			require.True(t, created)
			t.Cleanup(scope.Finish)
			input := strings.NewReader("request-body")
			if automatic && test.bound {
				require.True(t, request.BindReader(ctx, input))
			}
			output := bufio.NewReaderSize(input, test.size)
			if !automatic {
				// Bind after construction so the manual helper is the only
				// operation that can propagate provenance to output.
				if test.bound {
					require.True(t, request.BindReader(ctx, input))
				}
				iastbufio.Propagate(input, output)
			}
			data := request.CloneReaderBytes(output, []byte("request-body"))
			if automatic {
				require.Equal(t, test.want, data != nil)
			} else {
				// The manual helper makes a binding that is not exclusive
				// (decision Q13): a consumer attributes nothing.
				require.Nil(t, data)
				bound := request.LookupObject(output, store.BindingReader, make([]store.OwnerRef, 4)) == 1
				require.Equal(t, test.want, bound)
			}
			require.Equal(t, len("request-body"), input.Len(), "propagation must not read input")
			scope.Finish()
			require.Nil(t, request.CloneReaderBytes(output, []byte("request-body")))
		})
	}
}

func TestAutomaticNewReaderDelegationAndCleanup(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})

	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	input := strings.NewReader("request-body")
	require.True(t, request.BindReader(ctx, input))
	output := bufio.NewReader(input)
	require.Equal(t, 4096, output.Size())
	data := request.CloneReaderBytes(output, []byte("request-body"))
	require.Equal(t, []byte("request-body"), data)
	require.Equal(t, len("request-body"), input.Len(), "propagation must not read input")
	var observed []taint.Range
	require.True(t, taint.VisitBytes(ctx, data, func(r taint.Range) bool {
		observed = append(observed, r)
		return true
	}))
	require.Equal(t, []taint.Range{{
		Start:  0,
		Length: uint32(len(data)),
		Source: taint.SourceValue{
			Source: taint.Source{Origin: taint.OriginHttpRequestBody},
			Value:  "request-body",
		},
		Marks: taint.Marks{},
	}}, observed)

	scope.Finish()
	require.Nil(t, request.CloneReaderBytes(output, []byte("request-body")))
}

func TestPropagateNilReaders(t *testing.T) {
	require.NotPanics(t, func() {
		iastbufio.Propagate(nil, nil)
		var input *strings.Reader
		iastbufio.Propagate(input, bufio.NewReader(strings.NewReader("body")))
	})
}

// TestKnownLimitBufioValueCopySharesBuffer pins the current behavior of
// residual R15 of plan encoding-json-v2 (section 6.6, decision Q10): a copy of
// a bufio.Reader value shares its buffer with the original. A Reset and a Read
// of the copy write bytes of the new reader into the buffer that the original
// reads next. The Read guard of the original sees no retarget, thus IAST
// attributes these bytes to the request of the original.
//
// Known limit R15. If this test fails because the bytes are not attributed to
// A, the limit is fixed: update R15, the README, and the iast/bufio package
// doc.
func TestKnownLimitBufioValueCopySharesBuffer(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	ctx, scope := beginRequest(t)
	body := boundBody(t, ctx, "aaaaaaaaaaaaaaaaaaaaaaaa")
	require.NotPanics(t, func() {
		p := bufio.NewReaderSize(body, 16)
		_, err := p.Peek(16)
		require.NoError(t, err)
		q := *p
		q.Reset(strings.NewReader("cccccccc"))
		_, err = q.Read(make([]byte, 4))
		require.NoError(t, err)
		data, err := io.ReadAll(p)
		require.NoError(t, err)

		// The program bug: p returns bytes of the reader of q.
		require.True(t, strings.HasPrefix(string(data), "cccccccc"), "data is %q", data)
		// The mis-attribution: the bytes are tainted with the body source of
		// A.
		found := false
		taint.VisitBytes(ctx, data, func(r taint.Range) bool {
			found = r.Source.Origin == taint.OriginHttpRequestBody && r.Source.Value == string(data)
			return !found
		})
		require.True(t, found, "the bytes of the copy are not attributed to A")
		// The retargeted bit of A is not set: p stays exclusive to A.
		requireExclusiveOwner(t, scope, p)
	})
}
