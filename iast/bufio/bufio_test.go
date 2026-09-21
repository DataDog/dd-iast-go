// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bufio_test

import (
	"bufio"
	"context"
	"strings"
	"testing"

	iastbufio "github.com/DataDog/dd-iast-go/iast/bufio"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
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
			require.Equal(t, test.want, data != nil)
			require.Equal(t, len("request-body"), input.Len(), "propagation must not read input")
			scope.Finish()
			require.Nil(t, request.CloneReaderBytes(output, []byte("request-body")))
		})
	}
}

func TestPropagateNilReaders(t *testing.T) {
	require.NotPanics(t, func() {
		iastbufio.Propagate(nil, nil)
		var input *strings.Reader
		iastbufio.Propagate(input, bufio.NewReader(strings.NewReader("body")))
	})
}
