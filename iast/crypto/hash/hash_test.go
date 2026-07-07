// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hash_test

import (
	"context"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/constants"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "golang.org/x/crypto/md4" // Make the MD4 implementation available
)

var thisFile string

func init() {
	_, thisFile, _, _ = runtime.Caller(0)
}

func TestMD5(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	assert.Equal(t,
		[md5.Size]byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
		md5.Sum([]byte("hello")))

	spans := mockTracer.FinishedSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, 1.0, spans[0].Tag(constants.SpanTagEnabled))
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(spans[0].Tag(constants.SpanTagJson).(string)), &event))
	require.Equal(t, "vulnerability", spans[0].OperationName())
	require.Equal(t, "vulnerability", spans[0].Tag(ext.SpanType))
	assert.Equal(t,
		&model.Event{
			Vulnerabilities: []*model.Vulnerability{
				{
					Type:     model.VulnerabilityTypeWeakHash,
					Hash:     0xef2713f3de1c9efc,
					Evidence: &model.UnredactedStringValue{Value: "MD5"},
					Location: &model.Location{
						SpanID: spans[0].Context().SpanID(),
						Path:   thisFile,
						Line:   new(43),
						Type:   "github.com/DataDog/dd-iast-go/iast/crypto/hash_test",
						Method: "TestMD5",
					},
				},
			},
		},
		&event)
}

func TestSHA1(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	assert.Equal(t,
		[sha1.Size]byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0xf, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d},
		sha1.Sum([]byte("hello")))

	spans := mockTracer.FinishedSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, 1.0, spans[0].Tag(constants.SpanTagEnabled))
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(spans[0].Tag(constants.SpanTagJson).(string)), &event))
	require.Equal(t, "vulnerability", spans[0].OperationName())
	require.Equal(t, "vulnerability", spans[0].Tag(ext.SpanType))
	assert.Equal(t,
		&model.Event{
			Vulnerabilities: []*model.Vulnerability{
				{
					Type:     model.VulnerabilityTypeWeakHash,
					Hash:     0xef2713f3de1c9efc,
					Evidence: &model.UnredactedStringValue{Value: "SHA-1"},
					Location: &model.Location{
						SpanID: spans[0].Context().SpanID(),
						Path:   thisFile,
						Line:   new(81),
						Type:   "github.com/DataDog/dd-iast-go/iast/crypto/hash_test",
						Method: "TestSHA1",
					},
				},
			},
		},
		&event)
}

func TestHash(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	type expected struct {
		Digest []byte
		Hash   uint64
	}
	cases := map[crypto.Hash]expected{
		crypto.MD4: {
			Digest: []byte{0x86, 0x64, 0x37, 0xcb, 0x7a, 0x79, 0x4b, 0xce, 0x2b, 0x72, 0x7a, 0xcc, 0x03, 0x62, 0xee, 0x27},
			Hash:   0xef2713f3de1c9efc,
		},
		crypto.MD5: {
			Digest: []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
			Hash:   0xef2713f3de1c9efc,
		},
		crypto.SHA1: {
			Digest: []byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d},
			Hash:   0xef2713f3de1c9efc,
		},
	}

	expectedVulns := make([]*model.Vulnerability, 0, len(cases))

	//dd:span span.name:test
	func(ctx context.Context) {
		for alg, exp := range cases {
			h := alg.New()
			n, err := h.Write([]byte("hello"))
			require.NoError(t, err)
			require.Equal(t, 5, n)
			act := h.Sum(nil)
			assert.Equal(t, exp.Digest, act, "hash algorithm %s", alg)

			span, _ := tracer.SpanFromContext(ctx)
			expectedVulns = append(expectedVulns, &model.Vulnerability{
				Type:     model.VulnerabilityTypeWeakHash,
				Hash:     exp.Hash,
				Evidence: &model.UnredactedStringValue{Value: alg.String()},
				Location: &model.Location{
					SpanID: span.Context().SpanID(),
					Path:   thisFile,
					Line:   new(146),
					Type:   "github.com/DataDog/dd-iast-go/iast/crypto/hash_test.TestHash",
					Method: "func1",
				},
			})
		}
	}(context.Background())

	spans := mockTracer.FinishedSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, 1.0, spans[0].Tag(constants.SpanTagEnabled))
	assert.Equal(t, "test", spans[0].OperationName())
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(spans[0].Tag(constants.SpanTagJson).(string)), &event))
	assert.Len(t, event.Vulnerabilities, len(cases))
	assert.Equal(t,
		expectedVulns,
		event.Vulnerabilities,
	)
}
