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
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/instrumentation"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "golang.org/x/crypto/md4" // Make the MD4 implementation available
)

func init() {
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.StackTraceEnabled = true
}

func TestMD5(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	assert.Equal(t,
		[md5.Size]byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
		indirectCall1(md5.Sum, []byte("hello")))

	spanList := mockTracer.FinishedSpans()
	require.Len(t, spanList, 1)
	assert.Equal(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled))
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(spanList[0].Tag(spans.SpanTagJson).(string)), &event))
	require.Equal(t, "vulnerability", spanList[0].OperationName())
	require.Equal(t, "vulnerability", spanList[0].Tag(ext.SpanType))
	require.Len(t, event.Vulnerabilities, 1)
	assert.Equal(t,
		&model.Event{
			Vulnerabilities: []model.Vulnerability{
				model.NewVulnerability(
					constants.VulnerabilityTypeWeakHash,
					model.NewEvidenceString("MD5"),
					&model.Location{
						SpanID:  spanList[0].Context().SpanID(),
						StackID: spanList[0].Tag("_dd.stack").(map[string][]*instrumentation.StackTrace)["vulnerability"][0].ID,
						Path:    "/path/to/file.go",
						Line:    1337,
						Method:  "github.com/DataDog/dd-iast-go/iast/crypto/hash_test.indirectCall1[...]",
					},
				),
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
		indirectCall1(sha1.Sum, []byte("hello")))

	spanList := mockTracer.FinishedSpans()
	require.Len(t, spanList, 1)
	assert.Equal(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled))
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(spanList[0].Tag(spans.SpanTagJson).(string)), &event))
	require.Equal(t, "vulnerability", spanList[0].OperationName())
	require.Equal(t, "vulnerability", spanList[0].Tag(ext.SpanType))

	require.Len(t, event.Vulnerabilities, 1)

	assert.Equal(t,
		&model.Event{
			Vulnerabilities: []model.Vulnerability{
				model.NewVulnerability(
					constants.VulnerabilityTypeWeakHash,
					model.NewEvidenceString("SHA-1"),
					&model.Location{
						SpanID:  spanList[0].Context().SpanID(),
						StackID: spanList[0].Tag("_dd.stack").(map[string][]*instrumentation.StackTrace)["vulnerability"][0].ID,
						Path:    "/path/to/file.go",
						Line:    1337,
						Method:  "github.com/DataDog/dd-iast-go/iast/crypto/hash_test.indirectCall1[...]",
					},
				),
			},
		},
		&event)
}

func TestHash(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	// For this test we specifically don't want deduplication to happen.
	originalDeduplicationEnabled := config.DeduplicationEnabled
	config.DeduplicationEnabled = false
	t.Cleanup(func() {
		config.DeduplicationEnabled = originalDeduplicationEnabled
	})

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	type expected struct {
		Digest []byte
	}
	cases := map[crypto.Hash]expected{
		crypto.MD4: {
			Digest: []byte{0x86, 0x64, 0x37, 0xcb, 0x7a, 0x79, 0x4b, 0xce, 0x2b, 0x72, 0x7a, 0xcc, 0x03, 0x62, 0xee, 0x27},
		},
		crypto.MD5: {
			Digest: []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
		},
		crypto.SHA1: {
			Digest: []byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d},
		},
	}

	originalVulnerabilitiesPerRequest := config.VulnerabilitiesPerRequest
	config.VulnerabilitiesPerRequest = len(cases)
	t.Cleanup(func() {
		config.VulnerabilitiesPerRequest = originalVulnerabilitiesPerRequest
	})

	expectedVulns := make([]model.Vulnerability, 0, len(cases))

	//dd:span span.name:test
	func(ctx context.Context) {
		for alg, exp := range cases {
			h := indirectCall0(alg.New)
			n, err := h.Write([]byte("hello"))
			require.NoError(t, err)
			require.Equal(t, 5, n)
			act := h.Sum(nil)
			assert.Equal(t, exp.Digest, act, "hash algorithm %s", alg)

			span, _ := tracer.SpanFromContext(ctx)
			expectedVulns = append(expectedVulns, model.NewVulnerability(
				constants.VulnerabilityTypeWeakHash,
				model.NewEvidenceString(alg.String()),
				&model.Location{
					SpanID: span.Context().SpanID(),
					Path:   "/path/to/file.go",
					Line:   1337,
					Method: "github.com/DataDog/dd-iast-go/iast/crypto/hash_test.indirectCall0[...]",
				},
			))
		}
	}(context.Background())

	spanList := mockTracer.FinishedSpans()

	// Associate the relevant stack IDs
	for i := range expectedVulns {
		expectedId := spanList[0].Tag("_dd.stack").(map[string][]*instrumentation.StackTrace)["vulnerability"][i].ID
		expectedVulns[i].Location.StackID = expectedId
	}

	require.Len(t, spanList, 1)
	assert.Equal(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled))
	assert.Equal(t, "test", spanList[0].OperationName())
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(spanList[0].Tag(spans.SpanTagJson).(string)), &event))
	assert.Len(t, event.Vulnerabilities, len(cases))

	assert.Equal(t,
		expectedVulns,
		event.Vulnerabilities,
	)
}

// indirectCall1 calls the provided function and returns its result. This must
// remain last in the file, as it includes a line directive to ensure the call
// site is stable and independent from the actual filesystem location of the
// source under test.
func indirectCall0[T any](fn func() T) T {
	return /*line /path/to/file.go:1337*/ fn()
}

// indirectCall1 calls the provided function and returns its result. This must
// remain last in the file, as it includes a line directive to ensure the call
// site is stable and independent from the actual filesystem location of the
// source under test.
func indirectCall1[A any, T any](fn func(A) T, arg A) T {
	return /*line /path/to/file.go:1337*/ fn(arg)
}
