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
	"testing"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "golang.org/x/crypto/md4" // Make the MD4 implementation available
)

func TestMD5(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	ctx := context.Background()
	_, ctx = tracer.StartSpanFromContext(ctx, "test")

	assert.Equal(t,
		[md5.Size]byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
		md5.Sum([]byte("hello")))

	_ = mockTracer.FinishedSpans()
	//TODO: Implement once wired
}

func TestSHA1(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	ctx := context.Background()
	_, ctx = tracer.StartSpanFromContext(ctx, "test")

	assert.Equal(t,
		[sha1.Size]byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0xf, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d},
		sha1.Sum([]byte("hello")))

	_ = mockTracer.FinishedSpans()
	//TODO: Implement once wired
}

func TestHash(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	ctx := context.Background()
	_, ctx = tracer.StartSpanFromContext(ctx, "test")

	for alg, exp := range map[crypto.Hash][]byte{
		crypto.MD4:  {0x86, 0x64, 0x37, 0xcb, 0x7a, 0x79, 0x4b, 0xce, 0x2b, 0x72, 0x7a, 0xcc, 0x03, 0x62, 0xee, 0x27},
		crypto.MD5:  {0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
		crypto.SHA1: {0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d},
	} {
		h := alg.New()
		n, err := h.Write([]byte("hello"))
		require.NoError(t, err)
		require.Equal(t, 5, n)
		act := h.Sum(nil)
		assert.Equal(t, exp, act, "hash algorithm %s", alg)
	}

	_ = mockTracer.FinishedSpans()
	//TODO: Implement once wired
}
