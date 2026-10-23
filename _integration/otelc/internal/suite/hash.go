// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package suite

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/md4" //nolint:staticcheck // Deliberately exercise weak hash detection.
)

var (
	md4Digest  = []byte{0x86, 0x64, 0x37, 0xcb, 0x7a, 0x79, 0x4b, 0xce, 0x2b, 0x72, 0x7a, 0xcc, 0x03, 0x62, 0xee, 0x27}
	md5Digest  = []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92}
	sha1Digest = []byte{0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d}
)

func weakHash(evidence, function string) vulnerability {
	return vulnerability{typ: constants.VulnerabilityTypeWeakHash, evidence: evidence, function: function, line: 1337}
}

// checkWeakHash checks every weak hash sink: one report for each call, at the
// location of the caller, with and without stack traces.
func checkWeakHash(t *testing.T) {
	requireInstrumented(t)

	// Each sink returns the digest of "hello" and the function of this package
	// that is expected in the location.
	cases := []struct {
		name     string
		evidence string
		digest   []byte
		call     func() []byte
		function string
	}{
		{"md4.New", "MD4", md4Digest, func() []byte { return digestOf(indirectCall0(md4.New)) }, "indirectCall0[...]"},
		{"md5.New", "MD5", md5Digest, func() []byte { return digestOf(indirectCall0(md5.New)) }, "indirectCall0[...]"},
		{"md5.Sum", "MD5", md5Digest, func() []byte { s := indirectCall1(md5.Sum, []byte("hello")); return s[:] }, "indirectCall1[...]"},
		{"sha1.New", "SHA-1", sha1Digest, func() []byte { return digestOf(indirectCall0(sha1.New)) }, "indirectCall0[...]"},
		{"sha1.Sum", "SHA-1", sha1Digest, func() []byte { s := indirectCall1(sha1.Sum, []byte("hello")); return s[:] }, "indirectCall1[...]"},
	}

	withStackTrace(t, func(t *testing.T, stackTrace bool) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mockTracer := mocktracer.Start()
				t.Cleanup(mockTracer.Stop)
				before := telemetry.ExecutedSink.WeakHash.Load()

				assert.Equal(t, tc.digest, tc.call())

				assertSingleReport(t, mockTracer, weakHash(tc.evidence, tc.function), stackTrace, &telemetry.ExecutedSink.WeakHash, before)
			})
		}
	})
}

// digestOf writes "hello" in h, which must be a new hash, and returns its sum.
// Only the creation of the hash is a sink: this must not report.
func digestOf(h hash.Hash) []byte {
	_, _ = h.Write([]byte("hello"))
	return h.Sum(nil)
}

// checkWeakHashNotSinks checks that the methods of the hashes (for example
// (*digest).Sum) and the other hashes are NOT sinks: only the constructors and
// the md5.Sum and sha1.Sum functions are.
func checkWeakHashNotSinks(t *testing.T) {
	requireInstrumented(t)

	// The constructors are instrumented, and they run outside of the traced
	// section.
	hashes := map[string]hash.Hash{"md4": md4.New(), "md5": md5.New(), "sha1": sha1.New()}

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	before := telemetry.ExecutedSink.WeakHash.Load()

	for name, h := range hashes {
		_, err := h.Write([]byte("hello"))
		require.NoError(t, err, name)
		_ = h.Sum(nil)
		_ = h.Sum([]byte{1, 2, 3})
		h.Reset()
	}
	// A hash that is not weak.
	_ = sha256.Sum256([]byte("hello"))
	_ = digestOf(sha256.New())

	assert.Empty(t, mockTracer.FinishedSpans())
	assert.Equal(t, before, telemetry.ExecutedSink.WeakHash.Load())
}

// checkCryptoHashNew checks the `crypto.Hash.New` path (the hash goes through
// the registry, and ends up calling the constructor of the package).
func checkCryptoHashNew(t *testing.T) {
	requireInstrumented(t)

	cases := []struct {
		hash     crypto.Hash
		evidence string
	}{
		{crypto.MD4, "MD4"},
		{crypto.MD5, "MD5"},
		{crypto.SHA1, "SHA-1"},
	}

	withStackTrace(t, func(t *testing.T, stackTrace bool) {
		for _, tc := range cases {
			t.Run(tc.hash.String(), func(t *testing.T) {
				mockTracer := mocktracer.Start()
				t.Cleanup(mockTracer.Stop)
				before := telemetry.ExecutedSink.WeakHash.Load()

				h := indirectCall0(tc.hash.New)
				_, err := h.Write([]byte("hello"))
				require.NoError(t, err)

				// The frame of crypto.Hash.New is skipped, and the caller is reported.
				assertSingleReport(t, mockTracer, weakHash(tc.evidence, "indirectCall0[...]"), stackTrace, &telemetry.ExecutedSink.WeakHash, before)
			})
		}
	})
}

// indirectCall0 calls the provided function and returns its result. The line
// directive makes the call site stable and independent from the actual
// filesystem location of the source under test. A line directive changes the
// position of all the code after it, so keep these functions last in the file.
func indirectCall0[T any](fn func() T) T {
	return /*line /path/to/file.go:1337*/ fn()
}

// indirectCall1 is like indirectCall0 for functions that take one argument.
func indirectCall1[A any, T any](fn func(A) T, arg A) T {
	return /*line /path/to/file.go:1337*/ fn(arg)
}
