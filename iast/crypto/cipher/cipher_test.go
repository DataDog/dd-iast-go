// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package cipher_test

import (
	"context"
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blowfish" //nolint:staticcheck // Deliberately exercise weak cipher detection.
	"golang.org/x/crypto/pkcs12"
)

func init() {
	config.Enabled = true
	config.RequestSamplingPct = 100
}

func TestDES(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	before := telemetry.ExecutedSink.WeakCipher.Load()
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	key := mustDecodeHex(t, "133457799BBCDFF1")
	block, err := indirectCipherCall(des.NewCipher, key)
	require.NoError(t, err)
	assertBlockEncryption(t, block, "0123456789ABCDEF", "85E813540F0AB405")

	assertWeakCipher(t, mockTracer, before, "DES", 1337, "indirectCipherCall")
}

func TestTripleDES(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	before := telemetry.ExecutedSink.WeakCipher.Load()
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	key := mustDecodeHex(t, "0123456789abcdeffedcba987654321089abcdef01234567")
	block, err := indirectCipherCall(des.NewTripleDESCipher, key)
	require.NoError(t, err)
	assertBlockRoundTrip(t, block, mustDecodeHex(t, "0123456789abcdef"))

	assertWeakCipher(t, mockTracer, before, "TripleDES", 1337, "indirectCipherCall")
}

func TestRC4(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	before := telemetry.ExecutedSink.WeakCipher.Load()
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	stream, err := indirectCipherCall(rc4.NewCipher, []byte("Key"))
	require.NoError(t, err)
	actual := make([]byte, len("Plaintext"))
	stream.XORKeyStream(actual, []byte("Plaintext"))
	assert.Equal(t, "bbf316e8d940af0ad3", hex.EncodeToString(actual))

	assertWeakCipher(t, mockTracer, before, "RC4", 1337, "indirectCipherCall")
}

func TestBlowfish(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	before := telemetry.ExecutedSink.WeakCipher.Load()
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	block, err := indirectCipherCall(blowfish.NewCipher, make([]byte, 8))
	require.NoError(t, err)
	assertBlockEncryption(t, block, "0000000000000000", "4ef997456198dd78")

	assertWeakCipher(t, mockTracer, before, "Blowfish", 1337, "indirectCipherCall")
}

func TestSaltedBlowfish(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	for _, tc := range []struct {
		name string
		salt []byte
	}{
		{name: "with salt", salt: []byte("salt")},
		{name: "empty salt", salt: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := telemetry.ExecutedSink.WeakCipher.Load()
			mockTracer := mocktracer.Start()
			t.Cleanup(mockTracer.Stop)

			block, err := indirectSaltedCipherCall(blowfish.NewSaltedCipher, []byte("key"), tc.salt)
			require.NoError(t, err)
			assertBlockRoundTrip(t, block, []byte("12345678"))

			assertWeakCipher(t, mockTracer, before, "Blowfish", 1448, "indirectSaltedCipherCall")
		})
	}
}

func TestPKCS12PBE(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	for _, tc := range []struct {
		name     string
		fixture  string
		evidence []string
	}{
		{
			name:     "RC2",
			fixture:  "testdata/pbe-rc2.p12",
			evidence: []string{"PBEWithSHAAnd40BitRC2CBC", "RC2"},
		},
		{
			name:     "TripleDES",
			fixture:  "testdata/pbe-tripledes.p12",
			evidence: []string{"PBEWithSHAAnd3KeyTripleDESCBC", "TripleDES"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalDeduplicationEnabled := config.DeduplicationEnabled
			originalVulnerabilitiesPerRequest := config.VulnerabilitiesPerRequest
			config.DeduplicationEnabled = true
			config.VulnerabilitiesPerRequest = 16 // The PBE KDF also reports SHA-1 from several call sites.
			t.Cleanup(func() {
				config.DeduplicationEnabled = originalDeduplicationEnabled
				config.VulnerabilitiesPerRequest = originalVulnerabilitiesPerRequest
			})

			data, err := os.ReadFile(tc.fixture)
			require.NoError(t, err)

			before := telemetry.ExecutedSink.WeakCipher.Load()
			mockTracer := mocktracer.Start()
			t.Cleanup(mockTracer.Stop)

			var cert *x509.Certificate
			//dd:span span.name:test
			func(context.Context) {
				_, cert, err = indirectPKCS12Decode(data, "testpass")
			}(context.Background())
			require.NoError(t, err)
			require.NotNil(t, cert)
			assert.Equal(t, "testcert", cert.Subject.CommonName)

			spanList := mockTracer.FinishedSpans()
			require.Len(t, spanList, 1)
			span := spanList[0]
			assert.Equal(t, "test", span.OperationName())
			var event model.Event
			require.NoError(t, json.Unmarshal([]byte(span.Tag(spans.SpanTagJson).(string)), &event))
			weakCiphers := make([]model.Vulnerability, 0, len(tc.evidence))
			for _, vuln := range event.Vulnerabilities {
				if vuln.Type == constants.VulnerabilityTypeWeakCipher {
					weakCiphers = append(weakCiphers, vuln)
				}
			}
			require.Len(t, weakCiphers, len(tc.evidence))
			for i, evidence := range tc.evidence {
				assert.Equal(t, model.NewEvidenceString(evidence), weakCiphers[i].Evidence)
			}
			assert.Equal(t, before+uint64(len(tc.evidence)), telemetry.ExecutedSink.WeakCipher.Load())
		})
	}
}

func TestInstrumentedSink(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	assert.Equal(t, uint(8), telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakCipher])
}

func TestAESIsNotReported(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	before := telemetry.ExecutedSink.WeakCipher.Load()
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	block, err := indirectCipherCall(aes.NewCipher, make([]byte, 16))
	require.NoError(t, err)
	assertBlockRoundTrip(t, block, make([]byte, aes.BlockSize))

	assert.Empty(t, mockTracer.FinishedSpans())
	assert.Equal(t, before, telemetry.ExecutedSink.WeakCipher.Load())
}

func assertWeakCipher(
	t *testing.T,
	mockTracer mocktracer.Tracer,
	executedBefore uint64,
	evidence string,
	line uint32,
	method string,
) {
	t.Helper()

	spanList := mockTracer.FinishedSpans()
	require.Len(t, spanList, 1)
	span := spanList[0]
	assert.Equal(t, 1.0, span.Tag(spans.SpanTagEnabled))
	assert.Equal(t, "vulnerability", span.OperationName())
	assert.Equal(t, "vulnerability", span.Tag(ext.SpanType))

	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(span.Tag(spans.SpanTagJson).(string)), &event))
	require.Len(t, event.Vulnerabilities, 1)
	vuln := event.Vulnerabilities[0]
	assert.Equal(t, constants.VulnerabilityTypeWeakCipher, vuln.Type)
	assert.Equal(t, model.NewEvidenceString(evidence), vuln.Evidence)
	assert.NotZero(t, vuln.Hash)
	require.NotNil(t, vuln.Location)
	assert.Equal(t, span.Context().SpanID(), vuln.Location.SpanID)
	assert.Equal(t, "/path/to/file.go", vuln.Location.Path)
	assert.Equal(t, line, vuln.Location.Line)
	assert.Contains(t, vuln.Location.Method, method)
	assert.Equal(t, executedBefore+1, telemetry.ExecutedSink.WeakCipher.Load())
}

func assertBlockEncryption(t *testing.T, block stdcipher.Block, plaintextHex, ciphertextHex string) {
	t.Helper()
	plaintext := mustDecodeHex(t, plaintextHex)
	actual := make([]byte, len(plaintext))
	block.Encrypt(actual, plaintext)
	assert.Equal(t, mustDecodeHex(t, ciphertextHex), actual)
}

func assertBlockRoundTrip(t *testing.T, block stdcipher.Block, plaintext []byte) {
	t.Helper()
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	actual := make([]byte, len(plaintext))
	block.Decrypt(actual, ciphertext)
	assert.Equal(t, plaintext, actual)
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

// indirectCipherCall calls the provided constructor and returns its result. It
// uses a line directive to keep the expected application location stable.
func indirectCipherCall[C any](fn func([]byte) (C, error), key []byte) (C, error) {
	return /*line /path/to/file.go:1337*/ fn(key)
}

// indirectSaltedCipherCall calls a two-argument cipher constructor and returns
// its result using a stable application location.
func indirectSaltedCipherCall[C any](fn func([]byte, []byte) (C, error), key, salt []byte) (C, error) {
	return /*line /path/to/file.go:1448*/ fn(key, salt)
}

// indirectPKCS12Decode calls the public PKCS#12 decoder. Keep it last so the
// line directive cannot affect other code.
func indirectPKCS12Decode(data []byte, password string) (any, *x509.Certificate, error) {
	return /*line /path/to/file.go:1559*/ pkcs12.Decode(data, password)
}
