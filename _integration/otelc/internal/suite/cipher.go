// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package suite

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/des" //nolint:gosec // Deliberately exercise weak cipher detection.
	"crypto/rc4" //nolint:gosec // Deliberately exercise weak cipher detection.
	"crypto/x509"
	"embed"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/instrumentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blowfish" //nolint:staticcheck // Deliberately exercise weak cipher detection.
	"golang.org/x/crypto/pkcs12"   //nolint:staticcheck // Deliberately exercise weak cipher detection.
)

//go:embed testdata/*.p12
var fixtures embed.FS

func weakCipher(evidence, function string, line uint32) vulnerability {
	return vulnerability{typ: constants.VulnerabilityTypeWeakCipher, evidence: evidence, function: function, line: line}
}

// checkWeakCipher checks the weak cipher sinks that have one argument: one
// report for each call, at the location of the caller, with and without stack
// traces. If the setup does not import the weak cipher detection, the sinks
// must not report.
func checkWeakCipher(t *testing.T, cfg Config) {
	requireInstrumented(t)

	cases := []struct {
		name     string
		evidence string
		call     func() error
		function string
	}{
		{"des.NewCipher", "DES", func() error { _, err := indirectCipherCall(des.NewCipher, make([]byte, 8)); return err }, "indirectCipherCall[...]"},
		{"des.NewTripleDESCipher", "TripleDES", func() error { _, err := indirectCipherCall(des.NewTripleDESCipher, make([]byte, 24)); return err }, "indirectCipherCall[...]"},
		{"rc4.NewCipher", "RC4", func() error { _, err := indirectCipherCall(rc4.NewCipher, []byte("Key")); return err }, "indirectCipherCall[...]"},
		{"blowfish.NewCipher", "Blowfish", func() error { _, err := indirectCipherCall(blowfish.NewCipher, make([]byte, 8)); return err }, "indirectCipherCall[...]"},
	}

	withStackTrace(t, func(t *testing.T, stackTrace bool) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mockTracer := mocktracer.Start()
				t.Cleanup(mockTracer.Stop)
				before := telemetry.ExecutedSink.WeakCipher.Load()

				require.NoError(t, tc.call())

				if !cfg.Cipher {
					assertNoReport(t, mockTracer, before)
					return
				}
				assertSingleReport(t, mockTracer, weakCipher(tc.evidence, tc.function, 1337), stackTrace, &telemetry.ExecutedSink.WeakCipher, before)
			})
		}
	})
}

// checkSaltedBlowfish checks blowfish.NewSaltedCipher. With an empty salt it
// calls blowfish.NewCipher, and with a salt it does not: both cases must make
// exactly one report, at the location of the caller of NewSaltedCipher.
func checkSaltedBlowfish(t *testing.T, cfg Config) {
	requireInstrumented(t)

	withStackTrace(t, func(t *testing.T, stackTrace bool) {
		for _, tc := range []struct {
			name string
			salt []byte
		}{
			{name: "with salt", salt: []byte("salt")},
			{name: "empty salt", salt: []byte{}},
			{name: "nil salt", salt: nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mockTracer := mocktracer.Start()
				t.Cleanup(mockTracer.Stop)
				before := telemetry.ExecutedSink.WeakCipher.Load()

				block, err := indirectSaltedCipherCall(blowfish.NewSaltedCipher, []byte("key"), tc.salt)
				require.NoError(t, err)
				assertBlockRoundTrip(t, block, []byte("12345678"))

				if !cfg.Cipher {
					assertNoReport(t, mockTracer, before)
					return
				}
				assertSingleReport(t, mockTracer, weakCipher("Blowfish", "indirectSaltedCipherCall[...]", 1448), stackTrace, &telemetry.ExecutedSink.WeakCipher, before)
			})
		}
	})
}

// knownOtelcPKCS12Gap tells that the otelc version in go.mod does not keep the
// original location of the code that it adds to x/crypto/pkcs12 (the file of
// the report has no directory, and the lines are moved down). otelc PR #1499
// (https://github.com/open-telemetry/opentelemetry-go-compile-instrumentation/pull/1499)
// fixes it: with that PR, the locations of otelc are the same as the locations of
// Orchestrion (a probe in /tmp, with the head of the PR, confirmed it).
//
// While this constant is true, the test expects the locations of the gap for
// otelc, so the test fails when the gap closes. The gap is the number of lines
// that otelc adds above the call: one for each call that it injects in front of
// it in crypto.go. When the otelc version in go.mod
// includes PR #1499, the test fails with "known gap closed": delete this
// constant and the code that uses it (the "gap" fields). Both tools must then
// give the same location.
//
// The alternative, to skip the case of otelc, is worse: it would hide any other
// difference, and nothing would tell us to enable the check again.
const knownOtelcPKCS12Gap = true

// pkcs12Source finds crypto.go of x/crypto/pkcs12 in the module cache, and the
// line of the statement that contains each needle. This is the location that a
// report must have, so the test does not copy line numbers from the library.
func pkcs12Source(t *testing.T, needles ...string) (path string, lines []uint32) {
	t.Helper()

	// pkcs12.Decode is in pkcs12.go, which neither tool changes. crypto.go is in
	// the same directory.
	pc := reflect.ValueOf(pkcs12.Decode).Pointer()
	decodeFile, _ := runtime.FuncForPC(pc).FileLine(pc)
	path = filepath.Join(filepath.Dir(decodeFile), "crypto.go")

	// With -trimpath, the path in the binary is relative to the module cache
	// ("golang.org/x/crypto@vX/pkcs12/..."), and it is not a file on disk. The
	// reports use the same path, so keep it for the comparison, but read the
	// source from the directory that the go command gives.
	sourceFile := path
	if _, err := os.Stat(sourceFile); err != nil {
		out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "golang.org/x/crypto/pkcs12").Output()
		require.NoError(t, err, "find the directory of golang.org/x/crypto/pkcs12")
		sourceFile = filepath.Join(strings.TrimSpace(string(out)), "crypto.go")
	}

	data, err := os.ReadFile(sourceFile)
	require.NoError(t, err)
	source := strings.Split(string(data), "\n")
	for _, needle := range needles {
		var found []uint32
		for i, line := range source {
			if strings.Contains(line, needle) {
				found = append(found, uint32(i+1))
			}
		}
		require.Len(t, found, 1, "line of %q in %s", needle, path)
		lines = append(lines, found[0])
	}
	return path, lines
}

// checkPKCS12 checks the two PBE implementations of x/crypto/pkcs12 and the RC2
// cipher that they use (rc2.New is internal to x/crypto, and so PKCS#12 is the
// only way to call it). Decoding one fixture reports the PBE algorithm, then
// its underlying cipher. It also reports the SHA-1 hash from several call sites
// (the key derivation function), and those are not checked here.
//
// The library calls both ciphers, so the location is not in this package: it is
// the call in crypto.go. The test checks the path, the line, and the first frame
// of the stack. They must be the same for both tools.
func checkPKCS12(t *testing.T, cfg Config) {
	requireInstrumented(t)

	for _, tc := range []struct {
		name     string
		fixture  string
		evidence []string
		// pbeCreate is the class of the "create" method that calls the cipher.
		pbeCreate string
		// cipherCall is the statement of "create" that calls the cipher.
		cipherCall string
		// cipherGap is the number of lines that otelc adds above cipherCall (a
		// known gap: see knownOtelcPKCS12Gap).
		cipherGap uint32
	}{
		{"RC2", "testdata/pbe-rc2.p12", []string{"PBEWithSHAAnd40BitRC2CBC", "RC2"}, "golang.org/x/crypto/pkcs12.shaWith40BitRC2CBC", "return rc2.New(key, len(key)*8)", 2},
		{"TripleDES", "testdata/pbe-tripledes.p12", []string{"PBEWithSHAAnd3KeyTripleDESCBC", "TripleDES"}, "golang.org/x/crypto/pkcs12.shaWithTripleDESCBC", "return des.NewTripleDESCipher(key)", 1},
	} {
		withStackTrace(t, func(t *testing.T, stackTrace bool) {
			t.Run(tc.name, func(t *testing.T) {
				original := config.VulnerabilitiesPerRequest
				config.VulnerabilitiesPerRequest = 64 // One per call: each report is on its own span.
				t.Cleanup(func() { config.VulnerabilitiesPerRequest = original })

				data, err := fixtures.ReadFile(tc.fixture)
				require.NoError(t, err)

				mockTracer := mocktracer.Start()
				t.Cleanup(mockTracer.Stop)
				before := telemetry.ExecutedSink.WeakCipher.Load()

				_, cert, err := indirectPKCS12Decode(data, "testpass")
				require.NoError(t, err)
				require.NotNil(t, cert)
				assert.Equal(t, "testcert", cert.Subject.CommonName)

				// Without a parent span, each report is on its own span.
				type report struct {
					vulnerability model.Vulnerability
					span          *mocktracer.Span
				}
				var ciphers []report
				for _, span := range mockTracer.FinishedSpans() {
					for _, vuln := range vulnerabilityEvent(t, span).Vulnerabilities {
						if vuln.Type == constants.VulnerabilityTypeWeakCipher {
							ciphers = append(ciphers, report{vuln, span})
						}
					}
				}

				if !cfg.Cipher {
					assert.Empty(t, ciphers)
					assert.Equal(t, before, telemetry.ExecutedSink.WeakCipher.Load())
					return
				}

				// The PBE algorithm is reported by its "create" method, which the
				// sink skips: the location is its caller, pbDecrypterFor. The sink of
				// the underlying cipher is skipped too: the location is the "create"
				// method.
				path, lines := pkcs12Source(t, "block, err := cipherType.create(key)", tc.cipherCall)
				expected := []struct {
					class, method string
					// function is the name of the first frame of the stack.
					function string
					line     uint32
					gap      uint32
				}{
					{"", "golang.org/x/crypto/pkcs12.pbDecrypterFor", "pbDecrypterFor", lines[0], 2},
					{tc.pbeCreate, "create", "create", lines[1], tc.cipherGap},
				}

				require.Len(t, ciphers, len(tc.evidence))
				for i, evidence := range tc.evidence {
					vuln, span := ciphers[i].vulnerability, ciphers[i].span
					want := expected[i]

					wantPath, wantLine := path, want.line
					if knownOtelcPKCS12Gap && build.Tool() == build.ToolOtelc {
						// The known gap: the file has no directory, and the line is moved.
						wantPath, wantLine = "crypto.go", want.line+want.gap
					}

					assert.Equal(t, model.NewEvidenceString(evidence), vuln.Evidence)
					require.NotNil(t, vuln.Location, evidence)
					assert.Equal(t, want.class, vuln.Location.Class, evidence)
					assert.Equal(t, want.method, vuln.Location.Method, evidence)
					if knownOtelcPKCS12Gap && build.Tool() == build.ToolOtelc {
						if vuln.Location.Path == path && vuln.Location.Line == want.line {
							t.Fatalf("known gap closed: otelc reports the original location of %s; delete knownOtelcPKCS12Gap", evidence)
						}
					}
					assert.Equal(t, wantPath, vuln.Location.Path, evidence)
					assert.Equal(t, wantLine, vuln.Location.Line, evidence)

					if !stackTrace {
						assert.Empty(t, vuln.Location.StackID, evidence)
						assert.Nil(t, span.Tag("_dd.stack"), evidence)
						continue
					}

					// The stack has the same ID as the location, and its first frame
					// is the location.
					stacks := span.Tag("_dd.stack").(map[string][]*instrumentation.StackTrace)["vulnerability"]
					require.Len(t, stacks, 1, evidence)
					assert.NotEmpty(t, vuln.Location.StackID, evidence)
					assert.Equal(t, vuln.Location.StackID, stacks[0].ID, evidence)
					require.NotEmpty(t, stacks[0].Frames, evidence)
					frame := stacks[0].Frames[0]
					assert.Equal(t, "golang.org/x/crypto/pkcs12", frame.Namespace, evidence)
					assert.Equal(t, want.function, frame.Function, evidence)
					assert.Equal(t, wantPath, frame.File, evidence)
					assert.Equal(t, wantLine, frame.Line, evidence)
				}
				assert.Equal(t, before+uint64(len(tc.evidence)), telemetry.ExecutedSink.WeakCipher.Load())
			})
		})
	}
}

// checkWeakCipherNotSinks checks that using a cipher is NOT a sink: only the
// constructors are. It also checks that a cipher that is not weak is not
// reported.
func checkWeakCipherNotSinks(t *testing.T) {
	requireInstrumented(t)

	// The constructors are instrumented, and they run outside of the traced
	// section.
	desBlock, err := des.NewCipher(make([]byte, 8))
	require.NoError(t, err)
	blowfishBlock, err := blowfish.NewCipher(make([]byte, 8))
	require.NoError(t, err)
	rc4Stream, err := rc4.NewCipher([]byte("Key"))
	require.NoError(t, err)

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	before := telemetry.ExecutedSink.WeakCipher.Load()

	assertBlockRoundTrip(t, desBlock, make([]byte, des.BlockSize))
	assertBlockRoundTrip(t, blowfishBlock, make([]byte, blowfish.BlockSize))
	rc4Stream.XORKeyStream(make([]byte, 4), []byte("data"))

	block, err := indirectCipherCall(aes.NewCipher, make([]byte, 16))
	require.NoError(t, err)
	assertBlockRoundTrip(t, block, make([]byte, aes.BlockSize))

	assertNoReport(t, mockTracer, before)
}

func assertNoReport(t *testing.T, mockTracer mocktracer.Tracer, executedBefore uint64) {
	t.Helper()
	assert.Empty(t, mockTracer.FinishedSpans())
	assert.Equal(t, executedBefore, telemetry.ExecutedSink.WeakCipher.Load())
}

func assertBlockRoundTrip(t *testing.T, block stdcipher.Block, plaintext []byte) {
	t.Helper()
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	actual := make([]byte, len(plaintext))
	block.Decrypt(actual, ciphertext)
	assert.Equal(t, plaintext, actual)
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

// indirectPKCS12Decode calls the public PKCS#12 decoder.
func indirectPKCS12Decode(data []byte, password string) (any, *x509.Certificate, error) {
	return /*line /path/to/file.go:1559*/ pkcs12.Decode(data, password)
}
