// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package suite holds the end-to-end checks of the IAST detections that are
// ported to otelc. Every setup module (one per way to import this module in the
// tool file of an application) runs the same checks, so the setups can only
// differ in the way the rules are selected.
package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/instrumentation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	config.Enabled = true
	config.RequestSamplingPct = 100
	// The same operation is run several times (and with several settings).
	config.DeduplicationEnabled = false
}

// pkgPath is the import path of this package. The test functions below run in
// it, so the locations that IAST reports refer to it.
const pkgPath = "github.com/DataDog/dd-iast-go/_integration/otelc/internal/suite"

// Config tells which detections the setup under test enables. The weak hash
// detection is always enabled: every setup imports it.
type Config struct {
	// Cipher is true if the setup imports the weak cipher detection (the root
	// package, or iast/crypto/cipher). If it is false, the weak cipher functions
	// are linked in the binary but they must NOT be instrumented.
	Cipher bool
}

// sinkPackage describes the rules that must match in one target package.
type sinkPackage struct {
	// module is the import path of the target package.
	module string
	// file is the file that the "add_file" rule copies into the package.
	file string
	// declarations is the name of the "add_file" rule.
	declarations string
	// rules are the names of the "inject_code" rules: one for each sink.
	rules []string
}

// The tables below are the specification of the rules. The count of
// instrumented sinks of a type is the number of "inject_code" rules of its
// packages, and it is the same as the Orchestrion count.
var (
	hashPackages = []sinkPackage{
		{"golang.org/x/crypto/md4", "otelc_decl_md4.go", "md4_declarations", []string{"md4_new"}},
		{"crypto/md5", "otelc_decl_md5.go", "md5_declarations", []string{"md5_new", "md5_sum"}},
		{"crypto/sha1", "otelc_decl_sha1.go", "sha1_declarations", []string{"sha1_new", "sha1_sum"}},
	}
	cipherPackages = []sinkPackage{
		{"crypto/des", "otelc_decl_des.go", "des_declarations", []string{"des_new_cipher", "des_new_triple_des_cipher"}},
		{"crypto/rc4", "otelc_decl_rc4.go", "rc4_declarations", []string{"rc4_new_cipher"}},
		{"golang.org/x/crypto/blowfish", "otelc_decl_blowfish.go", "blowfish_declarations", []string{"blowfish_new_cipher", "blowfish_new_salted_cipher"}},
		{"golang.org/x/crypto/pkcs12/internal/rc2", "otelc_decl_rc2.go", "rc2_declarations", []string{"rc2_new"}},
		{"golang.org/x/crypto/pkcs12", "otelc_decl_pkcs12.go", "pkcs12_declarations", []string{"pkcs12_triple_des_create", "pkcs12_rc2_create"}},
	}
)

func (c Config) packages() (hash, cipher []sinkPackage) {
	if c.Cipher {
		return hashPackages, cipherPackages
	}
	return hashPackages, nil
}

func sinkCount(packages []sinkPackage) uint {
	var count uint
	for _, pkg := range packages {
		count += uint(len(pkg.rules))
	}
	return count
}

// Run runs all checks. The binary under test must be built with otelc or with
// Orchestrion. A plain "go test" is a mistake, and the checks fail.
func Run(t *testing.T, cfg Config) {
	t.Run("BuildTool", checkBuildTool)
	t.Run("InstrumentedSinks", func(t *testing.T) { checkInstrumentedSinks(t, cfg) })
	t.Run("MatchedRules", func(t *testing.T) { checkMatchedRules(t, cfg) })

	t.Run("WeakHash", checkWeakHash)
	t.Run("WeakHashNotSinks", checkWeakHashNotSinks)
	t.Run("CryptoHashNew", checkCryptoHashNew)

	t.Run("WeakCipher", func(t *testing.T) { checkWeakCipher(t, cfg) })
	t.Run("SaltedBlowfish", func(t *testing.T) { checkSaltedBlowfish(t, cfg) })
	t.Run("PKCS12", func(t *testing.T) { checkPKCS12(t, cfg) })
	t.Run("WeakCipherNotSinks", checkWeakCipherNotSinks)

	t.Run("SpanFinish", checkSpanFinish)
}

// requireInstrumented fails the test if the binary was not built with a
// compile-time instrumentation tool. This module only makes sense when it is
// built with otelc or with Orchestrion, so a plain "go test" is a mistake: the
// test fails instead of skipping, to avoid a silent pass in CI.
func requireInstrumented(t *testing.T) {
	t.Helper()
	if !build.Instrumented() {
		t.Fatal("this binary was not built with otelc or Orchestrion; " +
			"use 'go tool otelc go test . ./internal/...' or 'go tool orchestrion go test . ./internal/...' " +
			"(in a setup module: 'go tool otelc go test ./...')")
	}
}

func checkBuildTool(t *testing.T) {
	requireInstrumented(t)
	t.Logf("built with: %s", build.Tool())
	assert.Contains(t, []string{build.ToolOtelc, build.ToolOrchestrion}, build.Tool())
}

// checkInstrumentedSinks checks the number of instrumented sinks that was
// recorded at build time. It is the same for both tools. All the packages of the
// sinks are linked in this binary, so each rule counts.
func checkInstrumentedSinks(t *testing.T, cfg Config) {
	requireInstrumented(t)

	hash, cipher := cfg.packages()
	expected := map[constants.VulnerabilityType]uint{
		constants.VulnerabilityTypeWeakHash:   sinkCount(hash),   // md4: 1, md5: 2, sha1: 2
		constants.VulnerabilityTypeWeakCipher: sinkCount(cipher), // des: 2, rc4: 1, blowfish: 2, rc2: 1, pkcs12: 2
	}
	require.EqualValues(t, 5, expected[constants.VulnerabilityTypeWeakHash])

	for i, count := range telemetry.InstrumentedSink {
		vulnerabilityType := constants.VulnerabilityType(i)
		assert.Equal(t, expected[vulnerabilityType], count, "sink count for %s", vulnerabilityType)
	}
}

// checkMatchedRules checks that otelc matched each expected rule exactly one
// time, and no other rule. A rule file that two imports reach (for example the
// root package and a sub-package) must not load twice. It is also the guard for
// the count of instrumented sinks: the file that otelc copies into each target
// package registers a fixed count, which must be equal to the number of
// "inject_code" rules that really matched (the tables above, which
// checkInstrumentedSinks compares with the registered counts).
//
// A setup that does not import the weak cipher detection must match no rule of
// it.
func checkMatchedRules(t *testing.T, cfg Config) {
	requireInstrumented(t)
	if build.Tool() != build.ToolOtelc {
		t.Skip("matched rules are only reported by otelc")
	}

	data, err := os.ReadFile(filepath.Join(".otelc-build", "matched.json"))
	require.NoError(t, err, "otelc writes the matched rules in this file during the build")

	// All kinds of rules have the same shape: a map from source file to rules,
	// except the "file" rules, which are a list.
	type namedRule struct {
		Name string `json:"name"`
		File string `json:"file"`
	}
	var sets []struct {
		ModulePath string                 `json:"module_path"`
		RawRules   map[string][]namedRule `json:"raw_rules"`
		DeclRules  map[string][]namedRule `json:"decl_rules"`
		FuncRules  map[string][]namedRule `json:"func_rules"`
		FileRules  []namedRule            `json:"file_rules"`
	}
	require.NoError(t, json.Unmarshal(data, &sets))

	// Each entry is "<kind>:<module>:<rule>". A rule that was loaded or matched
	// twice appears twice in this list.
	var matched []string
	for _, set := range sets {
		add := func(kind string, rules map[string][]namedRule) {
			for _, list := range rules {
				for _, rule := range list {
					matched = append(matched, kind+":"+set.ModulePath+":"+rule.Name)
				}
			}
		}
		add("inject_code", set.RawRules)
		add("decl", set.DeclRules)
		add("func", set.FuncRules)
		for _, rule := range set.FileRules {
			matched = append(matched, "add_file:"+set.ModulePath+":"+rule.Name+"="+rule.File)
		}
	}

	expected := []string{
		// internal/build/otelc.yml (core)
		"decl:github.com/DataDog/dd-iast-go/internal/build:build_flag_otelc",
		// instrumentation/spans/otelc.yml (core)
		"inject_code:github.com/DataDog/dd-trace-go/v2/ddtrace/tracer:span_finish",
		"add_file:github.com/DataDog/dd-trace-go/v2/ddtrace/tracer:span_finish_declarations=otelc_decl_finish.go",
	}
	hash, cipher := cfg.packages()
	for _, pkg := range append(append([]sinkPackage(nil), hash...), cipher...) {
		// iast/crypto/hash/otelc.yml and iast/crypto/cipher/otelc.yml
		expected = append(expected, "add_file:"+pkg.module+":"+pkg.declarations+"="+pkg.file)
		for _, rule := range pkg.rules {
			expected = append(expected, "inject_code:"+pkg.module+":"+rule)
		}
	}

	// Our rules: each one must match exactly one time, and no other rule of this
	// module may match (the rules of the weak cipher detection must not match in a
	// setup that does not import it).
	remaining := append([]string(nil), matched...)
	for _, want := range expected {
		found := slices.Index(remaining, want)
		if !assert.GreaterOrEqual(t, found, 0, "rule did not match: %s", want) {
			continue
		}
		remaining = slices.Delete(remaining, found, found+1)
		assert.NotContains(t, remaining, want, "rule matched more than one time: %s", want)
	}

	// The rules of dd-trace-go come from the tool file of the application. They
	// must be present, so the tracer and the goroutine-local storage work with
	// our rules. We do not assert the full list: it changes with the tracer
	// version, and with the integrations that the application imports. We only
	// assert the list of the rules in the tracer package, which our own
	// "span_finish" rule shares (see below). Each rule is removed from the
	// remaining list once it is found.
	for _, want := range ddTraceGoRules {
		found := slices.Index(remaining, want)
		if assert.GreaterOrEqual(t, found, 0, "dd-trace-go rule did not match: %s", want) {
			remaining = slices.Delete(remaining, found, found+1)
		}
	}

	// No other rule may match in the packages that our rules target. The
	// disabled cipher rules would be here. The tracer package is a target of
	// "span_finish": only the known rules of dd-trace-go may be there with it.
	// A new rule of dd-trace-go there changes the goroutine-local storage or
	// the span: add it to ddTraceGoRules after checking it with our rule.
	ours := map[string]bool{
		"github.com/DataDog/dd-iast-go/internal/build":     true,
		"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer": true,
	}
	for _, pkg := range append(append([]sinkPackage(nil), hashPackages...), cipherPackages...) {
		ours[pkg.module] = true
	}
	for _, other := range remaining {
		_, rest, _ := strings.Cut(other, ":")
		module, _, _ := strings.Cut(rest, ":")
		assert.False(t, ours[module], "unexpected rule: %s", other)
	}
}

// ddTraceGoRules are the rules of dd-trace-go that the tool file of the
// application selects (the core tracer rules), and that dd-iast-go needs. In
// particular, "span_gls_finish" and our "span_finish" both inject code at the
// start of (*Span).Finish.
var ddTraceGoRules = []string{
	"decl:github.com/DataDog/dd-trace-go/v2/internal/otelc:enable_otelc_flag",
	"inject_code:github.com/DataDog/dd-trace-go/v2/ddtrace/tracer:span_gls_context_with_span",
	"inject_code:github.com/DataDog/dd-trace-go/v2/ddtrace/tracer:span_gls_span_from_context",
	"inject_code:github.com/DataDog/dd-trace-go/v2/ddtrace/tracer:span_gls_finish",
	"inject_code:github.com/DataDog/dd-trace-go/v2/ddtrace/tracer:span_gls_clear",
	"inject_code:runtime:gls_goexit1_reset",
	"add_file:runtime:gls_runtime_accessors=gls_accessors.go",
}

// vulnerability describes the report that a sink must produce.
type vulnerability struct {
	typ      constants.VulnerabilityType
	evidence string
	// function is the name of the function that calls the sink, as it must appear
	// in the location, for example "indirectCall0[...]".
	function string
	// line is the line of the call, set by the "line" directive of the caller.
	line uint32
}

// singleVulnerabilityEvent returns the event of the only span that the sink
// made. The test fails if there is not exactly one span.
func singleVulnerabilityEvent(t *testing.T, mockTracer mocktracer.Tracer) (model.Event, *mocktracer.Span) {
	t.Helper()
	spanList := mockTracer.FinishedSpans()
	require.Len(t, spanList, 1)
	span := spanList[0]
	return vulnerabilityEvent(t, span), span
}

func vulnerabilityEvent(t *testing.T, span *mocktracer.Span) model.Event {
	t.Helper()
	require.Equal(t, "vulnerability", span.OperationName())
	require.Equal(t, "vulnerability", span.Tag(ext.SpanType))
	require.Equal(t, 1.0, span.Tag(spans.SpanTagEnabled))

	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(span.Tag(spans.SpanTagJson).(string)), &event))
	return event
}

// assertSingleReport checks that the sink made exactly one report, which is the
// expected one: evidence, location (the caller of the sink, never a frame of the
// library), stack trace, and count of executed sinks. executed is the counter of
// the vulnerability type, and before its value before the call.
func assertSingleReport(
	t *testing.T,
	mockTracer mocktracer.Tracer,
	expected vulnerability,
	stackTrace bool,
	executed interface{ Load() uint64 },
	before uint64,
) {
	t.Helper()

	event, span := singleVulnerabilityEvent(t, mockTracer)

	var stackID string
	if stackTrace {
		stacks := span.Tag("_dd.stack").(map[string][]*instrumentation.StackTrace)["vulnerability"]
		require.Len(t, stacks, 1)
		stackID = stacks[0].ID
		// The first frame of the recorded stack is the caller of the sink, and not
		// a frame of the library. (Its index differs: Orchestrion keeps the index
		// of the stack before the tracer removes the generated frame, otelc has
		// no generated frame and the index is shifted to 0 by IAST.)
		require.NotEmpty(t, stacks[0].Frames)
		assert.Equal(t, expected.function, stacks[0].Frames[0].Function)
		assert.Equal(t, pkgPath, stacks[0].Frames[0].Namespace)
	} else {
		assert.Nil(t, span.Tag("_dd.stack"))
	}

	require.Len(t, event.Vulnerabilities, 1)
	assert.Equal(t,
		model.Event{
			Vulnerabilities: []model.Vulnerability{
				model.NewVulnerability(
					expected.typ,
					model.NewEvidenceString(expected.evidence),
					&model.Location{
						SpanID:  span.Context().SpanID(),
						StackID: stackID,
						Path:    "/path/to/file.go",
						Line:    expected.line,
						Method:  pkgPath + "." + expected.function,
					},
				),
			},
		},
		event)
	assert.Equal(t, before+1, executed.Load(), "count of executed sinks")
}

// withStackTrace runs fn for each setting of the stack trace collection.
func withStackTrace(t *testing.T, fn func(t *testing.T, stackTrace bool)) {
	t.Helper()
	for _, stackTrace := range []bool{true, false} {
		name := "stack_trace=false"
		if stackTrace {
			name = "stack_trace=true"
		}
		t.Run(name, func(t *testing.T) {
			original := config.StackTraceEnabled
			config.StackTraceEnabled = stackTrace
			t.Cleanup(func() { config.StackTraceEnabled = original })
			fn(t, stackTrace)
		})
	}
}
