package seqreview_test

import (
	"iter"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode"

	app "github.com/DataDog/dd-iast-go/iast/seqreview"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

// Function-value calls are deliberately outside the direct-call weaving scope.
// They provide a native control within the same binary.
var (
	nativeSplit      = strings.SplitSeq
	nativeSplitAfter = strings.SplitAfterSeq
	nativeLines      = strings.Lines
	nativeFields     = strings.FieldsSeq
	nativeFieldsFunc = strings.FieldsFuncSeq
	saved            iter.Seq[string]
	total            int
)

const input = "alpha beta\ngamma delta"

var constructors = []struct {
	name   string
	direct func(string) iter.Seq[string]
	native func(string) iter.Seq[string]
}{
	{"SplitSeq", app.Split, func(s string) iter.Seq[string] { return nativeSplit(s, " ") }},
	{"SplitAfterSeq", app.SplitAfter, func(s string) iter.Seq[string] { return nativeSplitAfter(s, " ") }},
	{"Lines", app.Lines, func(s string) iter.Seq[string] { return nativeLines(s) }},
	{"FieldsSeq", app.Fields, func(s string) iter.Seq[string] { return nativeFields(s) }},
	{"FieldsFuncSeq", app.FieldsFunc, func(s string) iter.Seq[string] { return nativeFieldsFunc(s, unicode.IsSpace) }},
}

func TestNoOwnerAllocationParity(t *testing.T) {
	// Given: default runtime configuration, no request or owner ever created.
	t.Logf("toolchain=%s woven=%t enabled=%t sampling=%d max_concurrent=%d no_owner=%t",
		runtime.Version(), built.WithOrchestrion, config.Enabled,
		config.RequestSamplingPct, config.MaxConcurrentRequests, request.ActiveStore() == nil)
	if request.ActiveStore() != nil {
		t.Fatal("test requires no active taint owner")
	}
	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			// When: a typed sequence escapes for deferred consumption.
			native := testing.AllocsPerRun(1000, func() { saved = tc.native(input) })
			direct := testing.AllocsPerRun(1000, func() { saved = tc.direct(input) })
			// Then: inactive instrumentation should not allocate a wrapper.
			t.Logf("native=%.0f direct=%.0f extra=%.0f allocs/call", native, direct, direct-native)
			if direct != native {
				t.Errorf("no-owner allocation regression: native %.0f, direct %.0f", native, direct)
			}
		})
	}
}

func TestSequenceValues(t *testing.T) {
	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			// Given the same clean input, compare deferred consumption.
			want := slices.Collect(tc.native(input))
			saved = tc.direct(input)
			got := slices.Collect(saved)
			if !slices.Equal(got, want) {
				t.Fatalf("values: got %q, want %q", got, want)
			}
		})
	}
}

func BenchmarkEscapingSequence(b *testing.B) {
	if request.ActiveStore() != nil {
		b.Fatal("benchmark requires no active taint owner")
	}
	for _, tc := range constructors {
		b.Run(tc.name+"/native", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				saved = tc.native(input)
			}
		})
		b.Run(tc.name+"/direct", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				saved = tc.direct(input)
			}
		})
	}
}

func BenchmarkImmediateSplit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		total = app.ConsumeSplit(input)
	}
}
