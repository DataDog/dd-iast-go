// Reviewer reproducer: exercise every exported taint.* function concurrently
// with adversarial (nil/empty/oversized/invalid) inputs to verify the public
// API never panics and behaves per its documented contract. Not part of the
// permanent test suite.
package taint_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

func TestReviewPublicAPINilAndEmptySafety(t *testing.T) {
	// No active scope at all: context.Background() carries no *request.Scope.
	if got := taint.TaintString(context.Background(), taint.Source{}, ""); got != "" {
		t.Fatalf("empty string round-trip changed: %q", got)
	}
	if got := taint.TaintString[string](nil, taint.Source{Origin: taint.OriginHttpRequestBody}, "value"); got != "value" { //nolint:staticcheck // deliberately passing nil ctx
		t.Fatalf("nil ctx changed value: %q", got)
	}
	var nilBytes []byte
	if got := taint.TaintBytes(context.Background(), taint.Source{Origin: taint.OriginHttpRequestBody}, nilBytes); got != nil {
		t.Fatalf("nil []byte round-trip changed: %v", got)
	}
	if taint.IsTaintedString("") {
		t.Fatal("empty string reported tainted")
	}
	if taint.IsTaintedBytes(nilBytes) {
		t.Fatal("nil []byte reported tainted")
	}
	if taint.VisitString("", func(taint.Range) bool { t.Fatal("visited empty string"); return true }) {
		t.Fatal("VisitString delivered on empty string")
	}
	if taint.VisitBytes(nilBytes, func(taint.Range) bool { t.Fatal("visited nil bytes"); return true }) {
		t.Fatal("VisitBytes delivered on nil bytes")
	}
	// NOTE (finding F2): a bare untyped `nil` literal, e.g.
	// taint.IsTaintedBytes(nil) or taint.VisitBytes(nil, ...), fails to
	// compile with "cannot infer T" because Go cannot infer a ~[]byte type
	// parameter from an untyped nil. Callers must spell []byte(nil) or use a
	// typed nil variable, as nilBytes does here. Captured separately in
	// nil-inference-error.txt.</newText>}, {
	if taint.VisitString("attacker", nil) {
		t.Fatal("VisitString with nil visitor reported delivery")
	}
	if taint.VisitBytes([]byte("attacker"), nil) {
		t.Fatal("VisitBytes with nil visitor reported delivery")
	}
	// Zero-value Marks/Origin/VulnerabilityType, including out-of-range values.
	var m taint.Marks
	if m.Has(taint.VulnerabilityType(255)) {
		t.Fatal("out-of-range VulnerabilityType reported marked")
	}
	if m.Has(0) {
		t.Fatal("zero VulnerabilityType reported marked")
	}
}

func TestReviewPublicAPIInvalidOriginDropsSilently(t *testing.T) {
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})
	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("scope not created/active")
	}
	t.Cleanup(scope.Finish)

	// Origin(0) is the unnamed blank iota; Origin(255) is past OriginCount.
	// Neither is exported as a named constant, but nothing in taint.go's
	// exported signature stops a caller from passing them: Source.Origin is a
	// plain Origin (uint8) field.
	for _, bad := range []taint.Origin{0, 255} {
		value := "value-" + string(rune(bad))
		got := taint.TaintString(ctx, taint.Source{Origin: bad, Name: "n"}, value)
		if got != value {
			t.Fatalf("origin %d: TaintString mutated value to %q", bad, got)
		}
		if taint.IsTaintedString(got) {
			t.Fatalf("origin %d: value reported tainted despite invalid origin", bad)
		}
	}
}

// TestReviewPublicAPIConcurrentStress hammers every exported entry point from
// many goroutines while Begin/Finish cycle scopes, including nil/degenerate
// arguments interleaved with valid ones. Run with -race.
func TestReviewPublicAPIConcurrentStress(t *testing.T) {
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})

	const workers = 32
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				ctx, scope, created := request.Begin(context.Background())
				if !created {
					continue
				}
				value := strings.Repeat("a", (w%5)+1) // exercises the <2-byte drop path too
				managed := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p"}, value)
				_ = taint.IsTaintedString(managed)
				taint.VisitString(managed, func(r taint.Range) bool { return true })

				b := []byte(strings.Repeat("b", (w%5)+1))
				managedB := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"}, b)
				_ = taint.IsTaintedBytes(managedB)
				taint.VisitBytes(managedB, func(r taint.Range) bool { return true })

				// Nil/invalid inputs interleaved on the same goroutines/scopes.
				taint.TaintString(ctx, taint.Source{}, "")
				taint.TaintBytes(ctx, taint.Source{Origin: taint.Origin(255)}, []byte(nil))
				taint.VisitString("", nil)

				scope.Finish()
			}
		}(w)
	}
	wg.Wait()
}
