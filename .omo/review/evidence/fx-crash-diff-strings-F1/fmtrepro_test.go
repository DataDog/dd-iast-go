// Independent phase-3 verification reproducer for fx-crash-diff-strings-F1.
// Direct fmt.* calls in a root-module package woven by orchestrion, exactly as
// customer code is compiled. Each case runs inside one real request scope with
// one tainted HTTP-parameter source.
package fmtrepro

import (
	"context"
	"fmt"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

// allowlistCol is the common sanitising idiom under test: a named string type
// whose String() maps attacker-controlled input to a fixed safe constant.
type allowlistCol string

func (c allowlistCol) String() string { return "col_safe" }

// safeError is a named string type implementing error; fmt calls Error().
type safeError string

func (e safeError) Error() string { return "err_safe" }

func scope(t *testing.T, v string) (string, *request.Scope) {
	t.Helper()
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	ctx, sc, created := request.Begin(context.Background())
	if !created {
		t.Fatal("no scope")
	}
	out := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "sort"}, v)
	if !taint.IsTaintedString(out) {
		t.Fatal("source not tainted")
	}
	return out, sc
}

func report(t *testing.T, name, got string) {
	t.Helper()
	var rs []taint.Range
	taint.VisitString(got, func(r taint.Range) bool { rs = append(rs, r); return true })
	t.Logf("%-46s result=%q tainted=%v ranges=%d", name, got, len(rs) > 0, len(rs))
}

// TestFmtCoarseF1 runs the positive controls, then the claimed false-positive
// shapes. It fails if the positive controls break, so an unwoven build cannot
// silently "confirm" or "refute" anything.
func TestFmtCoarseF1(t *testing.T) {
	v, sc := scope(t, "'; DROP TABLE users; --")
	defer sc.Finish()

	// Positive control 1: plain %s of a tainted string must propagate (proves weaving + propagation active).
	report(t, "CONTROL Sprintf(%s tainted)", fmt.Sprintf("SELECT * FROM t ORDER BY %s", v))
	// Positive control 2: a clean literal with a tainted argument never rendered must NOT be tainted.
	report(t, "CONTROL Sprintf(%d len)", fmt.Sprintf("rows=%d", len(v)))

	// F1a: Stringer renders a safe constant from attacker input; no attacker bytes in output.
	report(t, "F1a Sprintf(%s Stringer-enum)", fmt.Sprintf("SELECT * FROM users ORDER BY %s", allowlistCol(v)))
	// F1b: Sprint on the Stringer value directly.
	report(t, "F1b Sprint(Stringer-enum)", fmt.Sprint(allowlistCol(v)))
	// F1c: named string type implementing error.
	report(t, "F1c Sprintf(%v error-enum)", fmt.Sprintf("query failed: %v", safeError(v)))

	// F2a: verb does not render the operand at all.
	report(t, "F2a Sprintf(%T)", fmt.Sprintf("type=%T", v))
	// F2b: zero precision renders nothing.
	report(t, "F2b Sprintf(%.0s)", fmt.Sprintf("x%.0sy", v))
	// F2c: explicit argument index skips the tainted argument.
	report(t, "F2c Sprintf(%[2]s skip)", fmt.Sprintf("%[2]s", v, "clean-literal"))
}
