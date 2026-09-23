package propagation_test

import (
	"context"
	"errors"

	"fmt"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"testing"

	testapp "github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func reviewRanges(value string) string {
	out := ""
	taint.VisitString(value, func(r taint.Range) bool {
		out += fmt.Sprintf("[%d,+%d src=%s] ", r.Start, r.Length, r.Source.Name)
		return true
	})
	if out == "" {
		return "UNTAINTED"
	}
	return out
}

func TestReviewFmtMethodsInvokedOnce(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	value := activeString(t, "attacker")
	calls := 0
	got := testapp.ReviewSprint(testapp.CountingStringer{Calls: &calls, Value: value})
	t.Logf("Stringer: result=%q calls=%d ranges=%s", got, calls, reviewRanges(got))
	if calls != 1 || got != "attacker" {
		t.Errorf("Stringer invoked %d times, result %q", calls, got)
	}
	calls = 0
	got = testapp.ReviewSprintf("%v|%s", testapp.CountingFormatter{Calls: &calls, Value: value}, testapp.CountingError{Calls: &calls, Value: value})
	t.Logf("Formatter+error: result=%q calls=%d ranges=%s", got, calls, reviewRanges(got))
	if calls != 2 {
		t.Errorf("methods invoked %d times, want 2", calls)
	}
	calls = 0
	got = testapp.ReviewSprintf("%s", testapp.CountingError{Calls: &calls, Value: value})
	if calls != 1 {
		t.Errorf("error invoked %d times", calls)
	}
	if testapp.ReviewSprintMulti() != "abcd" {
		t.Errorf("multi-value arg broken")
	}
	if testapp.ReviewSprint() != "" || testapp.ReviewSprintf("x") != "x" {
		t.Errorf("empty args broken")
	}
}

func TestReviewFmtOverTaint(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	value := activeString(t, "attacker")
	cases := map[string]string{
		"RedactedSecret Stringer (%s)": testapp.ReviewSprintf("SELECT '%s'", testapp.RedactedSecret(value)),
		"ConstFormatter (%v)":          testapp.ReviewSprintf("SELECT %v", testapp.ConstFormatter(value)),
		"%T":                           testapp.ReviewSprintfType(value),
		"%.0s":                         testapp.ReviewSprintfZeroPrecision(value),
		"%[2]s":                        testapp.ReviewSprintfIndexed(value),
		"%d of []byte":                 testapp.ReviewSprintf("SELECT %d", []byte(value)),
	}
	for name, got := range cases {
		t.Logf("OVERTAINT-CHECK %-30s result=%q contains-input=%v ranges=%s", name, got, contains(got, value), reviewRanges(got))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestReviewFmtUnderTaint(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	value := activeString(t, "attacker")
	ptr := value
	cases := map[string]string{
		"struct %v":        testapp.ReviewSprintf("SELECT %v", testapp.Holder{Field: value}),
		"slice %v":         testapp.ReviewSprintf("SELECT %v", []string{value}),
		"map %v":           testapp.ReviewSprintf("SELECT %v", map[string]string{"k": value}),
		"*string %s":       testapp.ReviewSprintf("SELECT %s", &ptr),
		"Stringer wrap %s": testapp.ReviewSprintf("SELECT %s", testapp.Wrap{S: value}),
		"error %v":         testapp.ReviewSprintf("SELECT %v", errors.New(value)),
		"direct %s":        testapp.ReviewSprintf("SELECT %s", value),
		"direct %q":        testapp.ReviewSprintf("SELECT %q", value),
		"width %20s":       testapp.ReviewSprintf("SELECT %20s", value),
		"precision %.3s":   testapp.ReviewSprintf("SELECT %.3s", value),
	}
	for name, got := range cases {
		t.Logf("UNDERTAINT-CHECK %-18s result=%q ranges=%s", name, got, reviewRanges(got))
	}
}

func TestReviewFmtAllowlistStringerFalsePositive(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	order := activeString(t, "desc; DROP TABLE users")
	query := testapp.ReviewOrderQuery(order)
	t.Logf("ALLOWLIST query=%q tainted=%v ranges=%s", query, taint.IsTaintedString(query), reviewRanges(query))
	if taint.IsTaintedString(query) {
		t.Errorf("FALSE POSITIVE: query built only from constants is tainted")
	}
}

func TestReviewBuilderFprintf(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	value := activeString(t, "attacker")
	got := testapp.ReviewBuilderFprintf(value, "clean")
	t.Logf("BUILDER-FPRINTF result=%q ranges=%s", got, reviewRanges(got))
	got = testapp.ReviewBuilderFprintfFirst(value, "clean")
	t.Logf("BUILDER-FPRINTF-FIRST result=%q ranges=%s", got, reviewRanges(got))
}

func TestReviewFmtTwoSources(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("no scope")
	}
	defer scope.Finish()
	a := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "a"}, "alpha")
	b := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "b"}, "bravo")
	got := testapp.ReviewSprintfTwo(a, b)
	t.Logf("TWO-SOURCES sprintf result=%q ranges=%s", got, reviewRanges(got))
	concat := testapp.ReviewPrefix(a)
	t.Logf("CONCAT reference result=%q ranges=%s", concat, reviewRanges(concat))
	got = testapp.ReviewSprintf("x%sy", concat)
	t.Logf("PARTIAL-INPUT sprintf result=%q ranges=%s", got, reviewRanges(got))
}

func TestReviewUnquoteAndUnescapeAlias(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	value := activeString(t, "attacker")
	quoted := testapp.ReviewQuoteWrap(value)
	t.Logf("quoted=%q ranges=%s", quoted, reviewRanges(quoted))
	unquoted, err := testapp.ReviewUnquote(quoted)
	t.Logf("unquoted=%q err=%v ranges=%s", unquoted, err, reviewRanges(unquoted))
	raw := "`" + "ab" + "`"
	unraw, err := testapp.ReviewUnquote(raw)
	t.Logf("raw clean unquote=%q err=%v ranges=%s", unraw, err, reviewRanges(unraw))
	prefixed := testapp.ReviewPrefix(value) // "ab"+attacker+"cd", ranges [2,+8)
	un, err := testapp.ReviewQueryUnescape(prefixed)
	t.Logf("queryunescape alias=%q err=%v ranges=%s", un, err, reviewRanges(un))
	esc := testapp.ReviewQueryEscape(prefixed)
	t.Logf("queryescape alias=%q ranges=%s", esc, reviewRanges(esc))
	withPlus := testapp.ReviewPrefix(activeString(t, "a+b"))
	un2, err := testapp.ReviewQueryUnescape(withPlus)
	t.Logf("queryunescape changed=%q err=%v ranges=%s", un2, err, reviewRanges(un2))
	bad, err := testapp.ReviewUnquote(testapp.ReviewPrefix(value))
	t.Logf("unquote error=%q err=%v ranges=%s", bad, err, reviewRanges(bad))
}
