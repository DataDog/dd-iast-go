// Review reproducers for coarse propagation (prop-string-coarse).

package propagation_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

// sortField is an allowlisting Stringer: fmt prints only a fixed column name.
type sortField string

func (f sortField) String() string {
	if f == "name" {
		return "name"
	}
	return "id"
}

// errCode is a string-kind error whose message never contains the value.
type errCode string

func (errCode) Error() string { return "bad request" }

func TestReviewCoarseFormatTaintsUnprintedStringKindArguments(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	attack, _ := taintString(t, owner, "x'); DROP TABLE users;--", []ranges.Range{{Length: 24, SourceID: 0}})

	cases := []struct {
		name string
		got  string
	}{
		{"Stringer allowlist", iastprop.FmtSprintf("SELECT * FROM t ORDER BY %s", sortField(attack))},
		{"Error method", iastprop.FmtSprint("failure: ", errCode(attack))},
		{"%T verb", iastprop.FmtSprintf("SELECT %T FROM t", attack)},
		{"%.0s verb", iastprop.FmtSprintf("SELECT * FROM t%.0s", attack)},
	}
	for _, c := range cases {
		rs := lookupRanges(s, c.got)
		t.Logf("%-18s output=%q containsAttack=%v ranges=%+v", c.name, c.got, strings.Contains(c.got, attack), rs)
		if !strings.Contains(c.got, attack) && len(rs) > 0 {
			t.Errorf("FALSE POSITIVE (%s): output %q does not contain tainted bytes but is tainted %+v", c.name, c.got, rs)
		}
	}
}

func TestReviewCoarseSourceIsNotTheUnsanitizedContributor(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	// Source 11 carries secure marks 0x6 (sanitized);
	// source 12 carries none. The result is unsafe only because of source 12.
	sanitized, _ := taintString(t, owner, "sanitized", []ranges.Range{{Length: 9, SourceID: 11, Marks: 0x6}})
	raw, _ := taintString(t, owner, "' OR 1=1 --", []ranges.Range{{Length: 11, SourceID: 12, Marks: 0}})
	out := iastprop.FmtSprintf("SELECT * FROM t WHERE a='%s' AND b='%s'", sanitized, raw)
	rs := lookupRanges(s, out)
	t.Logf("output=%q ranges=%+v", out, rs)
	if len(rs) == 1 && rs[0].SourceID == 11 && rs[0].Marks == 0 {
		t.Errorf("MISATTRIBUTION: unsafe coarse range (marks=0) reports source 11 (fully sanitized); unsanitized source 12 is dropped")
	}
}

func TestReviewCoarseFormatMissesIndirectArguments(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	attack, _ := taintString(t, owner, "' OR 1=1 --", []ranges.Range{{Length: 11, SourceID: 0}})
	cases := []struct {
		name string
		got  string
	}{
		{"[]string", iastprop.FmtSprintf("SELECT * FROM t WHERE a IN (%v)", []string{attack})},
		{"struct field", iastprop.FmtSprintf("SELECT * FROM t WHERE a='%v'", struct{ S string }{attack})},
		{"errors.New", iastprop.FmtSprintf("SELECT * FROM t WHERE a='%v'", errors.New(attack))},
	}
	for _, c := range cases {
		rs := lookupRanges(s, c.got)
		t.Logf("%-12s output=%q containsAttack=%v ranges=%+v", c.name, c.got, strings.Contains(c.got, attack), rs)
		if strings.Contains(c.got, attack) && len(rs) == 0 {
			t.Errorf("FALSE NEGATIVE (%s): output contains tainted bytes but is untainted", c.name)
		}
	}
}

func TestReviewToValidUTF8IdentityGuardIsRequired(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	value := strings.Clone("clean valid value")
	replacement, _ := taintString(t, owner, "<<tainted-repl>>", []ranges.Range{{Length: 16, SourceID: 0}})

	guarded := iastprop.StringsToValidUTF8(value, replacement)
	t.Logf("wrapper (guarded): %q ranges=%+v", guarded, lookupRanges(s, guarded))
	if len(lookupRanges(s, guarded)) != 0 {
		t.Errorf("guarded wrapper tainted an unchanged clean value")
	}
	unguarded := propagation.CoarseString(strings.ToValidUTF8(value, replacement), value, replacement)
	t.Logf("without guard     : %q ranges=%+v", unguarded, lookupRanges(s, unguarded))
	if len(lookupRanges(s, unguarded)) == 0 {
		t.Errorf("expected the unguarded call to over-taint (guard would be redundant)")
	}

	// Tainted value, no repair: exact window derivation keeps partial ranges.
	partial, _ := taintString(t, owner, "abc-def-ghi", []ranges.Range{{Start: 4, Length: 3, SourceID: 5}})
	same := iastprop.StringsToValidUTF8(partial, "?")
	t.Logf("tainted no-repair : %q ranges=%+v", same, lookupRanges(s, same))
	if got := lookupRanges(s, same); len(got) != 1 || got[0] != (ranges.Range{Start: 4, Length: 3, SourceID: 5}) {
		t.Errorf("exact ranges not preserved on unchanged ToValidUTF8: %+v", got)
	}
}

func TestReviewCaseStringCoarseWidensPartialTaint(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	q, _ := taintString(t, owner, "SELECT 'café' WHERE x='abc'", []ranges.Range{{Start: 24, Length: 3, SourceID: 2, Marks: 0x4}})
	out := iastprop.StringsToUpper(q)
	t.Logf("non-ASCII upper: %q ranges=%+v (input range covered 3 bytes)", out, lookupRanges(s, out))
	a, _ := taintString(t, owner, "SELECT x='abc'", []ranges.Range{{Start: 10, Length: 3, SourceID: 2, Marks: 0x4}})
	outA := iastprop.StringsToUpper(a)
	t.Logf("ASCII upper    : %q ranges=%+v", outA, lookupRanges(s, outA))
	low := iastprop.StringsToLower(a)
	t.Logf("ASCII lower(unchanged-prefix, alias?) %q ranges=%+v", low, lookupRanges(s, low))
}

// End-to-end: a request-source-tainted value passes through an allowlisting
// Stringer into fmt.Sprintf; the SQL sink's evidence collector (the exact call
// made by iast/database/sql.Report) then collects an unsafe snapshot, so a SQL
// injection is reported for a query containing no request data.
func TestReviewStringerAllowlistReachesSQLSinkAsUnsafe(t *testing.T) {
	enableIAST(t)
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("scope not created")
	}
	t.Cleanup(func() { scope.Finish() })
	param := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "sort"}, strings.Clone("name; DROP TABLE users"))
	if !taint.IsTaintedString(param) {
		t.Fatal("source not tainted")
	}
	query := iastprop.FmtSprintf("SELECT * FROM users ORDER BY %s", sortField(param))
	snapshot, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	t.Logf("query=%q containsParam=%v status=%v (StatusCollected=%v)", query, strings.Contains(query, param), status, evidence.StatusCollected)
	if status == evidence.StatusCollected {
		for i := 0; i < snapshot.PartCount(); i++ {
			part, _ := snapshot.PartAt(i)
			v, _ := snapshot.PartValue(part)
			t.Logf("  part %d source=%d value=%q", i, part.Source, v)
		}
		for i := 0; i < snapshot.SourceCount(); i++ {
			src, _ := snapshot.SourceAt(i)
			t.Logf("  source %d origin=%v name=%q value=%q", i, src.Origin, src.Name, src.Value)
		}
		t.Errorf("FALSE POSITIVE: SQL sink would report injection for a query without request data")
	}
}
