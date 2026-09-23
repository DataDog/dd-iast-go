package redaction

import (
	"strings"
	"testing"
)

// Review reproducer (crash-fuzz-redaction): scanOracleQuotes runs over the raw
// query without tracking ordinary '...' literal state, so a standard literal
// ending in q/Q followed by a non-identifier byte opens a bogus Oracle q-quote.
// The bogus span re-synchronizes the SQL lexer so that a later ordinary string
// literal body is lexed as a bare identifier and is NOT marked sensitive.
func TestReviewOracleQuoteDesyncLeaksLiteral(t *testing.T) {
	cases := []string{
		"SELECT * FROM jobs WHERE status IN ('Q','R','') AND token = 'hunter2'",
		"SELECT * FROM t WHERE a = 'Q' OR b IN (',','') AND pwd='hunter2'",
		"SELECT * FROM t WHERE c IN ('q','x','-') AND pwd='hunter2'",
		// control: no q-literal, literal must be covered
		"SELECT * FROM jobs WHERE status IN ('P','R','') AND token = 'hunter2'",
	}
	leaks := 0
	for _, query := range cases {
		analysis := AnalyzeSQL(query)
		secret := strings.Index(query, "hunter2")
		covered := make([]bool, len(query))
		for _, interval := range analysis.Sensitive {
			for i := interval.Start; i < interval.Start+interval.Length; i++ {
				covered[i] = true
			}
		}
		var exposed strings.Builder
		for i := secret; i < secret+len("hunter2"); i++ {
			if !covered[i] {
				exposed.WriteByte(query[i])
			}
		}
		t.Logf("query=%q status=%d sensitive=%v exposedSecretBytes=%q", query, analysis.Status, analysis.Sensitive, exposed.String())
		if exposed.Len() > 0 {
			leaks++
		}
	}
	if leaks > 0 {
		t.Errorf("%d queries leak the literal 'hunter2' unredacted", leaks)
	}
}

// Probe other literal syntaxes for coverage of the secret (informational).
func TestReviewLiteralSyntaxProbe(t *testing.T) {
	for _, query := range []string{
		`SELECT * FROM t WHERE a = 'it\'s hunter2'`,
		`SELECT * FROM t WHERE a = 'it''s hunter2'`,
		`SELECT * FROM t WHERE a = E'x\'hunter2'`,
		`SELECT * FROM t WHERE a = N'hunter2'`,
		`SELECT * FROM t WHERE a = "hunter2"`,
		`SELECT * FROM t WHERE a = $$hunter2$$`,
		`SELECT * FROM t WHERE a = $x$hunter2$x$`,
		`SELECT * FROM t WHERE a = q'[hunter2]'`,
		`SELECT * FROM t WHERE a = 'q' || 'hunter2'`,
		`SELECT * FROM t WHERE a = 'Q'||'x'||'hunter2'`,
		`SELECT * FROM t WHERE a = '-Q'||'x'||' hunter2'`,
	} {
		analysis := AnalyzeSQL(query)
		secret := strings.Index(query, "hunter2")
		covered := make([]bool, len(query))
		for _, interval := range analysis.Sensitive {
			for i := interval.Start; i < interval.Start+interval.Length; i++ {
				covered[i] = true
			}
		}
		var exposed strings.Builder
		for i := secret; i < secret+len("hunter2"); i++ {
			if !covered[i] {
				exposed.WriteByte(query[i])
			}
		}
		t.Logf("PROBE query=%q status=%d exposed=%q", query, analysis.Status, exposed.String())
	}
}

// End to end through BuildWithSensitive: a tainted request value placed inside
// a SQL string literal after the bogus q-quote leaves the process raw, both as
// the evidence part and as the wire source value. The control query (literal
// 'P' instead of 'Q') redacts it.
func TestReviewOracleQuoteDesyncLeaksTaintedLiteralEndToEnd(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	for _, status := range []string{"Q", "P"} {
		prefix := "SELECT * FROM jobs WHERE status IN ('" + status + "','R','') AND note = '"
		snapshot := compositeSnapshot(t, prefix, "userSecret42", "'")
		analysis := AnalyzeSQL(snapshot.Value())
		result, ok := BuildWithSensitive(snapshot, analysis.Sensitive, analysis.Status != AnalysisOK)
		if !ok {
			t.Fatalf("BuildWithSensitive failed")
		}
		src := result.Sources[0].Model
		t.Logf("status=%s evidence=%q sourceRedacted=%t sourceValue=%q", status, normalizeParts(result.Parts), src.Redacted, src.Value)
		if status == "Q" && !src.Redacted {
			t.Errorf("status=Q: tainted literal leaked raw: source value %q, evidence %q", src.Value, normalizeParts(result.Parts))
		}
		if status == "P" && src.Redacted == false {
			t.Errorf("control unexpectedly unredacted")
		}
	}
}
