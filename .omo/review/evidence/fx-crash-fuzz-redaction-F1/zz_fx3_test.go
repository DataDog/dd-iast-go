package redaction

import (
	"strings"
	"testing"
)

// Independent phase-3 reproducer (fx-crash-fuzz-redaction-F1).
// Each case holds a secret literal body; the SQL analyzer must cover every byte.
func TestFx3OracleQuoteDesync(t *testing.T) {
	cases := []struct{ name, query, secret string }{
		// realistic IN-list with three short codes, first ends in Q
		{"in-list", "SELECT id FROM jobs WHERE state IN ('Q','R','S') AND owner = 's3cr3tTok'", "s3cr3tTok"},
		// compact INSERT built by concatenation
		{"insert", "INSERT INTO users(kind,role,password) VALUES ('Q','u','s3cr3tTok')", "s3cr3tTok"},
		// lower-case q ending a longer literal
		{"lower", "UPDATE t SET a='faq',b='x',c='s3cr3tTok' WHERE id=1", "s3cr3tTok"},
		// sink-redaction-sql-cmd shape: q' inside a literal
		{"inner-q", "SELECT '?q'[?]' s3cr3tTok'", "s3cr3tTok"},
		// controls
		{"control-P", "SELECT id FROM jobs WHERE state IN ('P','R','S') AND owner = 's3cr3tTok'", "s3cr3tTok"},
		{"control-real-qquote", "SELECT q'[x]' , 's3cr3tTok' FROM dual", "s3cr3tTok"},
	}
	for _, c := range cases {
		a := AnalyzeSQL(c.query)
		covered := make([]bool, len(c.query))
		for _, iv := range a.Sensitive {
			for i := iv.Start; i < iv.Start+iv.Length; i++ {
				covered[i] = true
			}
		}
		at := strings.Index(c.query, c.secret)
		exposed := 0
		for i := at; i < at+len(c.secret); i++ {
			if !covered[i] {
				exposed++
			}
		}
		_, spans, _ := scanOracleQuotes(c.query)
		var bogus []string
		for _, s := range spans {
			bogus = append(bogus, c.query[s.start:s.end])
		}
		verdict := "COVERED"
		if a.Status == AnalysisOK && exposed > 0 {
			verdict = "LEAK"
		}
		t.Logf("%s %-20s status=%d qspans=%q exposed=%d/%d sensitive=%v", verdict, c.name, a.Status, bogus, exposed, len(c.secret), a.Sensitive)
	}
}

// End to end through BuildWithSensitive with a tainted value in the later literal.
func TestFx3OracleQuoteDesyncBuild(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	for _, prefix := range []string{
		"INSERT INTO users(kind,role,password) VALUES ('Q','u','",
		"INSERT INTO users(kind,role,password) VALUES ('P','u','",
	} {
		snapshot := compositeSnapshot(t, prefix, "s3cr3tTok", "')")
		a := AnalyzeSQL(snapshot.Value())
		res, ok := BuildWithSensitive(snapshot, a.Sensitive, a.Status != AnalysisOK)
		if !ok {
			t.Fatal("build failed")
		}
		src := res.Sources[0].Model
		t.Logf("prefix=%q evidence=%q sourceRedacted=%t sourceValue=%q", prefix, normalizeParts(res.Parts), src.Redacted, src.Value)
	}
}
