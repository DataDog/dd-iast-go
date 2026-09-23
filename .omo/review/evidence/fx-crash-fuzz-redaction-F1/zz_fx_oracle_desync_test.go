package redaction

import (
	"strings"
	"testing"
)

// fx-crash-fuzz-redaction-F1 independent reproducer: literal bodies of every
// ordinary '...' literal must be covered by AnalyzeSQL's sensitive intervals.
func TestFXOracleQuoteDesync(t *testing.T) {
	cases := []struct{ query, secret string }{
		{"SELECT * FROM orders WHERE state IN ('Q','X') AND email = 'alice@example.com'", "alice@example.com"},
		{"SELECT id FROM t WHERE code = 'q' AND name = 'bob' OR x = 1 AND y = ('<', 'topsecret')", "topsecret"},
		{"UPDATE u SET flag = 'Q', note = 'n' WHERE ssn = '123-45-6789'", "123-45-6789"},
		{"SELECT '?q'[?]' suffix'", "suffix"},
		{"SELECT * FROM orders WHERE state IN ('P','X') AND email = 'alice@example.com'", "alice@example.com"}, // control
	}
	for _, c := range cases {
		a := AnalyzeSQL(c.query)
		start := strings.Index(c.query, c.secret)
		covered := make([]bool, len(c.query))
		for _, iv := range a.Sensitive {
			for i := iv.Start; i < iv.Start+iv.Length; i++ {
				covered[i] = true
			}
		}
		exposed := 0
		for i := start; i < start+len(c.secret); i++ {
			if !covered[i] {
				exposed++
			}
		}
		spans := 0
		if _, s, _ := scanOracleQuotes(c.query); s != nil {
			spans = len(s)
		}
		t.Logf("status=%d oracleSpans=%d exposedBytes=%d/%d query=%q sensitive=%v", a.Status, spans, exposed, len(c.secret), c.query, a.Sensitive)
		if a.Status == AnalysisOK && exposed > 0 {
			t.Errorf("LEAK: %q not redacted in %q", c.secret, c.query)
		}
	}
}
