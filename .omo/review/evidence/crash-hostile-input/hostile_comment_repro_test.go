package redaction

import "testing"

// Reproducer (review node crash-hostile-input): SQL comment bodies are not
// treated as sensitive, so literals that follow an injected "--" (or live in a
// block comment) are emitted in clear. The shared cross-tracer corpus
// (dd-trace-js evidence-redaction-suite.json "SQLi exploited", "Query with
// line comment", "Query with block comment") expects them redacted.
func TestHostileSQLCommentBodiesAreRedacted(t *testing.T) {
	cases := []struct {
		query, secret string
	}{
		{"SELECT * FROM Users WHERE email = '' OR TRUE --' AND password = '81dc9bdb52d04dc20036dbd8313ed055' AND deletedAt IS NULL", "81dc9bdb52d04dc20036dbd8313ed055"},
		{"select * from users -- This is a line comment with secret hunter2", "hunter2"},
		{"select * from users/*\ntoken=tok_live_SECRETBLOCK\n*/", "tok_live_SECRETBLOCK"},
	}
	for _, c := range cases {
		analysis := AnalyzeSQL(c.query)
		t.Logf("status=%d intervals=%v", analysis.Status, analysis.Sensitive)
		visible := visibleOutsideIntervals(c.query, analysis.Sensitive)
		t.Logf("visible evidence: %q", visible)
		if analysis.Status == AnalysisOK && contains(visible, c.secret) {
			t.Errorf("secret %q is NOT covered by any sensitive interval in %q", c.secret, c.query)
		}
	}
}

func visibleOutsideIntervals(value string, intervals []Interval) string {
	out := []byte(value)
	for _, interval := range intervals {
		for i := interval.Start; i < interval.Start+interval.Length; i++ {
			out[i] = '*'
		}
	}
	return string(out)
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
