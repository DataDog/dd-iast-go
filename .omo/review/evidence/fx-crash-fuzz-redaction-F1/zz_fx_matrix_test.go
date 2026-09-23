package redaction

import (
	"strings"
	"testing"
)

func TestFXOracleQuoteMatrix(t *testing.T) {
	const secret = "s3cr3tVal"
	queries := []string{
		"SELECT * FROM t WHERE c IN ('Q','R') AND p = '" + secret + "'",
		"SELECT * FROM t WHERE c IN ('Q','R','S') AND p = '" + secret + "'",
		"SELECT * FROM t WHERE c IN ('Q','R','S','T') AND p = '" + secret + "'",
		"SELECT * FROM t WHERE c IN ('Q', 'R', 'S') AND p = '" + secret + "'",
		"INSERT INTO t (a, b, c) VALUES ('q','a','" + secret + "')",
		"INSERT INTO t (a, b) VALUES ('Q','" + secret + "')",
		"INSERT INTO t (a, b, c, d) VALUES ('Q','a','b','" + secret + "')",
		"INSERT INTO t VALUES ('Q','a','b'),('R','c','" + secret + "')",
		"SELECT * FROM t WHERE grade = 'Q' AND (x = 1) AND p = '" + secret + "'",
		"SELECT * FROM t WHERE c IN ('P','R','S') AND p = '" + secret + "'",
	}
	leaks := 0
	for _, q := range queries {
		a := AnalyzeSQL(q)
		start := strings.Index(q, secret)
		covered := make([]bool, len(q))
		for _, iv := range a.Sensitive {
			for i := iv.Start; i < iv.Start+iv.Length; i++ {
				covered[i] = true
			}
		}
		exposed := 0
		for i := start; i < start+len(secret); i++ {
			if !covered[i] {
				exposed++
			}
		}
		leak := a.Status == AnalysisOK && exposed > 0
		if leak {
			leaks++
		}
		t.Logf("leak=%-5t exposed=%d/%d query=%q", leak, exposed, len(secret), q)
	}
	t.Logf("leaking queries: %d/%d", leaks, len(queries))
}
