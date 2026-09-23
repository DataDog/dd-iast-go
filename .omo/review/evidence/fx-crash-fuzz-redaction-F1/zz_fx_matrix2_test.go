package redaction

import (
	"strings"
	"testing"
)

func TestFXOracleQuoteMatrix2(t *testing.T) {
	const secret = "s3cr3tVal"
	queries := []string{
		"INSERT INTO t (kind, meta, owner) VALUES ('Q','{}','" + secret + "')",
		"INSERT INTO t (kind, tag, path, owner) VALUES ('Q','a','/tmp','" + secret + "')",
		"INSERT INTO t (kind, tag, phone, owner) VALUES ('Q','a','+33612','" + secret + "')",
		"SELECT * FROM t WHERE kind IN ('Q','A','') AND owner = '" + secret + "'",
		"SELECT * FROM t WHERE kind IN ('Q','A') AND name LIKE '%x%' AND owner = '" + secret + "'",
		"INSERT INTO t (kind, tag, pattern, owner) VALUES ('Q','a','%x%','" + secret + "')",
		"INSERT INTO t (kind, tag, owner) VALUES ('Q','a',' " + secret + "')",
		"INSERT INTO t (kind, tag, owner) VALUES ('Q','',' " + secret + "')",
		"INSERT INTO t (kind, tag, owner) VALUES ('Q','',' " + secret + "')",
		"INSERT INTO t (kind, tag, owner) VALUES ('P','a',' " + secret + "')",
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
