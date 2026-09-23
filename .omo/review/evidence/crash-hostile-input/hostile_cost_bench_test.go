package redaction

import (
	"strings"
	"testing"
)

// Supporting measurement (review node crash-hostile-input): per-call cost of
// the SQL analyzer on a query just below MaxAnalyzerBytes. The sink runs this
// for every tainted query even after the per-request vulnerability quota is
// exhausted.
func BenchmarkHostileAnalyzeSQL30KB(b *testing.B) {
	query := "SELECT * FROM t WHERE a = '" + strings.Repeat("v\xff,", 10000) + "' AND n = x"
	b.SetBytes(int64(len(query)))
	for b.Loop() {
		_ = AnalyzeSQL(query)
	}
}
