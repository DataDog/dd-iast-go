package redaction

import (
	"strings"
	"testing"
)

func TestReviewMalformedLiteralContainingOracleQuoteDoesNotExposeSuffix(t *testing.T) {
	// Given: a malformed SQL literal containing text that looks like an Oracle q-quote.
	query := "SELECT 'prefix q'[secret]' suffix'"
	configureRedaction(t, true, "never-match", "never-match")
	snapshot := compositeSnapshot(t, "SELECT 'prefix q'[secret]' ", "suffix", "'")

	// When: the SQL redaction analyzer tokenizes it.
	analysis := AnalyzeSQL(query)
	masked := maskSensitive(analysis)
	result, ok := BuildWithSensitive(snapshot, analysis.Sensitive, false)

	// Then: the tainted literal body must be marked and redacted in wire evidence.
	if analysis.Status != AnalysisOK || strings.Contains(masked, "suffix") || !ok || !result.Sources[0].Model.Redacted {
		t.Fatalf(
			"status=%v masked=%q intervals=%#v build-ok=%t source-redacted=%t source-value=%q",
			analysis.Status,
			masked,
			analysis.Sensitive,
			ok,
			result.Sources[0].Model.Redacted,
			result.Sources[0].Model.Value,
		)
	}
}
