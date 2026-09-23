package redaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

// fx-sink-e2e-truepos-F1 (phase 3) verification: SQL comment redaction bypass.
const fxAppSecret = "fx-secret-literal-9c2e" // application's own literal, NOT user input
const fxCommentSecret = "fxTOKENSECRETzebra42"

func TestFxDashDashInjectionLeavesAppLiteralsClean(t *testing.T) {
	injected := "SELECT id FROM users WHERE name = 'admin' -- AND pw_hash = '" + fxAppSecret + "' AND tenant = 42"
	analysis := AnalyzeSQL(injected)
	if analysis.Status != AnalysisOK {
		t.Fatalf("status = %v", analysis.Status)
	}
	masked := maskSensitive(analysis)
	if strings.Contains(masked, fxAppSecret) || strings.Contains(masked, "tenant = 42") {
		t.Logf("LEAK: injected -- left app literals sensitive-visible: masked=%q intervals=%v", masked, analysis.Sensitive)
	} else {
		t.Fatalf("claim refuted: injected -- redacted app literals: %q", masked)
	}
	// security claim: the same query with a benign input DOES redact these literals.
	benign := "SELECT id FROM users WHERE name = 'alice' AND pw_hash = '" + fxAppSecret + "' AND tenant = 42"
	bAnalysis := AnalyzeSQL(benign)
	if bAnalysis.Status != AnalysisOK {
		t.Fatalf("benign status = %v", bAnalysis.Status)
	}
	bMasked := maskSensitive(bAnalysis)
	if strings.Contains(bMasked, fxAppSecret) || strings.Contains(bMasked, "tenant = 42") {
		t.Fatalf("CONTROL FAILED: benign input did not redact app literals: %q", bMasked)
	}
	t.Logf("CONTROL: benign masked: %q", bMasked)
}

func TestFxCleanBlockCommentNeverRedacted(t *testing.T) {
	query := "SELECT id FROM users /* api_key=fx_sk_live_CLEANCOMMENT */ ORDER BY name"
	analysis := AnalyzeSQL(query)
	if analysis.Status != AnalysisOK {
		t.Fatalf("status = %v", analysis.Status)
	}
	masked := maskSensitive(analysis)
	if strings.Contains(masked, "fx_sk_live_CLEANCOMMENT") {
		t.Logf("LEAK: clean comment body never redacted: %q", masked)
	} else {
		t.Fatalf("claim refuted: clean comment redacted: %q", masked)
	}
}

// security claim: a tainted value inside a SQL line comment is serialized raw
// in the vulnerability event despite default redaction and non-matching
// built-in patterns (sink-redaction-source-F3).
func TestFxTaintedCommentSecretLeaksEvent(t *testing.T) {
	if !config.RedactionEnabled {
		t.Fatal("expected default redaction to be enabled")
	}
	if config.RedactionNamePattern.MatchString("parameter") || config.RedactionValuePattern.MatchString(fxCommentSecret) {
		t.Fatal("reproducer requires the documented built-in redaction patterns not to match")
	}
	snapshot := compositeSnapshot(t, "SELECT id /* review_token=", fxCommentSecret, " */ FROM users")
	analysis := AnalyzeSQL(snapshot.Value())
	result, ok := BuildWithSensitive(snapshot, analysis.Sensitive, analysis.Status != AnalysisOK)
	if !ok {
		t.Fatal("BuildWithSensitive failed")
	}
	payload, err := json.Marshal(model.Event{
		Sources: []model.Source{result.Sources[0].Model},
		Vulnerabilities: []model.Vulnerability{{
			Type:     constants.VulnerabilityTypeSqlInjection,
			Evidence: model.NewEvidenceTaintedValue(result.Parts),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(payload)
	leakMark := `"value":"` + fxCommentSecret + `","source":0`
	if strings.Contains(body, leakMark) {
		t.Logf("LEAK event JSON (tainted comment secret serialized raw as evidence): %s", body)
	} else {
		t.Fatalf("claim refuted: comment secret not in raw evidence: %s", body)
	}
}
