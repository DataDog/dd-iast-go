package redaction

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

// fx-sink-e2e-truepos-F1 independent reproducer: SQL comment bodies vs redaction.
func TestFXCommentRedaction(t *testing.T) {
	cases := []struct{ name, prefix, tainted, suffix string }{
		// shared corpus (dd-trace-js evidence-redaction-suite.json) "Query with line comment": expects " --" then {redacted:true}
		{"corpus-line-comment", "select * from ", "users", " -- This is a line comment"},
		// shared corpus "Query with block comment": expects "/*" {redacted:true} "*/"
		{"corpus-block-comment", "select * from ", "users", "/*\nThis is a block comment\n*/"},
		{"login-benign", "SELECT id FROM users WHERE name = '", "alice", "' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42"},
		{"login-injected-dashdash", "SELECT id FROM users WHERE name = '", "admin' --", "' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42"},
		{"login-injected-hash-mysql", "SELECT id FROM users WHERE name = '", "admin' #", "' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42"},
		{"tainted-secret-in-comment", "SELECT 1 -- ", "hunter2", "\n"},
		{"clean-app-comment", "SELECT id FROM users /* api_key=sk_live_CLEANCOMMENT */ ORDER BY ", "name", ""},
	}
	for _, c := range cases {
		snapshot := compositeSnapshot(t, c.prefix, c.tainted, c.suffix)
		analysis := AnalyzeSQL(snapshot.Value())
		result, ok := BuildWithSensitive(snapshot, analysis.Sensitive, analysis.Status != AnalysisOK)
		if !ok {
			t.Fatalf("%s: BuildWithSensitive failed", c.name)
		}
		event := model.Event{
			Sources: []model.Source{result.Sources[0].Model},
			Vulnerabilities: []model.Vulnerability{{Type: constants.VulnerabilityTypeSqlInjection, Evidence: model.NewEvidenceTaintedValue(result.Parts)}},
		}
		payload, _ := json.Marshal(event)
		t.Logf("%s\n  query=%q\n  status=%v intervals=%v masked=%q\n  payload=%s", c.name, snapshot.Value(), analysis.Status, analysis.Sensitive, maskSensitive(analysis), payload)
	}
}
