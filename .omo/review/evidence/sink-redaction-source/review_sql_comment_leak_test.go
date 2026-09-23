package redaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestReviewSQLCommentSecretMustBeRedacted(t *testing.T) {
	const secret = "hunter2"
	if !config.RedactionEnabled {
		t.Fatal("expected default redaction to be enabled")
	}
	if config.RedactionNamePattern.MatchString("parameter") || config.RedactionValuePattern.MatchString(secret) {
		t.Fatal("reproducer requires the documented built-in redaction patterns")
	}

	snapshot := compositeSnapshot(t, "SELECT 1 -- ", secret, "\n")
	analysis := AnalyzeSQL(snapshot.Value())
	result, ok := BuildWithSensitive(snapshot, analysis.Sensitive, analysis.Status != AnalysisOK)
	if !ok {
		t.Fatal("BuildWithSensitive failed")
	}

	event := model.Event{
		Sources: []model.Source{result.Sources[0].Model},
		Vulnerabilities: []model.Vulnerability{{
			Type: constants.VulnerabilityTypeSqlInjection,
			Evidence: model.NewEvidenceTaintedValue(result.Parts),
		}},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), secret) {
		t.Fatalf("LEAK: default redaction serialized SQL comment secret: %s", payload)
	}
}
