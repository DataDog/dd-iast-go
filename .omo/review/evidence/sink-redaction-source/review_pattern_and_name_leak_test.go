package redaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestReviewRedactionPatternMustNotReproduceSecret(t *testing.T) {
	const secret = "abc"
	if !config.RedactionEnabled || !config.RedactionNamePattern.MatchString("password") {
		t.Fatal("reproducer requires the documented built-in redaction configuration")
	}

	result, ok := BuildSources(sourceSnapshot(t, "password", secret))
	if !ok {
		t.Fatal("BuildSources failed")
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
	if strings.Contains(string(payload), secret) {
		t.Fatalf("LEAK: redacted password value was serialized in a pattern: %s", payload)
	}
}

func TestReviewSensitiveSourceNameMustNotLeaveProcess(t *testing.T) {
	const sourceName = "token:abcdefghijklm"
	if !config.RedactionEnabled || !config.RedactionNamePattern.MatchString(sourceName) {
		t.Fatal("reproducer requires the documented built-in redaction configuration")
	}

	result, ok := BuildSources(sourceSnapshot(t, sourceName, "trigger"))
	if !ok {
		t.Fatal("BuildSources failed")
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
	if strings.Contains(string(payload), sourceName) {
		t.Fatalf("LEAK: source name marked sensitive was serialized unchanged: %s", payload)
	}
}
