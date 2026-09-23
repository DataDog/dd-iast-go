// Independent phase-3 verification reproducer for sink-redaction-source-F1.
// Verifies that the deterministic redaction pattern can equal the secret
// itself for both the wire model.Source.Pattern and the evidence ValuePart
// Pattern when redaction is active with the built-in default patterns.
package redaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestFXPatternMustNotReproduceSecret(t *testing.T) {
	const secret = "abc"
	if !config.RedactionEnabled || config.RedactionNamePattern == nil ||
		!config.RedactionNamePattern.MatchString("password") ||
		config.RedactionNamePattern.MatchString("parameter") {
		t.Fatal("reproducer requires the built-in default redaction configuration")
	}
	result, ok := BuildSources(sourceSnapshot(t, "password", secret))
	if !ok {
		t.Fatal("BuildSources failed")
	}
	wire := result.Sources[0].Model
	if wire.Pattern == secret {
		t.Errorf("LEAK model.Source.Pattern == secret: %#v", wire)
	}
	for _, part := range result.Parts {
		if part.Pattern == secret {
			t.Errorf("LEAK evidence ValuePart.Pattern == secret: %#v", part)
		}
	}
	payload, err := json.Marshal(model.Event{
		Sources: []model.Source{wire},
		Vulnerabilities: []model.Vulnerability{{
			Type:     constants.VulnerabilityTypeSqlInjection,
			Evidence: model.NewEvidenceTaintedValue(result.Parts),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), `"`+secret+`"`) {
		t.Fatalf("LEAK serialized event contains the raw secret: %s", payload)
	}
	t.Logf("serialized event: %s", payload)
}
