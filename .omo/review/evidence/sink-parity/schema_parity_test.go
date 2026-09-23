package redaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestTaintedPartAtTruncationBoundaryHasRequiredValue(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = 250
	t.Cleanup(func() { config.TruncationMaxValue = previous })

	snapshot := compositeSnapshot(t, "SELECT "+strings.Repeat(" ", 243), "xx", "")
	analysis := AnalyzeSQL(snapshot.Value())
	if analysis.Status != AnalysisOK {
		t.Fatalf("AnalyzeSQL status = %v", analysis.Status)
	}
	result, ok := BuildWithSensitive(snapshot, analysis.Sensitive, false)
	if !ok {
		t.Fatal("BuildWithSensitive failed")
	}
	sources := make([]model.Source, len(result.Sources))
	for index, source := range result.Sources {
		sources[index] = source.Model
	}
	event := model.Event{
		Sources: sources,
		Vulnerabilities: []model.Vulnerability{
			model.NewVulnerability(
				constants.VulnerabilityTypeSqlInjection,
				model.NewEvidenceTaintedValue(result.Parts),
				&model.Location{SpanID: 1},
			),
		},
	}
	wire, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("WIRE_PAYLOAD=%s", wire)
	var payload struct {
		Vulnerabilities []struct {
			Evidence struct {
				ValueParts []map[string]json.RawMessage `json:"valueParts"`
			} `json:"evidence"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(wire, &payload); err != nil {
		t.Fatal(err)
	}
	part := payload.Vulnerabilities[0].Evidence.ValueParts[1]
	if _, hasSource := part["source"]; !hasSource {
		t.Fatalf("expected a tainted part, got %s", part)
	}
	if _, hasValue := part["value"]; !hasValue {
		t.Fatalf("unredacted tainted part omits required value: %s", part)
	}
}
