package redaction_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/tinylib/msgp/msgp"
)

// This exercises real request taint, string propagation, SQL analysis, redaction,
// and the event JSON encoder; only sampling is made deterministic.
func TestIndependentSQLBoundaryEvidence(t *testing.T) {
	if !config.Enabled || !config.RedactionEnabled || config.TruncationMaxValue != 250 {
		t.Fatalf("expected default enabled/redacted/250 config, got %t/%t/%d",
			config.Enabled, config.RedactionEnabled, config.TruncationMaxValue)
	}
	previousSampling := config.RequestSamplingPct
	config.RequestSamplingPct = 100
	t.Cleanup(func() { config.RequestSamplingPct = previousSampling })

	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("request taint analysis did not start")
	}
	t.Cleanup(scope.Finish)
	input := taint.TaintString(ctx, taint.Source{
		Origin: constants.OriginHttpRequestParameter, Name: "id",
	}, "xX")

	for _, prefixLength := range []int{249, 250} {
		prefix := "SELECT " + strings.Repeat(" ", prefixLength-len("SELECT "))
		query := propagation.JoinString([]string{prefix, input}, "", prefix+input)
		snapshot, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
		if status != evidence.StatusCollected {
			t.Fatalf("prefix=%d CollectString status=%v", prefixLength, status)
		}
		analysis := redaction.AnalyzeSQL(snapshot.Value())
		if analysis.Status != redaction.AnalysisOK {
			t.Fatalf("prefix=%d AnalyzeSQL status=%v", prefixLength, analysis.Status)
		}
		converted, ok := redaction.BuildWithSensitive(snapshot, analysis.Sensitive, false)
		if !ok || len(converted.Parts) != 2 || len(converted.Sources) != 1 {
			t.Fatalf("prefix=%d converted=%#v ok=%t", prefixLength, converted, ok)
		}

		event := model.Event{
			Sources: []model.Source{converted.Sources[0].Model},
			Vulnerabilities: []model.Vulnerability{
				model.NewVulnerability(
					constants.VulnerabilityTypeSqlInjection,
					model.NewEvidenceTaintedValue(converted.Parts),
					&model.Location{SpanID: 1},
				),
			},
		}
		wire, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		for _, encoding := range []string{"json", "msgpack"} {
			if encoding == "msgpack" {
				encoded, err := event.MarshalMsg(nil)
				if err != nil {
					t.Fatal(err)
				}
				var translated bytes.Buffer
				remainder, err := msgp.UnmarshalAsJSON(&translated, encoded)
				if err != nil || len(remainder) != 0 {
					t.Fatalf("msgpack conversion error=%v remainder=%d", err, len(remainder))
				}
				wire = translated.Bytes()
			}
			var decoded struct {
				Vulnerabilities []struct {
					Evidence struct {
						ValueParts []map[string]json.RawMessage `json:"valueParts"`
					} `json:"evidence"`
				} `json:"vulnerabilities"`
			}
			if err := json.Unmarshal(wire, &decoded); err != nil {
				t.Fatal(err)
			}
			part := decoded.Vulnerabilities[0].Evidence.ValueParts[1]
			partJSON, err := json.Marshal(part)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("encoding=%s prefix=%d tainted_part=%s", encoding, prefixLength, partJSON)
			if string(part["source"]) != "0" {
				t.Fatalf("encoding=%s prefix=%d source index missing: %s", encoding, prefixLength, partJSON)
			}
			if _, present := part["value"]; !present {
				t.Errorf("encoding=%s prefix=%d unredacted tainted part lacks schema-required value: %s",
					encoding, prefixLength, partJSON)
			}
		}
	}
}
