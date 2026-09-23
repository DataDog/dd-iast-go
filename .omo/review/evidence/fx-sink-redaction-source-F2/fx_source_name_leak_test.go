// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

func TestIndependent_HTTPQuerySensitiveKeyLeakedInMsgpack(t *testing.T) {
	const name = "token:abcdefghijklm"
	if !config.Enabled || !config.RedactionEnabled || config.RequestSamplingPct != 30 ||
		!config.RedactionNamePattern.MatchString(name) {
		t.Fatal("requires the unmodified default IAST and redaction configuration")
	}
	t.Logf("defaults: redaction=%t sampling=%d sensitive_name=%t",
		config.RedactionEnabled, config.RequestSamplingPct, config.RedactionNamePattern.MatchString(name))

	// Make only admission deterministic; keep the default redaction configuration.
	previousSampling := config.RequestSamplingPct
	config.RequestSamplingPct = 100
	t.Cleanup(func() { config.RequestSamplingPct = previousSampling })

	ctx, scope, created := request.Begin(context.Background())
	if !created || scope == nil || scope.Decision() != request.DecisionActive {
		t.Fatalf("request admission: created=%t scope=%v", created, scope)
	}
	defer scope.Finish()

	httpRequest := httptest.NewRequest("GET", "/?token%3Aabcdefghijklm=SELECT+1", nil)
	httpRequest.Header = request.EagerHTTP(ctx, &httpRequest.RequestURI, &httpRequest.URL.Path,
		&httpRequest.URL.RawQuery, httpRequest.Header, httpRequest.URL, httpRequest.Body)
	parameters := request.ManageURLQuery(httpRequest.URL, httpRequest.URL.Query())
	values := parameters[name]
	if len(values) != 1 {
		t.Fatalf("managed query values for %q: %#v", name, parameters)
	}
	snapshot, status := evidence.CollectString(values[0], constants.VulnerabilityTypeSqlInjection)
	if status != evidence.StatusCollected {
		t.Fatalf("HTTP query value was not tainted: status=%v", status)
	}
	analysis := redaction.AnalyzeSQL(values[0])
	if analysis.Status != redaction.AnalysisOK {
		t.Fatalf("SQL analyzer status=%v", analysis.Status)
	}
	converted, ok := redaction.BuildWithSensitive(snapshot, analysis.Sensitive, false)
	if !ok || len(converted.Sources) != 1 || !converted.Sources[0].Model.Redacted {
		t.Fatalf("sensitive HTTP source did not reach redaction: %#v, ok=%t", converted, ok)
	}

	event := &model.Event{
		Sources: []model.Source{converted.Sources[0].Model},
		Vulnerabilities: []model.Vulnerability{{
			Type:     constants.VulnerabilityTypeSqlInjection,
			Evidence: model.NewEvidenceTaintedValue(converted.Parts),
		}},
	}
	payload, err := spans.BuildLimitedPayload(event, spans.PayloadEncodingMsgpack)
	if err != nil || payload.Truncated {
		t.Fatalf("MessagePack payload: err=%v truncated=%t", err, payload.Truncated)
	}
	var decoded model.Event
	remaining, err := decoded.UnmarshalMsg(payload.Encoded)
	if err != nil || len(remaining) != 0 || len(decoded.Sources) != 1 {
		t.Fatalf("MessagePack decode: err=%v remaining=%d sources=%d", err, len(remaining), len(decoded.Sources))
	}
	wireJSON, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sources[0].Name == name {
		t.Fatalf("LEAK: MessagePack payload contains unchanged sensitive HTTP query name: %s", wireJSON)
	}
}
