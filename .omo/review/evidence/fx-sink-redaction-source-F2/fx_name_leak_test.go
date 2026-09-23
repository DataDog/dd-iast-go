// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

// Independent phase-3 verification of finding sink-redaction-source-F2.
// Unlike the phase-2 reproducer, this drives the public taint API
// (taint.TaintString with a named HTTP parameter source), the production
// evidence collection (evidence.CollectString), and serializes the event
// through BOTH production encoders: MessagePack (MarshalMsg, the meta-struct
// path in spans.Finished) and JSON (the _dd.iast.json fallback path).

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

const fxCredentialShapedName = "token:abcdefghijklm"

func TestFxSensitiveSourceNameSerializedUnredacted(t *testing.T) {
	if !config.RedactionEnabled || config.RedactionNamePattern == nil || !config.RedactionNamePattern.MatchString(fxCredentialShapedName) {
		t.Fatalf("reproducer requires default redaction; enabled=%v pattern=%v", config.RedactionEnabled, config.RedactionNamePattern)
	}

	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})
	ctx, scope, created := request.Begin(t.Context())
	if !created {
		t.Fatal("request scope was not created")
	}
	defer scope.Finish()

	managed := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: fxCredentialShapedName}, "SELECT 1")
	if !taint.IsTaintedString(managed) {
		t.Fatal("value was not tainted")
	}
	snapshot, status := evidence.CollectString(managed, constants.VulnerabilityTypeSqlInjection)
	if status != evidence.StatusCollected {
		t.Fatalf("CollectString status = %v", status)
	}
	result, ok := BuildSources(snapshot)
	if !ok {
		t.Fatal("BuildSources failed")
	}
	if len(result.Sources) == 0 {
		t.Fatal("no sources")
	}
	wire := result.Sources[0].Model
	if !wire.Redacted || wire.Value != "" {
		t.Fatalf("source was not redacted: %+v", wire)
	}
	if wire.Name != fxCredentialShapedName {
		t.Fatalf("unexpected wire name %q", wire.Name)
	}

	event := model.Event{
		Sources: []model.Source{wire},
		Vulnerabilities: []model.Vulnerability{{
			Type:     constants.VulnerabilityTypeSqlInjection,
			Evidence: model.NewEvidenceTaintedValue(result.Parts),
		}},
	}
	msgpack, err := event.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(msgpack, []byte(fxCredentialShapedName)) {
		t.Fatalf("LEAK (MessagePack meta-struct path): credential-shaped source name serialized unredacted: %q", msgpack)
	}
	asJSON, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(asJSON, []byte(fxCredentialShapedName)) {
		t.Fatalf("LEAK (JSON fallback path): credential-shaped source name serialized unredacted: %s", asJSON)
	}
}
