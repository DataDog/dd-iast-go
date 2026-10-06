// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"encoding/json"
	"os"
	stdexec "os/exec"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

// A JSON body that encoding/json decodes keeps its taint up to the command
// sink. With the v1 implementation of encoding/json, the hooks of
// iast/propagation/stream apply; with the v2 implementation (the default from
// Go 1.27), the hooks of iast/propagation/jsonv2 apply. The test uses
// json.Unmarshal: a json.Decoder on a bytes.Reader does not keep the taint,
// because no hook propagates the taint through bytes.Reader.Read.
func TestCommandDecodedJSON(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	body := taint.TaintBytes(fixture.ctx,
		taint.Source{Origin: constants.OriginHttpRequestBody, Name: "body"},
		[]byte(`{"argument":"secret"}`))
	var document struct {
		Argument string `json:"argument"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	if !taint.IsTaintedString(document.Argument) {
		t.Fatalf("decoded value %q is not tainted", document.Argument)
	}
	before := telemetry.ExecutedSink.CommandInjection.Load()
	command := stdexec.CommandContext(fixture.ctx, os.Args[0], "-test.run=TestHelperProcess", "--", document.Argument)
	command.Env = append(os.Environ(), "GO_WANT_DD_IAST_HELPER_PROCESS=1")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	if delta := telemetry.ExecutedSink.CommandInjection.Load() - before; delta != 1 {
		t.Fatalf("executed sink delta = %d, want 1", delta)
	}
	fixture.annotation.RLock()
	findings := append([]model.Vulnerability(nil), fixture.annotation.Vulnerabilities...)
	fixture.annotation.RUnlock()
	if len(findings) != 1 || findings[0].Type != constants.VulnerabilityTypeCommandInjection {
		t.Fatalf("findings = %#v, want 1 command injection", findings)
	}
}
