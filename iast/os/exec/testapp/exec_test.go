// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	stdexec "os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

func init() {
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	config.VulnerabilitiesPerRequest = 64
	config.DeduplicationEnabled = false
	config.RedactionEnabled = true
	config.RedactionNamePattern = regexp.MustCompile(`never-match`)
	config.RedactionValuePattern = regexp.MustCompile(`never-match`)
	config.TruncationMaxValue = 250
	config.StackTraceEnabled = true
}

func TestCommandInstrumentedCount(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	if got := telemetry.InstrumentedSink[constants.VulnerabilityTypeCommandInjection]; got != 1 {
		t.Fatalf("instrumented command sinks = %d, want 1", got)
	}
}

func TestCommandExecutionBoundaries(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	tests := []struct {
		name string
		run  func(*stdexec.Cmd) error
	}{
		{name: "start", run: func(command *stdexec.Cmd) error {
			if err := command.Start(); err != nil {
				return err
			}
			return command.Wait()
		}},
		{name: "run", run: func(command *stdexec.Cmd) error { return command.Run() }},
		{name: "output", run: func(command *stdexec.Cmd) error {
			output, err := command.Output()
			if err == nil && !strings.Contains(string(output), "secret") {
				t.Fatalf("output = %q", output)
			}
			return err
		}},
		{name: "combined output", run: func(command *stdexec.Cmd) error {
			output, err := command.CombinedOutput()
			if err == nil && !strings.Contains(string(output), "secret") {
				t.Fatalf("output = %q", output)
			}
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCommandFixture(t)
			before := telemetry.ExecutedSink.CommandInjection.Load()
			if err := test.run(fixture.command()); err != nil {
				t.Fatal(err)
			}
			assertCommandFinding(t, fixture, 1)
			if delta := telemetry.ExecutedSink.CommandInjection.Load() - before; delta != 1 {
				t.Fatalf("executed sink delta = %d", delta)
			}
		})
	}
}

func TestCommandWithoutContextUsesOwnerBinding(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	command := stdexec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", fixture.secret)
	command.Env = append(os.Environ(), "GO_WANT_DD_IAST_HELPER_PROCESS=1")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	assertCommandFinding(t, fixture, 1)
}

func TestCommandAnalyzerFailureFullyRedacts(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	long := taint.TaintString(fixture.ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "long"}, strings.Repeat("x", redaction.MaxAnalyzerBytes+1))
	command := stdexec.CommandContext(fixture.ctx, os.Args[0], "-test.run=TestHelperProcess", "--", long)
	command.Env = append(os.Environ(), "GO_WANT_DD_IAST_HELPER_PROCESS=1")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	assertCommandFinding(t, fixture, 1)
	fixture.annotation.RLock()
	finding := fixture.annotation.Vulnerabilities[0]
	fixture.annotation.RUnlock()
	for _, part := range finding.Evidence.ValueParts {
		if !part.Redacted || part.Value != "" {
			t.Fatalf("analyzer fallback exposed evidence: %#v", finding.Evidence.ValueParts)
		}
	}
}

func TestCommandBeyondCollectionBoundsDrops(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	command := stdexec.CommandContext(fixture.ctx, "/definitely/not/a/real/dd-iast-command", strings.Repeat("x", store.MaxRootBytes+1), fixture.secret)
	if err := command.Run(); err == nil {
		t.Fatal("missing executable unexpectedly ran")
	}
	assertCommandFinding(t, fixture, 0)

	arguments := make([]string, redaction.MaxCommandArguments+1)
	for index := range arguments {
		arguments[index] = "x"
	}
	arguments[len(arguments)-1] = fixture.secret
	command = stdexec.CommandContext(fixture.ctx, "/definitely/not/a/real/dd-iast-command", arguments...)
	if err := command.Run(); err == nil {
		t.Fatal("missing executable unexpectedly ran")
	}
	assertCommandFinding(t, fixture, 0)
}

func TestCommandPayloadEncodings(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	if err := fixture.command().Run(); err != nil {
		t.Fatal(err)
	}
	assertEventEncodings(t, fixture.annotation)
}

func TestCommandConstructionDoesNotReport(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	_ = fixture.command()
	assertCommandFinding(t, fixture, 0)
}

func TestCommandValidationFailureDoesNotReport(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	command := fixture.command()
	command.Path = ""
	before := telemetry.ExecutedSink.CommandInjection.Load()
	if err := command.Start(); err == nil {
		t.Fatal("invalid command unexpectedly started")
	}
	assertCommandFinding(t, fixture, 0)
	if telemetry.ExecutedSink.CommandInjection.Load() != before {
		t.Fatal("validation failure reached process-attempt callback")
	}
}

func TestCommandStartProcessErrorStillReports(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newCommandFixture(t)
	command := stdexec.CommandContext(fixture.ctx, "/definitely/not/a/real/dd-iast-command", fixture.secret)
	if err := command.Run(); err == nil {
		t.Fatal("missing executable unexpectedly ran")
	}
	assertCommandFinding(t, fixture, 1)
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_DD_IAST_HELPER_PROCESS") != "1" {
		return
	}
	separator := 0
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index + 1
			break
		}
	}
	_, _ = os.Stdout.WriteString(strings.Join(os.Args[separator:], " "))
	os.Exit(0)
}

func assertEventEncodings(t *testing.T, annotation *spans.Annotation) {
	t.Helper()
	annotation.RLock()
	jsonData, jsonErr := json.Marshal(&annotation.Event)
	msgpackData, msgpackErr := annotation.Event.MarshalMsg(nil)
	annotation.RUnlock()
	if jsonErr != nil || msgpackErr != nil {
		t.Fatalf("encode errors = JSON:%v msgpack:%v", jsonErr, msgpackErr)
	}
	if bytes.Contains(jsonData, []byte("secret")) || bytes.Contains(msgpackData, []byte("secret")) {
		t.Fatal("wire payload exposed raw tainted evidence")
	}
	var jsonEvent, msgpackEvent model.Event
	if err := json.Unmarshal(jsonData, &jsonEvent); err != nil {
		t.Fatal(err)
	}
	remainder, err := msgpackEvent.UnmarshalMsg(msgpackData)
	if err != nil || len(remainder) != 0 {
		t.Fatalf("msgpack decode = remainder:%d error:%v", len(remainder), err)
	}
	if !reflect.DeepEqual(jsonEvent, msgpackEvent) {
		t.Fatalf("encoding mismatch = JSON:%#v msgpack:%#v", jsonEvent, msgpackEvent)
	}
}

func BenchmarkCommandStartErrorInactive(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		command := stdexec.Command("/definitely/not/a/real/dd-iast-command", "clean")
		if err := command.Run(); err == nil {
			b.Fatal("missing executable unexpectedly ran")
		}
	}
}

type commandFixture struct {
	ctx        context.Context
	scope      *request.Scope
	span       *tracer.Span
	annotation *spans.Annotation
	secret     string
}

func newCommandFixture(t *testing.T) *commandFixture {
	t.Helper()
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("active scope was not created")
	}
	span, spanCtx := tracer.StartSpanFromContext(ctx, "request")
	annotation := spans.BindScope(span, scope)
	secret := taint.TaintString(spanCtx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "argument"}, "secret")
	fixture := &commandFixture{ctx: spanCtx, scope: scope, span: span, annotation: annotation, secret: secret}
	t.Cleanup(func() {
		spans.Finished(span)
		scope.Finish()
		span.Finish()
	})
	return fixture
}

func (f *commandFixture) command() *stdexec.Cmd {
	command := stdexec.CommandContext(f.ctx, os.Args[0], "-test.run=TestHelperProcess", "--", f.secret)
	command.Env = append(os.Environ(), "GO_WANT_DD_IAST_HELPER_PROCESS=1")
	return command
}

func assertCommandFinding(t *testing.T, fixture *commandFixture, want int) {
	t.Helper()
	fixture.annotation.RLock()
	findings := append([]model.Vulnerability(nil), fixture.annotation.Vulnerabilities...)
	sources := append([]model.Source(nil), fixture.annotation.Sources...)
	fixture.annotation.RUnlock()
	if len(findings) != want {
		t.Fatalf("finding count = %d, want %d", len(findings), want)
	}
	for _, finding := range findings {
		if finding.Type != constants.VulnerabilityTypeCommandInjection || finding.Location == nil || !strings.HasSuffix(finding.Location.Path, "exec_test.go") {
			t.Fatalf("finding = %#v, location = %#v", finding, finding.Location)
		}
		redacted := false
		for _, part := range finding.Evidence.ValueParts {
			if strings.Contains(part.Value, "secret") {
				t.Fatalf("command evidence exposed the tainted argument: %#v", finding.Evidence.ValueParts)
			}
			redacted = redacted || part.Redacted
		}
		if !redacted {
			t.Fatalf("command evidence has no redacted argument: %#v", finding.Evidence.ValueParts)
		}
	}
	if want > 0 && (len(sources) != 1 || !sources[0].Redacted || sources[0].Value != "") {
		t.Fatalf("sources = %#v", sources)
	}
}
