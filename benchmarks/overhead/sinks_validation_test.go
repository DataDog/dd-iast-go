// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

// The reporting of IAST reads the finished root span. The tag holds the JSON
// event when the tracer has no meta_struct support, as the mock tracer.
const iastJSONTag = "_dd.iast.json"

type iastEvent struct {
	Sources []struct {
		Origin string `json:"origin"`
		Name   string `json:"name"`
		Value  string `json:"value"`
	} `json:"sources"`
	Vulnerabilities []struct {
		Type     string `json:"type"`
		Evidence struct {
			Value      string `json:"value"`
			ValueParts []struct {
				Value    string `json:"value"`
				Source   *int   `json:"source"`
				Redacted bool   `json:"redacted"`
			} `json:"valueParts"`
		} `json:"evidence"`
	} `json:"vulnerabilities"`
}

// requireIAST skips unless this is the IAST variant of the benchmark runner.
func requireIAST(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if os.Getenv("DD_IAST_BENCH_EXPECT") != "iast" {
		t.Skip("set DD_IAST_BENCH_EXPECT=iast (with DD_IAST_ENABLED=true DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false)")
	}
}

// collectEvent waits for the finished server span of the request and decodes
// its IAST event. It returns nil when the span has no event.
func collectEvent(t *testing.T, mt mocktracer.Tracer) *iastEvent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, span := range mt.FinishedSpans() {
			if span.OperationName() != "http.request" {
				continue
			}
			tag, _ := span.Tag(iastJSONTag).(string)
			if tag == "" {
				// The span may have finished before the event was added.
				time.Sleep(20 * time.Millisecond)
				if tag, _ = span.Tag(iastJSONTag).(string); tag == "" {
					return nil
				}
			}
			var event iastEvent
			if err := json.Unmarshal([]byte(tag), &event); err != nil {
				t.Fatalf("invalid IAST JSON: %v\n%s", err, tag)
			}
			return &event
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no finished http.request span")
	return nil
}

func TestSinkWorkloads(t *testing.T) {
	requireIAST(t)
	type sink struct {
		name     string
		vuln     string
		value    string
		prefix   string
		suffix   string
		argument func(kind, v string) string
		run      func(ctx context.Context, argument string)
	}
	db := newNoopDB()
	defer db.Close()
	sinks := []sink{
		{"SinkSQL", "SQL_INJECTION", sinkSQLValue, sinkSQLPrefix, sinkSQLSuffix, sqlArgument,
			func(ctx context.Context, argument string) {
				if err := sqlSink(ctx, db, argument); err != nil {
					t.Errorf("query failed: %v", err)
				}
			}},
		{"SinkCommand", "COMMAND_INJECTION", sinkCmdValue, "-c " + sinkCmdPrefix, "", cmdArgument,
			func(ctx context.Context, argument string) {
				if err := cmdSink(ctx, argument); err == nil {
					t.Error("command unexpectedly started")
				}
			}},
	}
	for _, sink := range sinks {
		for _, kind := range sinkCases {
			t.Run(sink.name+"/"+kind, func(t *testing.T) {
				mt := mocktracer.Start()
				defer mt.Stop()
				runInRequest(t, sinkTarget(sink.value), func(ctx context.Context, req *http.Request) {
					sink.run(ctx, sink.argument(kind, req.FormValue("q")))
				})
				event := collectEvent(t, mt)
				if kind == "clean" {
					if event != nil && len(event.Vulnerabilities) != 0 {
						t.Fatalf("clean call reported %d vulnerabilities", len(event.Vulnerabilities))
					}
					return
				}
				if event == nil || len(event.Vulnerabilities) != 1 {
					t.Fatalf("want exactly 1 vulnerability, got event %+v", event)
				}
				vulnerability := event.Vulnerabilities[0]
				if vulnerability.Type != sink.vuln {
					t.Fatalf("type = %q, want %q", vulnerability.Type, sink.vuln)
				}
				if len(event.Sources) != 1 || event.Sources[0].Origin != "http.request.parameter" || event.Sources[0].Name != "q" {
					t.Fatalf("sources = %+v, want one http.request.parameter named q", event.Sources)
				}
				var taintedParts []string
				for _, part := range vulnerability.Evidence.ValueParts {
					if part.Source == nil {
						continue
					}
					if *part.Source != 0 {
						t.Fatalf("value part source index = %d, want 0", *part.Source)
					}
					// Redaction of a tainted SQL literal or command argument can
					// empty the value. Otherwise it is exactly the source value.
					if !part.Redacted && part.Value != "" && part.Value != sink.value {
						t.Errorf("tainted part = %q, want %q", part.Value, sink.value)
					}
					taintedParts = append(taintedParts, part.Value)
				}
				// Concatenation and Builder keep the exact range of the SQL text:
				// clean prefix, tainted value, clean suffix. The other shapes
				// taint the whole value (coarse) or the whole argument.
				if sink.name == "SinkSQL" && (kind == "taintedConcat" || kind == "taintedBuilder") {
					parts := vulnerability.Evidence.ValueParts
					if len(parts) != 3 || parts[0].Value != sink.prefix || parts[1].Source == nil || parts[2].Value != sink.suffix {
						t.Errorf("value parts = %+v, want prefix %q, tainted, suffix %q", parts, sink.prefix, sink.suffix)
					}
				}
				if len(taintedParts) == 0 {
					t.Fatalf("no tainted value part: %+v", vulnerability.Evidence)
				}
				t.Logf("evidence: %+v", vulnerability.Evidence)
			})
		}
	}
}

// TestRequestActive checks that the request of runInRequest is a sampled IAST
// request: a value that TaintString marks is seen as tainted.
func TestRequestActive(t *testing.T) {
	requireIAST(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	runInRequest(t, "/active?q=attacker", func(_ context.Context, req *http.Request) {
		if !taintedParameter(req) {
			t.Error("the request parameter is not tainted: the request is not active")
		}
	})
}
