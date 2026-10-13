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
	"slices"
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

// The trees whose expected evidence differs (envTree). The runner of each
// tree sets the variable for its validation step.
const (
	envTree      = "DD_IAST_BENCH_TREE"
	treeHeapbits = "heapbits"
	treePR39     = "pr39"
)

// part is one expected evidence part: its text, and whether it comes from
// the source (index 0, the parameter "q").
type part struct {
	value   string
	tainted bool
}

func clean(v string) part   { return part{v, false} }
func tainted(v string) part { return part{v, true} }

// expectedParts returns the exact evidence parts (with redaction off) of a
// sink call. The SQL evidence is the query; the command evidence is the
// joined argument list "/bin/sh -c <argument>". In both trees, concatenation
// and strings.Builder keep the exact range of the value. In the tree of
// PR #39, fmt.Sprintf is coarse: the whole result (or the whole argument) is
// tainted. In the heapbits tree it keeps the exact range.
func expectedParts(tree, sinkName, kind string) []part {
	exactSprintf := tree == treeHeapbits
	switch sinkName {
	case "SinkSQL":
		switch {
		case kind == "tainted":
			return []part{tainted(sinkSQLValue)}
		case kind == "taintedSprintf" && !exactSprintf:
			return []part{tainted(sinkSQLPrefix + sinkSQLValue + sinkSQLSuffix)}
		default: // taintedConcat, taintedBuilder, taintedSprintf (exact)
			return []part{clean(sinkSQLPrefix), tainted(sinkSQLValue), clean(sinkSQLSuffix)}
		}
	case "SinkCommand":
		command := sinkCmdShell + " -c "
		switch {
		case kind == "tainted":
			return []part{clean(command), tainted(sinkCmdValue)}
		case kind == "taintedSprintf" && !exactSprintf:
			return []part{clean(command), tainted(sinkCmdPrefix + sinkCmdValue)}
		default:
			return []part{clean(command + sinkCmdPrefix), tainted(sinkCmdValue)}
		}
	}
	panic("unknown sink " + sinkName)
}

// TestSinkWorkloads checks each sink workload: no vulnerability for the clean
// call; exactly 1 vulnerability for each tainted call, with one source (the
// parameter "q") and the exact expected evidence parts of the tree
// (DD_IAST_BENCH_TREE). The exact values need DD_IAST_REDACTION_ENABLED=false
// (the runner validation sets it); with redaction on, the test checks the
// number of tainted parts and their source only.
func TestSinkWorkloads(t *testing.T) {
	requireIAST(t)
	tree := os.Getenv(envTree)
	if tree != treeHeapbits && tree != treePR39 {
		t.Fatalf("set %s=%s or %s (the expected evidence ranges differ between the trees)", envTree, treeHeapbits, treePR39)
	}
	redacted := os.Getenv("DD_IAST_REDACTION_ENABLED") != "false"
	type sink struct {
		name     string
		vuln     string
		value    string
		argument func(kind, v string) string
		run      func(ctx context.Context, argument string)
	}
	db := newNoopDB()
	defer db.Close()
	sinks := []sink{
		{"SinkSQL", "SQL_INJECTION", sinkSQLValue, sqlArgument,
			func(ctx context.Context, argument string) {
				if err := sqlSink(ctx, db, argument); err != nil {
					t.Errorf("query failed: %v", err)
				}
			}},
		{"SinkCommand", "COMMAND_INJECTION", sinkCmdValue, cmdArgument,
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
				if len(event.Sources) != 1 || event.Sources[0].Origin != "http.request.parameter" || event.Sources[0].Name != "q" ||
					(!redacted && event.Sources[0].Value != sink.value) {
					t.Fatalf("sources = %+v, want one http.request.parameter named q with the value %q", event.Sources, sink.value)
				}
				want := expectedParts(tree, sink.name, kind)
				var got []part
				for _, p := range vulnerability.Evidence.ValueParts {
					if p.Source != nil && *p.Source != 0 {
						t.Fatalf("value part source index = %d, want 0", *p.Source)
					}
					got = append(got, part{p.Value, p.Source != nil})
				}
				if redacted {
					count := func(parts []part) (n int) {
						for _, p := range parts {
							if p.tainted {
								n++
							}
						}
						return n
					}
					if count(got) != count(want) {
						t.Errorf("tainted parts = %d, want %d: %+v", count(got), count(want), vulnerability.Evidence)
					}
				} else if !slices.Equal(got, want) {
					t.Errorf("value parts (tree %s) = %+v, want %+v", tree, got, want)
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
