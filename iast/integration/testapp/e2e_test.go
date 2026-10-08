// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	osexec "os/exec"
	"path"
	"regexp"
	"strings"
	"testing"

	_ "github.com/DataDog/dd-iast-go/iast/database/sql" // register test sink
	_ "github.com/DataDog/dd-iast-go/iast/os/exec"      // register test sink
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/assert"
)

const driverName = "dd-iast-e2e"

func init() {
	sql.Register(driverName, testDriver{})
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	config.VulnerabilitiesPerRequest = 64
	config.DeduplicationEnabled = false
	config.RedactionEnabled = true
	config.RedactionNamePattern = regexp.MustCompile(`never-match`)
	config.RedactionValuePattern = regexp.MustCompile(`never-match`)
	config.TruncationMaxValue = 250
}

func TestHTTPSourceToSQLPrepareAndExecute(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get("query")
		stmt, err := db.PrepareContext(ctx, query)
		if err != nil {
			t.Error(err)
			return
		}
		defer stmt.Close()
		if _, err = stmt.ExecContext(ctx); err != nil {
			t.Error(err)
		}
	}, url.Values{"query": {"SELECT 'secret'"}})
	if got := countType(event, constants.VulnerabilityTypeSqlInjection); got != 2 {
		t.Fatalf("SQL findings = %d, want prepare and execute", got)
	}
	assertSourcesReferenced(t, event)
	assertLocationsInTestFile(t, event, "e2e_test.go")
	if event.Vulnerabilities[0].Location.Line == event.Vulnerabilities[1].Location.Line {
		t.Error("prepare and execute must report their separate call sites")
	}
	// The value is a full copy of the source, and it has a literal. The SQL
	// analyzer redacts the literal: it redacts all the tainted part, and the
	// source value too (the same redaction as PR #39).
	assert.Equal(t, []model.Source{{
		Origin:   constants.OriginHttpRequestParameter,
		Name:     "query",
		Pattern:  "abcdefghijklmno",
		Redacted: true,
	}}, event.Sources)
	source := 0
	for _, vulnerability := range event.Vulnerabilities {
		assert.Equal(t, &model.Evidence{ValueParts: []model.ValuePart{
			{Pattern: "abcdefghijklmno", Redacted: true, SourceIndex: &source},
		}}, vulnerability.Evidence)
	}
}

func TestHTTPSourceToCommandAttempt(t *testing.T) {
	requireWoven(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		path := r.URL.Query().Get("path")
		_ = osexec.CommandContext(ctx, path).Run()
	}, url.Values{"path": {"/definitely-not-present-dd-iast"}})
	if got := countType(event, constants.VulnerabilityTypeCommandInjection); got != 1 {
		t.Fatalf("command findings = %d, want 1", got)
	}
	assertSourcesReferenced(t, event)
	assertLocationsInTestFile(t, event, "e2e_test.go")
	assert.Equal(t, []model.Source{
		model.NewSourceString(constants.OriginHttpRequestParameter, "path", "/definitely-not-present-dd-iast"),
	}, event.Sources)
	assert.Equal(t, model.NewEvidenceTaintedValue([]model.ValuePart{
		model.NewValuePartTaintedString("/definitely-not-present-dd-iast", 0, nil),
	}), event.Vulnerabilities[0].Evidence)
}

func TestJSONUnmarshalPropagatesNestedStrings(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(""), func(ctx context.Context, _ *http.Request) {
		type nested struct {
			Value string `json:"value"`
		}
		var destination struct {
			Nested  nested            `json:"nested"`
			Values  []string          `json:"values"`
			Mapping map[string]string `json:"mapping"`
			Any     any               `json:"any"`
		}
		document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"nested":{"value":"secret"},"values":["escaped\\nvalue"],"mapping":{"key":"mapped"},"any":"dynamic"}`))
		err := json.Unmarshal(document, &destination)
		ok := err == nil && taint.IsTaintedString(destination.Nested.Value) && taint.IsTaintedString(destination.Values[0]) && taint.IsTaintedString(destination.Mapping["key"])
		if !ok {
			t.Errorf("taint = nested:%v array:%v map:%v error:%v", taint.IsTaintedString(destination.Nested.Value), taint.IsTaintedString(destination.Values[0]), taint.IsTaintedString(destination.Mapping["key"]), err)
		}
		observed <- ok
	})
	if !<-observed {
		t.Fatal("json.Unmarshal did not propagate nested strings")
	}
}

func TestJSONDecoderPropagatesOwnerBoundBody(t *testing.T) {
	requireWoven(t)
	const body = `{"value":"first"} {"value":"second"}`
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(body), func(ctx context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var first, second struct {
			Value string `json:"value"`
		}
		err1 := decoder.Decode(&first)
		err2 := decoder.Decode(&second)
		firstSource, secondSource := "", ""
		taint.VisitString(ctx, first.Value, func(found taint.Range) bool { firstSource = found.Source.Value; return false })
		taint.VisitString(ctx, second.Value, func(found taint.Range) bool { secondSource = found.Source.Value; return false })
		// Plan 9.2: the body source taints the bytes at Read. Both values
		// have the body source, and its value is the body copy (not one
		// document for each Decode call, as in PR #39).
		ok := err1 == nil && err2 == nil && taint.IsTaintedString(first.Value) && taint.IsTaintedString(second.Value) && firstSource == body && secondSource == body
		if !ok {
			t.Errorf("decoder sources = first:%q second:%q errors:%v/%v", firstSource, secondSource, err1, err2)
		}
		observed <- ok
	})
	if !<-observed {
		t.Fatal("json.Decoder did not propagate reused reader provenance")
	}
}

func TestJSONCustomUnmarshalersDoNotPublishTaint(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(""), func(ctx context.Context, _ *http.Request) {
		document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"value":"secret"}`))
		var destination struct {
			Value customString `json:"value"`
		}
		err := json.Unmarshal(document, &destination)
		observed <- err == nil && destination.Value == "sanitized" && !taint.IsTaintedString(destination.Value)
	})
	if !<-observed {
		t.Fatal("custom unmarshaler output was tainted")
	}
}

func TestJSONPanickingUnmarshalerPreservesPanicWithoutTaint(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(""), func(ctx context.Context, _ *http.Request) {
		document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"value":"secret"}`))
		destination := struct {
			Value panicString `json:"value"`
		}{Value: "clean"}
		defer func() { observed <- recover() == "json panic" && !taint.IsTaintedString(destination.Value) }()
		_ = json.Unmarshal(document, &destination)
	})
	if !<-observed {
		t.Fatal("panicking unmarshaler changed panic or taint")
	}
}

func TestJSONInvalidInputDoesNotTaintDestination(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(""), func(ctx context.Context, _ *http.Request) {
		destination := struct {
			Value string `json:"value"`
		}{Value: "clean"}
		document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"value":`))
		err := json.Unmarshal(document, &destination)
		observed <- err != nil && !taint.IsTaintedString(destination.Value)
	})
	if !<-observed {
		t.Fatal("failed JSON published taint")
	}
}

func TestSafeSQLArgumentAndCommandConstructionDoNotReport(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		value := r.URL.Query().Get("value")
		if _, err := db.ExecContext(ctx, "SELECT ?", value); err != nil {
			t.Error(err)
		}
		_ = osexec.CommandContext(ctx, value)
	}, url.Values{"value": {"secret"}})
	if len(event.Vulnerabilities) != 0 {
		t.Fatalf("safe operations reported %#v", event.Vulnerabilities)
	}
}

func serveRequest(t *testing.T, body io.Reader, operation func(context.Context, *http.Request)) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.json.request")
		defer span.Finish()
		operation(ctx, r.WithContext(ctx))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}

func requestEvent(t *testing.T, operation func(context.Context, *http.Request), values url.Values) model.Event {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://iast.test/?"+values.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return captureRequestEvent(t, operation, request)
}

func BenchmarkJSONUnmarshalClean(b *testing.B) {
	document := []byte(`{"nested":{"value":"clean"},"values":["one","two"]}`)
	b.ReportAllocs()
	for b.Loop() {
		var destination struct {
			Nested struct {
				Value string `json:"value"`
			} `json:"nested"`
			Values []string `json:"values"`
		}
		if err := json.Unmarshal(document, &destination); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSONUnmarshalActiveClean(b *testing.B) {
	ctx, _, created := taintrequest.Begin(context.Background())
	if !created {
		b.Fatal("scope not created")
	}
	defer taintrequest.FinishContext(ctx, true)
	document := []byte(`{"nested":{"value":"clean"},"values":["one","two"]}`)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var destination struct {
			Nested struct {
				Value string `json:"value"`
			} `json:"nested"`
			Values []string `json:"values"`
		}
		if err := json.Unmarshal(document, &destination); err != nil {
			b.Fatal(err)
		}
	}
}

// requireWoven skips the test when the build is not woven. With
// DD_IAST_REQUIRE_WOVEN=1 (CI), the test fails instead.
func requireWoven(t *testing.T) {
	t.Helper()
	if built.WithOrchestrion {
		return
	}
	if os.Getenv("DD_IAST_REQUIRE_WOVEN") == "1" {
		t.Fatal("the build is not woven (DD_IAST_REQUIRE_WOVEN=1)")
	}
	t.Skip("run with Orchestrion")
}

func countType(event model.Event, kind constants.VulnerabilityType) int {
	count := 0
	for _, vulnerability := range event.Vulnerabilities {
		if vulnerability.Type == kind {
			count++
		}
	}
	return count
}

func assertSourcesReferenced(t *testing.T, event model.Event) {
	t.Helper()
	if len(event.Sources) == 0 {
		t.Fatal("event has no sources")
	}
	for _, vulnerability := range event.Vulnerabilities {
		if vulnerability.Evidence == nil {
			continue
		}
		for _, part := range vulnerability.Evidence.ValueParts {
			if part.SourceIndex != nil && (*part.SourceIndex < 0 || *part.SourceIndex >= len(event.Sources)) {
				t.Fatalf("invalid source index %d", *part.SourceIndex)
			}
		}
	}
}

// assertLocationsInTestFile checks that each finding has a location with a
// line in the file that has the name file. The location is the call site of
// the sink in the application code.
func assertLocationsInTestFile(t *testing.T, event model.Event, file string) {
	t.Helper()
	for index, vulnerability := range event.Vulnerabilities {
		if !assert.NotNil(t, vulnerability.Location, "finding %d has no location", index) {
			continue
		}
		assert.Equal(t, file, path.Base(vulnerability.Location.Path), "finding %d path", index)
		assert.NotZero(t, vulnerability.Location.Line, "finding %d line", index)
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type customString string

func (value *customString) UnmarshalJSON([]byte) error { *value = "sanitized"; return nil }

type panicString string

func (*panicString) UnmarshalJSON([]byte) error { panic("json panic") }

type testDriver struct{}

func (testDriver) Open(string) (driver.Conn, error) { return testConn{}, nil }

type testConn struct{}

func (testConn) Prepare(query string) (driver.Stmt, error)                   { return testStmt{}, nil }
func (testConn) PrepareContext(context.Context, string) (driver.Stmt, error) { return testStmt{}, nil }
func (testConn) Close() error                                                { return nil }
func (testConn) Begin() (driver.Tx, error)                                   { return testTx{}, nil }
func (testConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

type testStmt struct{}

func (testStmt) Close() error                               { return nil }
func (testStmt) NumInput() int                              { return -1 }
func (testStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (testStmt) Query([]driver.Value) (driver.Rows, error)  { return testRows{}, nil }
func (testStmt) ExecContext(context.Context, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

type testTx struct{}

func (testTx) Commit() error   { return nil }
func (testTx) Rollback() error { return nil }

type testRows struct{}

func (testRows) Columns() []string         { return []string{"value"} }
func (testRows) Close() error              { return nil }
func (testRows) Next([]driver.Value) error { return io.EOF }
