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
	osexec "os/exec"
	"regexp"
	"testing"

	_ "github.com/DataDog/dd-iast-go/iast/database/sql" // register test sink
	_ "github.com/DataDog/dd-iast-go/iast/os/exec"      // register test sink
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
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

func requestEvent(t *testing.T, operation func(context.Context, *http.Request), values url.Values) model.Event {
	t.Helper()
	mock := mocktracer.Start()
	defer mock.Stop()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.e2e.request")
		defer span.Finish()
		operation(ctx, r.WithContext(ctx))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "?" + values.Encode())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	finished := mock.FinishedSpans()
	if len(finished) != 1 {
		t.Fatalf("finished spans = %d", len(finished))
	}
	raw, _ := finished[0].Tag(spans.SpanTagJson).(string)
	if raw == "" {
		if finished[0].Tag(spans.SpanTagEnabled) == float64(1) {
			return model.Event{}
		}
		t.Fatal("request was not analyzed")
	}
	var event model.Event
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		t.Fatal(err)
	}
	return event
}

func requireWoven(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("run with Orchestrion")
	}
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

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

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
