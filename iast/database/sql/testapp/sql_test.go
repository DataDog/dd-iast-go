// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/DataDog/dd-iast-go/iast/database/sql" // register isolated sink callback
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

const testDriverName = "dd-iast-sql-test"

var driverCalls atomic.Uint64
var retryOnce atomic.Bool

func init() {
	stdsql.Register(testDriverName, testDriver{})
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

func TestDatabaseSQLInstrumentedCount(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	if got := telemetry.InstrumentedSink[constants.VulnerabilityTypeSqlInjection]; got != 11 {
		t.Fatalf("instrumented SQL sinks = %d, want 11", got)
	}
}

func TestDatabaseSQLPublicOperationBoundaries(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	tests := []struct {
		name string
		run  func(context.Context, *stdsql.DB, string) error
		want int
	}{
		{name: "db prepare", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.PrepareContext(ctx, query)
			if stmt != nil {
				stmt.Close()
			}
			return err
		}},
		{name: "db exec", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			result, err := db.ExecContext(ctx, query)
			if err == nil {
				rows, _ := result.RowsAffected()
				if rows != 7 {
					return io.ErrUnexpectedEOF
				}
			}
			return err
		}},
		{name: "db query", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			rows, err := db.QueryContext(ctx, query)
			if rows != nil {
				rows.Close()
			}
			return err
		}},
		{name: "query row delegation", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			return db.QueryRowContext(ctx, query).Scan()
		}},
		{name: "conn prepare", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			conn, err := db.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			stmt, err := conn.PrepareContext(ctx, query)
			if stmt != nil {
				stmt.Close()
			}
			return err
		}},
		{name: "conn exec", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			conn, err := db.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.ExecContext(ctx, query)
			return err
		}},
		{name: "conn query", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			conn, err := db.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			rows, err := conn.QueryContext(ctx, query)
			if rows != nil {
				rows.Close()
			}
			return err
		}},
		{name: "tx prepare", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			stmt, err := tx.PrepareContext(ctx, query)
			if stmt != nil {
				stmt.Close()
			}
			return err
		}},
		{name: "tx exec", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			_, err = tx.ExecContext(ctx, query)
			return err
		}},
		{name: "tx query", want: 1, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			rows, err := tx.QueryContext(ctx, query)
			if rows != nil {
				rows.Close()
			}
			return err
		}},
		{name: "prepared exec", want: 2, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.PrepareContext(ctx, query)
			if err != nil {
				return err
			}
			defer stmt.Close()
			_, err = stmt.ExecContext(ctx)
			return err
		}},
		{name: "prepared query", want: 2, run: func(ctx context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.PrepareContext(ctx, query)
			if err != nil {
				return err
			}
			defer stmt.Close()
			rows, err := stmt.QueryContext(ctx)
			if rows != nil {
				rows.Close()
			}
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSQLFixture(t)
			before := telemetry.ExecutedSink.SqlInjection.Load()
			err := test.run(fixture.ctx, fixture.db, fixture.query)
			if err != nil && err != stdsql.ErrNoRows {
				t.Fatal(err)
			}
			fixture.annotation.RLock()
			findings := append([]model.Vulnerability(nil), fixture.annotation.Vulnerabilities...)
			fixture.annotation.RUnlock()
			count := len(findings)
			for _, finding := range findings {
				if finding.Type != constants.VulnerabilityTypeSqlInjection || finding.Location == nil || !strings.HasSuffix(finding.Location.Path, "sql_test.go") {
					t.Fatalf("unexpected finding: %#v location:%#v", finding, finding.Location)
				}
			}
			executed := telemetry.ExecutedSink.SqlInjection.Load() - before
			if count != test.want {
				t.Fatalf("vulnerability count = %d, want %d (executed sink delta %d)", count, test.want, executed)
			}
			if got := executed; got != uint64(test.want) {
				t.Fatalf("executed sink delta = %d, want %d", got, test.want)
			}
		})
	}
}

func TestDatabaseSQLIgnoresTaintedArguments(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newSQLFixture(t)
	before := telemetry.ExecutedSink.SqlInjection.Load()
	if _, err := fixture.db.ExecContext(fixture.ctx, "SELECT ?", fixture.query); err != nil {
		t.Fatal(err)
	}
	fixture.annotation.RLock()
	findings := len(fixture.annotation.Vulnerabilities)
	fixture.annotation.RUnlock()
	if findings != 0 || telemetry.ExecutedSink.SqlInjection.Load()-before != 1 {
		t.Fatalf("findings = %d, executed delta = %d", findings, telemetry.ExecutedSink.SqlInjection.Load()-before)
	}
}

func TestDatabaseSQLCanceledContextPreservesResult(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newSQLFixture(t)
	ctx, cancel := context.WithCancel(fixture.ctx)
	cancel()
	beforeCalls := driverCalls.Load()
	_, err := fixture.db.ExecContext(ctx, fixture.query)
	if err != context.Canceled || driverCalls.Load() != beforeCalls {
		t.Fatalf("result = %v, driver delta = %d", err, driverCalls.Load()-beforeCalls)
	}
	fixture.annotation.RLock()
	findings := len(fixture.annotation.Vulnerabilities)
	fixture.annotation.RUnlock()
	if findings != 1 {
		t.Fatalf("attempted canceled sink findings = %d", findings)
	}
}

func TestDatabaseSQLPayloadEncodings(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newSQLFixture(t)
	if _, err := fixture.db.ExecContext(fixture.ctx, fixture.query); err != nil {
		t.Fatal(err)
	}
	assertEventEncodings(t, fixture.annotation)
}

func TestDatabaseSQLRetryReportsOnce(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newSQLFixture(t)
	retryOnce.Store(false)
	driverCalls.Store(0)
	query := fixture.query + " retry"
	query = propagation.JoinString([]string{fixture.query, " retry"}, "", query)
	if _, err := fixture.db.ExecContext(fixture.ctx, query); err != nil {
		t.Fatal(err)
	}
	fixture.annotation.RLock()
	findings := len(fixture.annotation.Vulnerabilities)
	fixture.annotation.RUnlock()
	if driverCalls.Load() != 2 || findings != 1 {
		t.Fatalf("driver calls = %d, findings = %d", driverCalls.Load(), findings)
	}
}

func TestDatabaseSQLDriverPanicIsPreserved(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	fixture := newSQLFixture(t)
	query := fixture.query + " panic"
	query = propagation.JoinString([]string{fixture.query, " panic"}, "", query)
	defer func() {
		if recovered := recover(); recovered != "driver panic" {
			t.Fatalf("recovered panic = %#v", recovered)
		}
		fixture.annotation.RLock()
		findings := len(fixture.annotation.Vulnerabilities)
		fixture.annotation.RUnlock()
		if findings != 1 {
			t.Fatalf("panic-path findings = %d", findings)
		}
	}()
	_, _ = fixture.db.ExecContext(fixture.ctx, query)
}

func TestDatabaseSQLNilStmtPreservesPanic(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	before := telemetry.ExecutedSink.SqlInjection.Load()
	defer func() {
		if recover() == nil {
			t.Fatal("nil statement did not panic")
		}
		if telemetry.ExecutedSink.SqlInjection.Load() != before {
			t.Fatal("nil statement invoked sink callback")
		}
	}()
	var stmt *stdsql.Stmt
	_, _ = stmt.ExecContext(context.Background())
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

func BenchmarkStmtExecContextInactive(b *testing.B) {
	db, err := stdsql.Open(testDriverName, "")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	stmt, err := db.PrepareContext(context.Background(), "SELECT ?")
	if err != nil {
		b.Fatal(err)
	}
	defer stmt.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := stmt.ExecContext(context.Background(), 1); err != nil {
			b.Fatal(err)
		}
	}
}

type sqlFixture struct {
	db         *stdsql.DB
	ctx        context.Context
	scope      *request.Scope
	span       *tracer.Span
	annotation *spans.Annotation
	query      string
}

func newSQLFixture(t *testing.T) *sqlFixture {
	t.Helper()
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("active scope was not created")
	}
	span, spanCtx := tracer.StartSpanFromContext(ctx, "request")
	annotation := spans.BindScope(span, scope)
	secret := taint.TaintString(spanCtx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "value"}, "secret")
	query := "SELECT '" + secret + "'"
	query = propagation.JoinString([]string{"SELECT '", secret, "'"}, "", query)
	db, err := stdsql.Open(testDriverName, "")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &sqlFixture{db: db, ctx: spanCtx, scope: scope, span: span, annotation: annotation, query: query}
	t.Cleanup(func() {
		db.Close()
		spans.Finished(span)
		scope.Finish()
		span.Finish()
	})
	return fixture
}

type testDriver struct{}

func (testDriver) Open(string) (driver.Conn, error) { return &testConn{}, nil }

type testConn struct{}

func (*testConn) Prepare(query string) (driver.Stmt, error) { return &testStmt{query: query}, nil }
func (*testConn) Close() error                              { return nil }
func (*testConn) Begin() (driver.Tx, error)                 { return testTx{}, nil }
func (*testConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return testTx{}, nil
}
func (*testConn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	return &testStmt{query: query}, nil
}
func (*testConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	driverCalls.Add(1)
	if strings.Contains(query, "panic") {
		panic("driver panic")
	}
	if strings.Contains(query, "retry") && retryOnce.CompareAndSwap(false, true) {
		return nil, driver.ErrBadConn
	}
	return driver.RowsAffected(7), nil
}
func (*testConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	driverCalls.Add(1)
	return testRows{}, nil
}

type testStmt struct{ query string }

func (*testStmt) Close() error  { return nil }
func (*testStmt) NumInput() int { return -1 }
func (*testStmt) Exec([]driver.Value) (driver.Result, error) {
	driverCalls.Add(1)
	return driver.RowsAffected(7), nil
}
func (*testStmt) Query([]driver.Value) (driver.Rows, error) {
	driverCalls.Add(1)
	return testRows{}, nil
}
func (*testStmt) ExecContext(context.Context, []driver.NamedValue) (driver.Result, error) {
	driverCalls.Add(1)
	return driver.RowsAffected(7), nil
}
func (*testStmt) QueryContext(context.Context, []driver.NamedValue) (driver.Rows, error) {
	driverCalls.Add(1)
	return testRows{}, nil
}

type testTx struct{}

func (testTx) Commit() error   { return nil }
func (testTx) Rollback() error { return nil }

type testRows struct{}

func (testRows) Columns() []string         { return []string{"value"} }
func (testRows) Close() error              { return nil }
func (testRows) Next([]driver.Value) error { return io.EOF }
