// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

import (
	"context"
	stdsql "database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	// The sink callbacks are registered by the application main, which a test
	// binary does not have (the aspect excludes the generated test main).
	_ "github.com/DataDog/dd-iast-go/iast/database/sql"
	_ "github.com/DataDog/dd-iast-go/iast/os/exec"
)

// Sink workloads (plan 10.2 item 3). Each case takes the value of the query
// parameter "q" (a source), builds the sink argument with one propagation
// shape, and calls the sink in the handler of a sampled request. The sink is
// a database/sql query on a no-op driver, or an os/exec Cmd.Start that fails
// before the fork (the working directory does not exist, so os.StartProcess
// stops at its directory check; the IAST hook still sees the call).
//
// Note: DD_IAST_VULNERABILITIES_PER_REQUEST (default 2) caps the findings that
// one request keeps. The timed loop runs in one request, so after the cap the
// loop measures the sink check and the dropped report. The validation test
// (sinks_validation_test.go) checks the first call.

const (
	sinkSQLPrefix = "SELECT * FROM users WHERE name = '"
	sinkSQLSuffix = "'"
	sinkSQLValue  = "x' OR '1'='1"
	sinkCmdPrefix = "echo "
	sinkCmdValue  = "hello; cat /etc/passwd"
	sinkCmdShell  = "/bin/sh"
	sinkCmdDir    = "/nonexistent-dd-iast-bench-dir"
)

var sinkCases = []string{"clean", "tainted", "taintedConcat", "taintedBuilder", "taintedSprintf"}

// sinkArgument builds the sink argument from the tainted value v.
func sinkArgument(kind, prefix, suffix, clean, v string) string {
	switch kind {
	case "clean":
		return clean
	case "tainted":
		return v
	case "taintedConcat":
		return prefix + v + suffix
	case "taintedBuilder":
		var builder strings.Builder
		builder.WriteString(prefix)
		builder.WriteString(v)
		builder.WriteString(suffix)
		return builder.String()
	case "taintedSprintf":
		return fmt.Sprintf("%s%s%s", prefix, v, suffix)
	}
	panic("unknown sink case " + kind)
}

func sqlArgument(kind, v string) string {
	return sinkArgument(kind, sinkSQLPrefix, sinkSQLSuffix, "SELECT * FROM users WHERE name = 'alice'", v)
}

func cmdArgument(kind, v string) string {
	return sinkArgument(kind, sinkCmdPrefix, "", "echo hello", v)
}

// noopConnector is a database/sql connector whose connections answer queries
// with no rows and no work.
type noopConnector struct{}

func (noopConnector) Connect(context.Context) (driver.Conn, error) { return noopConn{}, nil }
func (noopConnector) Driver() driver.Driver                        { return noopDriver{} }

type noopDriver struct{}

func (noopDriver) Open(string) (driver.Conn, error) { return noopConn{}, nil }

type noopConn struct{}

func (noopConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (noopConn) Close() error                        { return nil }
func (noopConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (noopConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return noopRows{}, nil
}

type noopRows struct{}

func (noopRows) Columns() []string         { return []string{"c"} }
func (noopRows) Close() error              { return nil }
func (noopRows) Next([]driver.Value) error { return io.EOF }

func newNoopDB() *stdsql.DB {
	db := stdsql.OpenDB(noopConnector{})
	db.SetMaxIdleConns(2)
	return db
}

// sqlSink runs one query. It returns the error of the query.
func sqlSink(ctx context.Context, db *stdsql.DB, query string) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	return rows.Close()
}

// cmdSink runs one Cmd.Start that fails at the directory check.
func cmdSink(ctx context.Context, argument string) error {
	command := exec.CommandContext(ctx, sinkCmdShell, "-c", argument)
	command.Dir = sinkCmdDir
	return command.Start()
}

func sinkTarget(value string) string {
	return "/sink?q=" + url.QueryEscape(value)
}

func BenchmarkSinkSQL(b *testing.B) {
	for _, kind := range sinkCases {
		b.Run(kind, func(b *testing.B) {
			db := newNoopDB()
			defer db.Close()
			benchInRequest(b, sinkTarget(sinkSQLValue), func(ctx context.Context, req *http.Request) {
				v := req.FormValue("q")
				if err := sqlSink(ctx, db, sqlArgument(kind, v)); err != nil {
					b.Errorf("warm-up query failed: %v", err)
					return
				}
				b.ReportAllocs()
				for b.Loop() {
					if err := sqlSink(ctx, db, sqlArgument(kind, v)); err != nil {
						b.Errorf("query failed: %v", err)
						return
					}
				}
			})
		})
	}
}

func BenchmarkSinkCommand(b *testing.B) {
	for _, kind := range sinkCases {
		b.Run(kind, func(b *testing.B) {
			benchInRequest(b, sinkTarget(sinkCmdValue), func(ctx context.Context, req *http.Request) {
				v := req.FormValue("q")
				if err := cmdSink(ctx, cmdArgument(kind, v)); err == nil {
					b.Error("command unexpectedly started")
					return
				}
				b.ReportAllocs()
				for b.Loop() {
					_ = cmdSink(ctx, cmdArgument(kind, v))
				}
			})
		})
	}
}
