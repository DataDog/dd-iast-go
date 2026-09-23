package main

import (
	"context"
	"database/sql/driver"
	"io"
	"sync"
)

// fakeDriver records every query text the driver receives (proves host behaviour).
type fakeDriver struct{}

var (
	queriesMu sync.Mutex
	queries   []string
)

func recordQuery(q string) {
	queriesMu.Lock()
	queries = append(queries, q)
	queriesMu.Unlock()
}

func (fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{}, nil }

type fakeConn struct{}

func (fakeConn) Prepare(q string) (driver.Stmt, error) { recordQuery(q); return fakeStmt{}, nil }
func (fakeConn) PrepareContext(_ context.Context, q string) (driver.Stmt, error) {
	recordQuery(q)
	return fakeStmt{}, nil
}
func (fakeConn) Close() error              { return nil }
func (fakeConn) Begin() (driver.Tx, error) { return fakeTx{}, nil }
func (fakeConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	recordQuery(q)
	return driver.RowsAffected(1), nil
}
func (fakeConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	recordQuery(q)
	return fakeRows{}, nil
}

type fakeStmt struct{}

func (fakeStmt) Close() error                               { return nil }
func (fakeStmt) NumInput() int                              { return -1 }
func (fakeStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (fakeStmt) Query([]driver.Value) (driver.Rows, error)  { return fakeRows{}, nil }

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeRows struct{}

func (fakeRows) Columns() []string         { return []string{"id"} }
func (fakeRows) Close() error              { return nil }
func (fakeRows) Next([]driver.Value) error { return io.EOF }
