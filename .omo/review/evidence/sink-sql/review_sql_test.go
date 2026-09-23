package testapp_test

import (
	"context"
	stdsql "database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/orchestrion/runtime/built"
)

type reviewValuer struct {
	value string
	calls *int
	err   error
}

func (v reviewValuer) Value() (driver.Value, error) {
	(*v.calls)++
	return v.value, v.err
}

func TestReviewSQLParameterValuerIsNotQueryEvidence(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires woven database/sql")
	}
	// Given an active analysis and a tainted value returned by driver.Valuer.
	fixture := newSQLFixture(t)
	calls := 0
	before := telemetry.ExecutedSink.SqlInjection.Load()
	// When the parameter is passed to a clean query.
	result, err := fixture.db.ExecContext(fixture.ctx, "SELECT ?", reviewValuer{value: fixture.query, calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	fixture.annotation.RLock()
	findings := len(fixture.annotation.Vulnerabilities)
	fixture.annotation.RUnlock()
	// Then the driver sees the value exactly once, but IAST does not report it.
	if rows != 7 || calls != 1 || findings != 0 || telemetry.ExecutedSink.SqlInjection.Load()-before != 1 {
		t.Fatalf("rows=%d valuerCalls=%d findings=%d sinkCalls=%d", rows, calls, findings, telemetry.ExecutedSink.SqlInjection.Load()-before)
	}
}

func TestReviewSQLValuerErrorDoesNotChangeResultOrReport(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires woven database/sql")
	}
	// Given a clean query and a Valuer that rejects a tainted parameter.
	fixture := newSQLFixture(t)
	sentinel := errors.New("valuer failure")
	calls := 0
	before := telemetry.ExecutedSink.SqlInjection.Load()
	// When database/sql converts the parameter.
	result, err := fixture.db.ExecContext(fixture.ctx, "SELECT ?", reviewValuer{value: fixture.query, calls: &calls, err: sentinel})
	fixture.annotation.RLock()
	findings := len(fixture.annotation.Vulnerabilities)
	fixture.annotation.RUnlock()
	// Then the original error propagates and the query still has no SQLi evidence.
	if result != nil || !errors.Is(err, sentinel) || calls != 1 || findings != 0 || telemetry.ExecutedSink.SqlInjection.Load()-before != 1 {
		t.Fatalf("result=%v error=%v valuerCalls=%d findings=%d sinkCalls=%d", result, err, calls, findings, telemetry.ExecutedSink.SqlInjection.Load()-before)
	}
}

func TestReviewSQLDelegatedOperations(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires woven database/sql")
	}
	tests := []struct {
		name string
		run  func(context.Context, *stdsql.DB, string) error
		want int
	}{
		{"DB.Prepare", func(_ context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.Prepare(query)
			if stmt != nil {
				defer stmt.Close()
			}
			return err
		}, 1},
		{"DB.Exec", func(_ context.Context, db *stdsql.DB, query string) error {
			_, err := db.Exec(query)
			return err
		}, 1},
		{"DB.Query", func(_ context.Context, db *stdsql.DB, query string) error {
			rows, err := db.Query(query)
			if rows != nil {
				defer rows.Close()
			}
			return err
		}, 1},
		{"DB.QueryRow", func(_ context.Context, db *stdsql.DB, query string) error {
			return db.QueryRow(query).Scan()
		}, 1},
		{"Tx.Prepare", func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			stmt, err := tx.Prepare(query)
			if stmt != nil {
				defer stmt.Close()
			}
			return err
		}, 1},
		{"Tx.Exec", func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			_, err = tx.Exec(query)
			return err
		}, 1},
		{"Tx.Query", func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			rows, err := tx.Query(query)
			if rows != nil {
				defer rows.Close()
			}
			return err
		}, 1},
		{"Tx.QueryRow", func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			return tx.QueryRow(query).Scan()
		}, 1},
		{"Tx.QueryRowContext", func(ctx context.Context, db *stdsql.DB, query string) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			return tx.QueryRowContext(ctx, query).Scan()
		}, 1},
		{"Conn.QueryRowContext", func(ctx context.Context, db *stdsql.DB, query string) error {
			conn, err := db.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			return conn.QueryRowContext(ctx, query).Scan()
		}, 1},
		{"Stmt.QueryRow", func(ctx context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.PrepareContext(ctx, query)
			if err != nil {
				return err
			}
			defer stmt.Close()
			return stmt.QueryRow().Scan()
		}, 2},
		{"Stmt.Exec", func(ctx context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.PrepareContext(ctx, query)
			if err != nil {
				return err
			}
			defer stmt.Close()
			_, err = stmt.Exec()
			return err
		}, 2},
		{"Stmt.Query", func(ctx context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.PrepareContext(ctx, query)
			if err != nil {
				return err
			}
			defer stmt.Close()
			rows, err := stmt.Query()
			if rows != nil {
				defer rows.Close()
			}
			return err
		}, 2},
		{"Stmt.QueryRowContext", func(ctx context.Context, db *stdsql.DB, query string) error {
			stmt, err := db.PrepareContext(ctx, query)
			if err != nil {
				return err
			}
			defer stmt.Close()
			return stmt.QueryRowContext(ctx).Scan()
		}, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given a tainted query and an active request span.
			fixture := newSQLFixture(t)
			before := telemetry.ExecutedSink.SqlInjection.Load()
			// When one public SQL operation delegates to a woven boundary.
			err := test.run(fixture.ctx, fixture.db, fixture.query)
			if err != nil && !errors.Is(err, stdsql.ErrNoRows) {
				t.Fatal(err)
			}
			fixture.annotation.RLock()
			findings := len(fixture.annotation.Vulnerabilities)
			fixture.annotation.RUnlock()
			// Then each reached prepare/query/exec boundary reports exactly once.
			if findings != test.want || telemetry.ExecutedSink.SqlInjection.Load()-before != uint64(test.want) {
				t.Fatalf("findings=%d sinkCalls=%d want=%d", findings, telemetry.ExecutedSink.SqlInjection.Load()-before, test.want)
			}
			fixture.annotation.RLock()
			for _, finding := range fixture.annotation.Vulnerabilities {
				if finding.Location == nil || !strings.HasSuffix(finding.Location.Path, "review_sql_test.go") || finding.Location.Line == 0 {
					t.Errorf("sink location is not a customer callsite: %+v", finding.Location)
				}
			}
			fixture.annotation.RUnlock()
		})
	}
}
