// Command dedupprobe is the fx-perf-memory-F1 review reproducer.
//
// Minimal realistic surface: an HTTP handler of the exact
// func(http.ResponseWriter, *http.Request) shape (so the woven build
// installs the application.http.Handler fallback advice: scope
// Begin/EagerHTTP/Finish), one tainted query parameter concatenated into
// SQL text, executed through database/sql on a fake driver (real sink).
//
// Built twice: plainly (no Orchestrion) and woven (go tool orchestrion).
// Reports per-request TotalAlloc/Mallocs deltas around the handler call and
// the total number of committed vulnerabilities across the whole run (no
// mocktracer reset), plus an optional alloc profile.
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

var db *sql.DB

// handle has the exact application handler shape so the woven build wraps it.
func handle(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request")
	defer span.Finish()
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, err := db.QueryContext(ctx, query)
	if err == nil {
		_ = rows.Close()
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	n := flag.Int("n", 300, "measured requests")
	warm := flag.Int("warm", 20, "warmup requests")
	memprofile := flag.String("memprofile", "", "write an alloc profile (MemProfileRate=1)")
	flag.Parse()
	if *memprofile != "" {
		runtime.MemProfileRate = 1
	}

	sql.Register("dedupprobe", memDriver{})
	var err error
	if db, err = sql.Open("dedupprobe", ""); err != nil {
		panic(err)
	}
	mt := mocktracer.Start()
	defer mt.Stop()

	req := httptest.NewRequest(http.MethodGet, "/users?name=alice", nil)

	for range *warm {
		handle(httptest.NewRecorder(), req)
	}

	var ms0, ms1 runtime.MemStats
	var totalBytes, totalObjs uint64
	for range *n {
		runtime.ReadMemStats(&ms0)
		handle(httptest.NewRecorder(), req)
		runtime.ReadMemStats(&ms1)
		totalBytes += ms1.TotalAlloc - ms0.TotalAlloc
		totalObjs += ms1.Mallocs - ms0.Mallocs
	}

	// Count committed vulnerabilities across ALL finished spans of the run
	// (the mocktracer is never reset), i.e. what deduplication let through.
	vulnSpans, vulns := 0, 0
	for _, s := range mt.FinishedSpans() {
		if raw, ok := s.Tag(spans.SpanTagJson).(string); ok && raw != "" {
			vulnSpans++
			var ev struct {
				Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
			}
			if json.Unmarshal([]byte(raw), &ev) == nil {
				vulns += len(ev.Vulnerabilities)
			}
		}
	}

	out := map[string]any{
		"woven":             built.WithOrchestrion,
		"go":                runtime.Version(),
		"iast_enabled":      config.Enabled,
		"sampling":          config.RequestSamplingPct,
		"dedup":             config.DeduplicationEnabled,
		"stack_traces":      config.StackTraceEnabled,
		"n":                 *n,
		"warm":              *warm,
		"bytes_per_req":     totalBytes / uint64(*n),
		"objects_per_req":   totalObjs / uint64(*n),
		"vulns_total":       vulns,
		"vuln_spans_total":  vulnSpans,
		"profiled_requests": *warm + *n,
	}
	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			panic(err)
		}
		runtime.GC()
		if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
			panic(err)
		}
		_ = f.Close()
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type memDriver struct{}

func (memDriver) Open(string) (driver.Conn, error) { return memConn{}, nil }

type memConn struct{}

func (memConn) Prepare(string) (driver.Stmt, error) { return memStmt{}, nil }
func (memConn) Close() error                        { return nil }
func (memConn) Begin() (driver.Tx, error)           { return memTx{}, nil }
func (memConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return memRows{}, nil
}

type memStmt struct{}

func (memStmt) Close() error                               { return nil }
func (memStmt) NumInput() int                              { return -1 }
func (memStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(0), nil }
func (memStmt) Query([]driver.Value) (driver.Rows, error)  { return memRows{}, nil }

type memTx struct{}

func (memTx) Commit() error   { return nil }
func (memTx) Rollback() error { return nil }

type memRows struct{}

func (memRows) Columns() []string         { return []string{"v"} }
func (memRows) Close() error              { return nil }
func (memRows) Next([]driver.Value) error { return io.EOF }
