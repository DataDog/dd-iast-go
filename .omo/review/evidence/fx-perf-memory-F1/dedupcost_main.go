// Command dedupcost measures, in a woven build, the per-request allocation cost
// of a sampled request whose tainted SQL sink sits at an already-reported
// (deduplicated) location, versus the same request passing the tainted value as
// a bound argument (no tainted SQL text, so sql.Report stops at CollectString).
//
// fx-perf-memory-F1 independent reproducer (review only).
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{}, nil }

type fakeConn struct{}

func (fakeConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (fakeConn) Close() error                        { return nil }
func (fakeConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (fakeConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return emptyRows{}, nil
}

type emptyRows struct{}

func (emptyRows) Columns() []string         { return []string{"id"} }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

var (
	db        *sql.DB
	params    int
	committed int
)

func init() { sql.Register("dedupcost", fakeDriver{}) }

func countCommitted(span *tracer.Span) {
	if _, annotation, found := spans.ExistingForSpan(span); found {
		annotation.TryUseOpen(func(a *spans.Annotation) { committed += len(a.Event.Vulnerabilities) })
	}
}

func runQuery(ctx context.Context, query string, args ...any) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err == nil {
		_ = rows.Close()
	}
}

// handleVuln concatenates request parameters into SQL text at ONE call site.
func handleVuln(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request")
	defer span.Finish()
	q := r.URL.Query()
	clauses := make([]string, 0, params)
	for i := range params {
		name := "p" + strconv.Itoa(i)
		clauses = append(clauses, name+" = '"+q.Get(name)+"'")
	}
	runQuery(ctx, "SELECT * FROM users WHERE "+strings.Join(clauses, " AND "))
	countCommitted(span)
	w.WriteHeader(http.StatusNoContent)
}

// handleBound reads the same parameters but binds them as arguments.
func handleBound(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request")
	defer span.Finish()
	q := r.URL.Query()
	clauses := make([]string, 0, params)
	args := make([]any, 0, params)
	for i := range params {
		name := "p" + strconv.Itoa(i)
		clauses = append(clauses, name+" = ?")
		args = append(args, q.Get(name))
	}
	runQuery(ctx, "SELECT * FROM users WHERE "+strings.Join(clauses, " AND "), args...)
	countCommitted(span)
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	mode := flag.String("mode", "vuln", "vuln|bound")
	n := flag.Int("n", 500, "measured requests")
	warm := flag.Int("warm", 50, "warmup requests (first one reports)")
	flag.IntVar(&params, "params", 1, "request parameters concatenated/bound")
	memprofile := flag.String("memprofile", "", "write alloc profile of the measured window")
	flag.Parse()

	mt := mocktracer.Start()
	defer mt.Stop()
	var err error
	if db, err = sql.Open("dedupcost", ""); err != nil {
		panic(err)
	}
	handler := handleVuln
	if *mode == "bound" {
		handler = handleBound
	}
	values := url.Values{}
	for i := range params {
		values.Set("p"+strconv.Itoa(i), "value"+strconv.Itoa(i))
	}
	target := "/users?" + values.Encode()
	one := func() (uint64, uint64) {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		handler(rec, req)
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs
	}
	for range *warm {
		one()
	}
	warmCommitted := committed
	committed = 0
	mt.Reset()
	if *memprofile != "" {
		runtime.MemProfileRate = 1
	}
	execBefore := telemetry.ExecutedTainted.Load()
	var bytes, objs uint64
	for i := range *n {
		b, o := one()
		bytes += b
		objs += o
		if i%100 == 99 {
			mt.Reset()
		}
	}
	execDelta := telemetry.ExecutedTainted.Load() - execBefore
	if *memprofile != "" {
		runtime.GC()
		f, err := os.Create(*memprofile)
		if err != nil {
			panic(err)
		}
		if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
			panic(err)
		}
		_ = f.Close()
	}
	fmt.Printf("mode=%s params=%d n=%d warm_committed=%d measured_committed=%d executed_tainted=%d bytes_per_req=%d objs_per_req=%d\n",
		*mode, params, *n, warmCommitted, committed, execDelta, bytes/uint64(*n), objs/uint64(*n))
}
