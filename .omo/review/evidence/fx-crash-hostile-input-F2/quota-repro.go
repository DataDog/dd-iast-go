// Command quota-repro drives the woven HTTP-to-SQL reporting path.
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
	"strings"
	"time"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

type quotaDriver struct{}

func (quotaDriver) Open(string) (driver.Conn, error) {
	return quotaConn{}, nil
}

type quotaConn struct{}

func (quotaConn) Begin() (driver.Tx, error) {
	return nil, driver.ErrSkip
}

func (quotaConn) Close() error {
	return nil
}

func (quotaConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (quotaConn) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}

type result struct {
	elapsed         time.Duration
	executedTainted uint64
	vulnerabilities int
}

func init() {
	sql.Register("quota-repro", quotaDriver{})
}

func main() {
	operations := flag.Int("operations", 40, "tainted SQL sinks in one request")
	payloadBytes := flag.Int("payload-bytes", 30_000, "query parameter size")
	flag.Parse()

	if *operations < 2 {
		panic("operations must be at least 2")
	}

	tracer.Start(tracer.WithService("quota-repro"))
	defer tracer.Stop()

	db, err := sql.Open("quota-repro", "")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	results := make(chan result, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		span, ctx := tracer.StartSpanFromContext(request.Context(), "quota-repro.request")
		defer span.Finish()

		value := request.FormValue("q")
		started := time.Now()

		if _, err := db.ExecContext(ctx, "SELECT '"+value+"'"); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := db.ExecContext(ctx, "SELECT '"+value+"'"); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		for range *operations - 2 {
			if _, err := db.ExecContext(ctx, "SELECT '"+value+"'"); err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		run := result{
			elapsed:         time.Since(started),
			executedTainted: telemetry.ExecutedTainted.Load(),
		}
		if _, annotation, found := spans.ExistingForSpan(span); found {
			annotation.TryUseOpen(func(annotation *spans.Annotation) {
				run.vulnerabilities = len(annotation.Event.Vulnerabilities)
			})
		}
		results <- run
		_, _ = fmt.Fprintln(writer, "ok")
	}))
	defer server.Close()

	response, err := http.Get(server.URL + "/?q=" + url.QueryEscape(strings.Repeat("a", *payloadBytes)))
	if err != nil {
		panic(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		panic(response.Status)
	}

	run := <-results
	fmt.Printf(
		"operations=%d payload_bytes=%d executed_tainted=%d recorded_vulnerabilities=%d handler_elapsed=%s\n",
		*operations,
		*payloadBytes,
		run.executedTainted,
		run.vulnerabilities,
		run.elapsed,
	)
}
