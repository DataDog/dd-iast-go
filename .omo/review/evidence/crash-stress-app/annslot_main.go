// Command annslot reproduces an analyzed request losing its SQL injection
// report because non-analyzed requests' root spans fill the span-annotation
// map, which shares the MaxConcurrentRequests cap with analysis permits.
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"

	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

type drv struct{}
type conn struct{}
type stmt struct{}

func (drv) Open(string) (driver.Conn, error)            { return conn{}, nil }
func (conn) Prepare(string) (driver.Stmt, error)        { return stmt{}, nil }
func (conn) Close() error                               { return nil }
func (conn) Begin() (driver.Tx, error)                  { return nil, fmt.Errorf("no tx") }
func (stmt) Close() error                               { return nil }
func (stmt) NumInput() int                              { return -1 }
func (stmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (stmt) Query([]driver.Value) (driver.Rows, error)  { return nil, fmt.Errorf("no rows") }
func (conn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

var (
	db      *sql.DB
	mu      sync.Mutex
	entered = map[string]chan string{}
	release = map[string]chan struct{}{}
)

func handler(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	ctx := r.Context()
	if r.URL.Query().Get("span") == "1" {
		span, sctx := tracer.StartSpanFromContext(ctx, "req")
		span.SetTag("role", role)
		defer span.Finish()
		ctx = sctx
	}
	status := fmt.Sprintf("active=%v", taintrequest.FromContext(ctx).Active())
	if role == "victim" {
		q := r.URL.Query().Get("q")
		status += fmt.Sprintf(" queryTainted=%v", taint.IsTaintedString(q))
		_, _ = db.ExecContext(ctx, q)
	}
	mu.Lock()
	in, rel := entered[role], release[role]
	mu.Unlock()
	if in != nil {
		in <- status
		<-rel
	}
	io.WriteString(w, status)
}

type holder struct {
	role string
	done chan struct{}
}

func hold(base, role string, span bool) (holder, string) {
	mu.Lock()
	entered[role] = make(chan string, 1)
	release[role] = make(chan struct{})
	in := entered[role]
	mu.Unlock()
	h := holder{role: role, done: make(chan struct{})}
	s := "0"
	if span {
		s = "1"
	}
	go func() {
		defer close(h.done)
		resp, err := http.Get(base + "/?role=" + role + "&span=" + s)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	return h, <-in
}

func (h holder) finish() {
	mu.Lock()
	close(release[h.role])
	mu.Unlock()
	<-h.done
}

func scenario(withDroppedSpan bool) {
	mt := mocktracer.Start()
	defer mt.Stop()
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	d1, s1 := hold(srv.URL, "hold1", true) // analyzed, root span -> annotation slot 1
	fmt.Printf("  hold1 (span):    %s\n", s1)
	d2, s2 := hold(srv.URL, "hold2", false) // analyzed, no span -> takes permit 2 only
	fmt.Printf("  hold2 (no span): %s\n", s2)
	var d3 holder
	if withDroppedSpan {
		var s3 string
		d3, s3 = hold(srv.URL, "hold3", true) // capacity-dropped, root span -> annotation slot 2
		fmt.Printf("  hold3 (span):    %s\n", s3)
	}
	d2.finish() // frees permit 2
	resp, err := http.Get(srv.URL + "/?role=victim&span=1&q=" + url.QueryEscape("SELECT * FROM users WHERE name = 'x' OR 1=1 --'"))
	if err != nil {
		fmt.Println("victim error:", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("  victim (span):   %s\n", body)
	d1.finish()
	if withDroppedSpan {
		d3.finish()
	}
	reported := false
	for _, s := range mt.FinishedSpans() {
		if s.Tag("role") == "victim" || s.OperationName() == "vulnerability" {
			js, _ := s.Tag("_dd.iast.json").(string)
			fmt.Printf("  span %-13q role=%v _dd.iast.enabled=%v iastJSONBytes=%d\n", s.OperationName(), s.Tag("role"), s.Tag("_dd.iast.enabled"), len(js))
			if len(js) > 0 {
				reported = true
			}
		}
	}
	fmt.Printf("  => victim SQL injection reported: %v\n", reported)
}

func main() {
	fmt.Printf("woven=%v DD_IAST_REQUEST_SAMPLING=%s DD_IAST_MAX_CONCURRENT_REQUESTS=%q (default 2)\n",
		built.WithOrchestrion, os.Getenv("DD_IAST_REQUEST_SAMPLING"), os.Getenv("DD_IAST_MAX_CONCURRENT_REQUESTS"))
	sql.Register("annslot", drv{})
	db, _ = sql.Open("annslot", "")
	fmt.Println("CONTROL: no capacity-dropped request holds a root span")
	scenario(false)
	fmt.Println("BUG: one capacity-dropped request holds a root span")
	scenario(true)
}
