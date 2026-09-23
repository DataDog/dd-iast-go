// Command fxrepro: independent woven reproducer for fx-sink-e2e-truepos-F1.
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

var db *sql.DB

func main() {
	mt := mocktracer.Start()
	sql.Register("fx", fxDriver{})
	db, _ = sql.Open("fx", "")
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		q := "SELECT id FROM users WHERE name = '" + user + "' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42"
		rows, err := db.QueryContext(r.Context(), q)
		if err == nil {
			rows.Close()
		}
		w.Header().Set("X-Case", r.URL.Query().Get("case"))
	})
	mux.HandleFunc("/note", func(w http.ResponseWriter, r *http.Request) {
		note := r.URL.Query().Get("note")
		q := "SELECT id FROM users ORDER BY name -- " + note
		rows, err := db.QueryContext(r.Context(), q)
		if err == nil {
			rows.Close()
		}
	})
	mux.HandleFunc("/sort", func(w http.ResponseWriter, r *http.Request) {
		col := r.URL.Query().Get("col")
		q := "SELECT id FROM users /* api_key=sk_live_CLEANCOMMENT */ ORDER BY " + col
		rows, err := db.QueryContext(r.Context(), q)
		if err == nil {
			rows.Close()
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	base := "http://" + ln.Addr().String()
	reqs := []string{
		"/login?case=benign&user=" + url.QueryEscape("alice"),
		"/login?case=dashdash&user=" + url.QueryEscape("admin' --"),
		"/note?note=" + url.QueryEscape("hunter2-customer-note"),
		"/sort?col=" + url.QueryEscape("name"),
	}
	for _, p := range reqs {
		resp, err := http.Get(base + p)
		if err != nil {
			panic(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	srv.Shutdown(context.Background())
	spans := mt.FinishedSpans()
	sort.Slice(spans, func(i, j int) bool { return spans[i].StartTime().Before(spans[j].StartTime()) })
	for _, s := range spans {
		tags := s.Tags()
		fmt.Printf("span name=%v resource=%v _dd.iast.enabled=%v\n", s.OperationName(), tags["resource.name"], tags["_dd.iast.enabled"])
		if j, ok := tags["_dd.iast.json"]; ok {
			fmt.Printf("  _dd.iast.json=%v\n", j)
		}
	}
	for _, q := range queries {
		fmt.Printf("driver received: %s\n", q)
	}
	mt.Stop()
	os.Exit(0)
}

var queries []string

type fxDriver struct{}

func (fxDriver) Open(string) (driver.Conn, error) { return fxConn{}, nil }

type fxConn struct{}

func (fxConn) Prepare(q string) (driver.Stmt, error) { return fxStmt{}, nil }
func (fxConn) Close() error                          { return nil }
func (fxConn) Begin() (driver.Tx, error)             { return nil, driver.ErrSkip }
func (fxConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	queries = append(queries, q)
	return fxRows{}, nil
}

type fxStmt struct{}

func (fxStmt) Close() error                               { return nil }
func (fxStmt) NumInput() int                              { return -1 }
func (fxStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(0), nil }
func (fxStmt) Query([]driver.Value) (driver.Rows, error)  { return fxRows{}, nil }

type fxRows struct{}

func (fxRows) Columns() []string         { return []string{"id"} }
func (fxRows) Close() error              { return nil }
func (fxRows) Next([]driver.Value) error { return io.EOF }
