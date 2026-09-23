// Command hostile is a woven HTTP app used to attack IAST with hostile inputs.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

var (
	db       *sql.DB
	mock     mocktracer.Tracer
	sinks    atomic.Int64
	tainted  atomic.Int64
	observed atomic.Int64
)

func sinkSQL(ctx context.Context, q string) {
	sinks.Add(1)
	if taint.IsTaintedString(q) {
		tainted.Add(1)
	}
	_, _ = db.ExecContext(ctx, q)
}

func sinkCmd(ctx context.Context, arg string) {
	sinks.Add(1)
	if taint.IsTaintedString(arg) {
		tainted.Add(1)
	}
	_ = exec.CommandContext(ctx, "/nonexistent-dd-iast-hostile", arg).Run()
}

func head(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func withSpan(h func(context.Context, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "hostile.request")
		defer span.Finish()
		h(ctx, r.WithContext(ctx))
		observed.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}
}

func headers(ctx context.Context, r *http.Request) {
	n := 0
	for name, values := range r.Header {
		for _, v := range values {
			if n < 80 {
				sinkSQL(ctx, "SELECT * FROM t WHERE h = '"+head(v, 200)+"' AND n = "+name)
				sinkSQL(ctx, "SELECT "+v)
				n++
			}
		}
	}
	sinkSQL(ctx, "SELECT '"+r.Header.Get("X-Big")+"'")
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+r.Header.Get("Authorization"))
	sinkCmd(ctx, r.Header.Get("X-Cmd"))
	sinkSQL(ctx, "SELECT "+r.URL.RawQuery+" FROM "+r.URL.Path+" -- "+r.RequestURI)
}

func query(ctx context.Context, r *http.Request) {
	values := r.URL.Query()
	n := 0
	for k, vs := range values {
		for _, v := range vs {
			if n < 100 {
				sinkSQL(ctx, "SELECT * FROM t WHERE "+k+" = '"+v+"'")
				n++
			}
		}
	}
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+r.URL.Query().Get("a"))
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+r.FormValue("a"))
	sinkCmd(ctx, r.FormValue("cmd"))
	sinkSQL(ctx, "SELECT "+r.URL.RawQuery)
}

func form(ctx context.Context, r *http.Request) {
	_ = r.ParseForm()
	n := 0
	for k, vs := range r.Form {
		for _, v := range vs {
			if n < 100 {
				sinkSQL(ctx, "SELECT * FROM t WHERE "+k+" = '"+v+"'")
				n++
			}
		}
	}
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+r.PostFormValue("a"))
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+r.FormValue("a"))
}

func multipartH(ctx context.Context, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		log.Printf("multipart error: %v", err)
	}
	if r.MultipartForm != nil {
		n := 0
		for k, vs := range r.MultipartForm.Value {
			for _, v := range vs {
				if n < 100 {
					sinkSQL(ctx, "SELECT * FROM t WHERE "+k+" = '"+v+"'")
					n++
				}
			}
		}
		n = 0
		for k, fhs := range r.MultipartForm.File {
			for _, fh := range fhs {
				if n < 50 {
					sinkSQL(ctx, "SELECT '"+fh.Filename+"' AS "+k)
					sinkCmd(ctx, fh.Filename)
					n++
				}
			}
		}
		_ = r.MultipartForm.RemoveAll()
	}
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+r.FormValue("a"))
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+r.PostFormValue("a"))
}

func readAll(ctx context.Context, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("readall error: %v", err)
	}
	s := string(body)
	sinkSQL(ctx, "SELECT '"+head(s, 100)+"'")
	sinkSQL(ctx, s)
	sinkSQL(ctx, strings.ToUpper(head(s, 4096)))
	sinkCmd(ctx, head(s, 1000))
}

type jsonDoc struct {
	A string            `json:"a"`
	B []string          `json:"b"`
	C map[string]string `json:"c"`
	D any               `json:"d"`
	N json.RawMessage   `json:"n"`
}

func jsonDecode(ctx context.Context, r *http.Request) {
	var doc jsonDoc
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		log.Printf("json decode error: %v", err)
	}
	jsonSinks(ctx, &doc)
}

func jsonUnmarshal(ctx context.Context, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var doc jsonDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		log.Printf("json unmarshal error: %v", err)
	}
	jsonSinks(ctx, &doc)
	var anything any
	_ = json.Unmarshal(body, &anything)
}

func jsonSinks(ctx context.Context, doc *jsonDoc) {
	sinkSQL(ctx, "SELECT * FROM t ORDER BY "+doc.A)
	for i, b := range doc.B {
		if i < 50 {
			sinkSQL(ctx, "SELECT '"+b+"'")
		}
	}
	i := 0
	for k, v := range doc.C {
		if i < 50 {
			sinkSQL(ctx, "SELECT "+k+" FROM "+v)
		}
		i++
	}
}

func cookies(ctx context.Context, r *http.Request) {
	for i, c := range r.Cookies() {
		if i < 100 {
			sinkSQL(ctx, "SELECT * FROM t WHERE "+c.Name+" = '"+c.Value+"'")
			sinkSQL(ctx, "SELECT * FROM t ORDER BY "+c.Value)
		}
	}
	if c, err := r.Cookie("a"); err == nil {
		sinkCmd(ctx, c.Value)
	}
	for _, c := range r.CookiesNamed("a") {
		sinkSQL(ctx, "SELECT "+c.Value)
	}
}

func propagate(ctx context.Context, r *http.Request) {
	q := r.URL.Query().Get("a")
	if q == "" {
		q = r.Header.Get("X-A")
	}
	sinkSQL(ctx, "SELECT "+strings.ToUpper(q))
	sinkSQL(ctx, "SELECT "+strings.ToLower(q))
	sinkSQL(ctx, "SELECT "+strings.ReplaceAll(q, "a", "bbbb"))
	sinkSQL(ctx, "SELECT "+strings.Replace(q, "\xff", "\u00e9", -1))
	sinkSQL(ctx, "SELECT "+strings.ToValidUTF8(q, "?"))
	sinkSQL(ctx, "SELECT "+strings.Repeat(q, 64))
	for i, part := range strings.Split(q, ",") {
		if i < 100 {
			sinkSQL(ctx, "SELECT "+part)
		}
	}
	for i, part := range strings.Fields(q) {
		if i < 100 {
			sinkSQL(ctx, "SELECT "+part)
		}
	}
	sinkSQL(ctx, "SELECT "+strings.Join(strings.Split(q, "&"), "|"))
	sinkSQL(ctx, fmt.Sprintf("SELECT %s %q %v %x", q, q, q, q))
	sinkSQL(ctx, "SELECT "+strconv.Quote(q))
	sinkSQL(ctx, "SELECT "+strconv.QuoteToASCII(q))
	if u, err := strconv.Unquote(q); err == nil {
		sinkSQL(ctx, "SELECT "+u)
	}
	if u, err := url.QueryUnescape(q); err == nil {
		sinkSQL(ctx, "SELECT "+u)
	}
	if u, err := url.PathUnescape(q); err == nil {
		sinkSQL(ctx, "SELECT "+u)
	}
	sinkSQL(ctx, "SELECT "+url.QueryEscape(q))
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		b.WriteString(q)
		b.WriteString("\xfe")
	}
	sinkSQL(ctx, "SELECT "+b.String())
	var buf bytes.Buffer
	for i := 0; i < 2000; i++ {
		buf.WriteString(q)
		buf.Write([]byte(q))
	}
	sinkSQL(ctx, "SELECT "+buf.String())
	bs := []byte(q)
	sinkSQL(ctx, "SELECT "+string(bytes.ToUpper(bs)))
	if len(q) > 3 {
		sinkSQL(ctx, "SELECT "+q[1:len(q)-1])
		sinkSQL(ctx, "SELECT "+q[len(q)/2:])
	}
	s := q + q + q + q + q + q + q + q + q + q + q + q + q + q + q + q
	sinkSQL(ctx, "SELECT "+s)
	sinkSQL(ctx, "SELECT "+strings.TrimSpace(q)+strings.Title(q)+strings.TrimLeft(q, "\xff"))
	sinkSQL(ctx, "SELECT "+strings.Map(func(r rune) rune { return r + 1 }, q))
	sinkCmd(ctx, q)
}

func exploit(ctx context.Context, r *http.Request) {
	param := r.URL.Query().Get("param")
	sinkSQL(ctx, "SELECT * FROM Users WHERE email = '"+param+"' AND password = '81dc9bdb52d04dc20036dbd8313ed055' AND deletedAt IS NULL")
	sinkSQL(ctx, "SELECT * FROM Users WHERE id = "+param+" /* token='tok_live_SECRETBLOCK' */")
}

func stats(w http.ResponseWriter, r *http.Request) {
	runtime.GC()
	debug.FreeOSMemory()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"heap_alloc": ms.HeapAlloc, "heap_inuse": ms.HeapInuse, "heap_objects": ms.HeapObjects,
		"sys": ms.Sys, "total_alloc": ms.TotalAlloc, "maxrss": ru.Maxrss, "goroutines": runtime.NumGoroutine(),
		"sinks": sinks.Load(), "tainted_sinks": tainted.Load(), "observed": observed.Load(),
	})
}

func dumpSpans(w http.ResponseWriter, r *http.Request) {
	var out []map[string]any
	for _, s := range mock.FinishedSpans() {
		out = append(out, map[string]any{
			"name": s.OperationName(), "enabled": s.Tag(spans.SpanTagEnabled), "json": s.Tag(spans.SpanTagJson),
		})
	}
	mock.Reset()
	_ = json.NewEncoder(w).Encode(out)
}

func main() {
	mock = mocktracer.Start()
	defer mock.Stop()
	sql.Register("hostile", testDriver{})
	var err error
	db, err = sql.Open("hostile", "")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/h", withSpan(headers))
	mux.Handle("/q", withSpan(query))
	mux.Handle("/form", withSpan(form))
	mux.Handle("/mp", withSpan(multipartH))
	mux.Handle("/readall", withSpan(readAll))
	mux.Handle("/json", withSpan(jsonDecode))
	mux.Handle("/jsonu", withSpan(jsonUnmarshal))
	mux.Handle("/cookie", withSpan(cookies))
	mux.Handle("/prop", withSpan(propagate))
	mux.Handle("/exploit", withSpan(exploit))
	mux.HandleFunc("/stats", stats)
	mux.HandleFunc("/spans", dumpSpans)
	addr := os.Getenv("HOSTILE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18089"
	}
	server := &http.Server{Addr: addr, Handler: mux, ErrorLog: log.New(os.Stderr, "http-server: ", log.LstdFlags)}
	log.Printf("listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

type testDriver struct{}

func (testDriver) Open(string) (driver.Conn, error) { return testConn{}, nil }

type testConn struct{}

func (testConn) Prepare(string) (driver.Stmt, error)                         { return testStmt{}, nil }
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

type testTx struct{}

func (testTx) Commit() error   { return nil }
func (testTx) Rollback() error { return nil }

type testRows struct{}

func (testRows) Columns() []string         { return []string{"value"} }
func (testRows) Close() error              { return nil }
func (testRows) Next([]driver.Value) error { return io.EOF }
