// Command soak drives a woven HTTP application with a mixed request workload
// and samples heap/goroutine/IAST gauges after every batch (life-soak review).
package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	osexec "os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/dd-iast-go/internal/spans"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

var (
	db         *sql.DB
	lateWG     sync.WaitGroup
	taintedHit atomic.Uint64 // handler observed tainted value at sink
	panics     atomic.Uint64
	lateRuns   atomic.Uint64
)

const kinds = 16

func main() {
	total := flag.Int("n", 300000, "requests after warmup")
	warm := flag.Int("warm", 20000, "warmup requests")
	batch := flag.Int("batch", 10000, "sample interval")
	workers := flag.Int("workers", 16, "concurrent clients")
	realTracer := flag.Bool("real-tracer", false, "use tracer.Start instead of mocktracer")
	flag.Parse()
	if !built.WithOrchestrion {
		log.Fatal("not woven")
	}
	sql.Register("soak", soakDriver{})
	var err error
	if db, err = sql.Open("soak", ""); err != nil {
		log.Fatal(err)
	}
	var mock mocktracer.Tracer
	if *realTracer {
		tracer.Start(tracer.WithAgentAddr("127.0.0.1:1"), tracer.WithLogger(nopLogger{}), tracer.WithLogStartup(false))
		defer tracer.Stop()
	} else {
		mock = mocktracer.Start()
		defer mock.Stop()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sql", handleSQL)
	mux.HandleFunc("/cmd", handleCmd)
	mux.HandleFunc("/clean", handleClean)
	mux.HandleFunc("/panic", handlePanic)
	mux.HandleFunc("/early", handleEarly)
	mux.HandleFunc("/early-error", handleEarlyError)
	mux.HandleFunc("/json", handleJSON)
	mux.HandleFunc("/form", handleForm)
	mux.HandleFunc("/orphan", handleOrphan)
	mux.HandleFunc("/late", handleLate)
	mux.HandleFunc("/readall", handleReadAll)
	mux.HandleFunc("/big", handleBig)
	mux.HandleFunc("/nospan", handleNoSpan)
	mux.HandleFunc("/pv/{id}", handlePathValue)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: mux, ErrorLog: log.New(io.Discard, "", 0)}
	go server.Serve(ln)
	base := "http://" + ln.Addr().String()
	client := &http.Client{Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256, IdleConnTimeout: time.Hour}}

	baseGoroutines := runtime.NumGoroutine() + 1 // + drainer
	var next atomic.Int64
	var failures atomic.Uint64
	runBatch := func(n int) {
		start := next.Load()
		end := start + int64(n)
		var wg sync.WaitGroup
		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := next.Add(1) - 1
					if i >= end {
						return
					}
					if err := doRequest(client, base, i); err != nil {
						failures.Add(1)
					}
				}
			}()
		}
		wg.Wait()
		next.Store(end)
		lateWG.Wait()
	}

	fmt.Println("phase,requests,heap_alloc,heap_inuse,heap_objects,heap_sys,heap_released,stack_inuse,sys,goroutines,numgc,reports,iast_enabled_spans,tainted_hits,permits_used,live_slots,store_values,store_charged,acquire_drops,tombstones,overflow_free,annotations,event_source_bytes,owner_bindings,failures,probe_hits_of_200,elapsed_s")
	t0 := time.Now()
	var drainMu sync.Mutex
	var reports, enabled int
	drain := func() {
		if mock == nil {
			return
		}
		drainMu.Lock()
		defer drainMu.Unlock()
		finished := mock.FinishedSpans()
		for _, s := range finished {
			if v, _ := s.Tag(spans.SpanTagJson).(string); v != "" {
				reports++
			}
			if v, ok := s.Tag(spans.SpanTagEnabled).(float64); ok && v == 1 {
				enabled++
			}
		}
		mock.Reset() // spans finished between the two calls are dropped from the counts only
	}
	go func() { // keep the mock tracer from retaining a whole batch of spans
		for range time.Tick(200 * time.Millisecond) {
			drain()
		}
	}()
	var probeSeq atomic.Int64
	sample := func(phase string) {
		// Serial health probe: with no concurrency every sampled-in request
		// must get a permit, so ~sampling% of these must see tainted SQL.
		hitsBefore := taintedHit.Load()
		for j := 0; j < 200; j++ {
			doRequest(client, base, 1_000_000_000+probeSeq.Add(1)*kinds)
		}
		probeHits := taintedHit.Load() - hitsBefore
		drain()
		drainMu.Lock()
		gotReports, gotEnabled := reports, enabled
		reports, enabled = 0, 0
		drainMu.Unlock()
		client.CloseIdleConnections()
		// Let server connection goroutines observe the close (bounded).
		for deadline := time.Now().Add(3 * time.Second); runtime.NumGoroutine() > baseGoroutines && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		runtime.GC()
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		g := taintrequest.SoakStats()
		ann, esb, ob := spans.SoakStats()
		fmt.Printf("%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f\n",
			phase, next.Load(), ms.HeapAlloc, ms.HeapInuse, ms.HeapObjects, ms.HeapSys, ms.HeapReleased, ms.StackInuse, ms.Sys, runtime.NumGoroutine(), ms.NumGC,
			gotReports, gotEnabled, taintedHit.Swap(0)-probeHits, g.PermitsUsed, g.LiveSlots, g.ProcessValues, g.Charged, g.AcquireDrops,
			g.Tombstones, g.OverflowFree, ann, esb, ob, failures.Load(), probeHits, time.Since(t0).Seconds())
	}
	sample("start")
	for done := 0; done < *warm; done += *batch {
		runBatch(*batch)
		sample("warm")
	}
	for done := 0; done < *total; done += *batch {
		runBatch(*batch)
		sample("soak")
	}
	client.CloseIdleConnections()
	fmt.Printf("# panics=%d late=%d failures=%d\n", panics.Load(), lateRuns.Load(), failures.Load())
}

func doRequest(client *http.Client, base string, i int64) error {
	id := strconv.FormatInt(i, 10)
	var req *http.Request
	var err error
	switch i % kinds {
	case 0, 1:
		req, err = http.NewRequest(http.MethodGet, base+"/sql?"+url.Values{"column": {"id" + id}, "table": {"  customers_" + id + "  "}}.Encode(), nil)
	case 2:
		if i%64 != 2 { // os/exec forks are serialized by syscall.ForkLock; keep them rare
			req, err = http.NewRequest(http.MethodGet, base+"/sql?"+url.Values{"column": {"cm" + id}, "table": {"c" + id}}.Encode(), nil)
			break
		}
		req, err = http.NewRequest(http.MethodGet, base+"/cmd?path="+url.QueryEscape("no-such-bin-"+id), nil)
	case 3:
		req, err = http.NewRequest(http.MethodGet, base+"/clean?x="+id, nil)
	case 4:
		req, err = http.NewRequest(http.MethodPost, base+"/panic?q="+id+"&abort="+strconv.FormatBool(i%32 < 16), nil)
	case 5:
		req, err = http.NewRequest(http.MethodPost, base+"/early?q="+id, strings.NewReader(`{"ignored":"`+id+`"}`))
	case 6:
		req, err = http.NewRequest(http.MethodGet, base+"/early-error?q="+id, nil)
	case 7:
		req, err = http.NewRequest(http.MethodPost, base+"/json", strings.NewReader(`{"name":"n`+id+`","tags":["a`+id+`","b"]}`))
	case 8:
		req, err = http.NewRequest(http.MethodPost, base+"/form?extra="+id, strings.NewReader("user=u"+id+"&role=admin"))
		if req != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: "session", Value: "c" + id})
		}
	case 9:
		req, err = http.NewRequest(http.MethodGet, base+"/orphan?q=o"+id, nil)
	case 10:
		req, err = http.NewRequest(http.MethodGet, base+"/late?q=l"+id, nil)
	case 11:
		req, err = http.NewRequest(http.MethodPost, base+"/readall", strings.NewReader("body-"+id+"-payload"))
	case 12:
		req, err = http.NewRequest(http.MethodGet, base+"/big", nil)
		if req != nil {
			req.Header.Set("X-Big", strings.Repeat("v"+id, 8192/len(id)))
		}
	case 13:
		req, err = http.NewRequest(http.MethodGet, base+"/nospan?q="+id, nil)
	case 14:
		req, err = http.NewRequest(http.MethodGet, base+"/pv/p"+id, nil)
	case 15:
		req, err = http.NewRequest(http.MethodGet, base+"/sql?"+url.Values{"column": {"zz" + id}, "table": {"t" + id}}.Encode(), nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("X-Request-Id", "rid-"+id)
	resp, err := client.Do(req)
	if err != nil {
		if i%kinds == 4 { // panics close the connection
			return nil
		}
		return err
	}
	io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func hit(v string) {
	if taint.IsTaintedString(v) {
		taintedHit.Add(1)
	}
}

func runSQL(ctx context.Context, query string) {
	hit(query)
	stmt, err := db.PrepareContext(ctx, query)
	if err == nil {
		stmt.ExecContext(ctx)
		stmt.Close()
	}
	if rows, err := db.QueryContext(ctx, query); err == nil {
		rows.Close()
	}
}

func handleSQL(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.sql")
	defer span.Finish()
	values := r.URL.Query()
	column := values.Get("column")[:2]
	table := strings.TrimSpace(values.Get("table"))
	joined := strings.Join([]string{"SELECT ", column, " FROM ", table}, "")
	query := fmt.Sprintf("%s WHERE id = '%s'", joined, values.Get("column"))
	runSQL(ctx, query)
	w.WriteHeader(http.StatusNoContent)
}

func handleCmd(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.cmd")
	defer span.Finish()
	path := "/nonexistent-dd-iast/" + strings.TrimSpace(r.URL.Query().Get("path"))
	hit(path)
	_ = osexec.CommandContext(ctx, path, "--flag").Run()
	w.WriteHeader(http.StatusNoContent)
}

func handleClean(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.clean")
	defer span.Finish()
	runSQL(ctx, "SELECT 1 FROM clean")
	w.Write([]byte("ok"))
}

func handlePanic(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.panic")
	defer span.Finish()
	q := r.URL.Query().Get("q")
	runSQL(ctx, "DELETE FROM t WHERE q = '"+q+"'")
	panics.Add(1)
	if r.URL.Query().Get("abort") == "true" {
		panic(http.ErrAbortHandler)
	}
	panic("soak panic " + q)
}

func handleEarly(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		return // never reads body, never starts a span
	}
	w.WriteHeader(http.StatusOK)
}

func handleEarlyError(w http.ResponseWriter, r *http.Request) {
	span, _ := tracer.StartSpanFromContext(r.Context(), "soak.early")
	defer span.Finish()
	if r.Header.Get("X-Request-Id") != "" {
		http.Error(w, "nope", http.StatusForbidden)
		return
	}
}

func handleJSON(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.json")
	defer span.Finish()
	var body struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	runSQL(ctx, "SELECT * FROM users WHERE name = '"+body.Name+"' AND tag = '"+body.Tags[0]+"'")
	w.WriteHeader(http.StatusNoContent)
}

func handleForm(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.form")
	defer span.Finish()
	if err := r.ParseForm(); err != nil {
		return
	}
	var b strings.Builder
	b.WriteString("UPDATE users SET role = '")
	b.WriteString(r.FormValue("role"))
	b.WriteString("' WHERE user = '")
	b.WriteString(r.PostFormValue("user"))
	b.WriteString("'")
	var buf bytes.Buffer
	if c, err := r.Cookie("session"); err == nil {
		buf.WriteString(c.Value)
	}
	buf.WriteString(r.Header.Get("X-Request-Id"))
	q := b.String() + " -- " + strings.ToUpper(buf.String())
	runSQL(ctx, q)
	w.WriteHeader(http.StatusNoContent)
}

func handleOrphan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	runSQL(r.Context(), "SELECT * FROM orphan WHERE q = '"+q+"'")
	w.WriteHeader(http.StatusNoContent)
}

func handleLate(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.late")
	defer span.Finish()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	lateWG.Add(1)
	go func() {
		defer lateWG.Done()
		time.Sleep(2 * time.Millisecond) // outlive the request on purpose
		lateRuns.Add(1)
		runSQL(ctx, "SELECT * FROM late WHERE q = '"+q+"'")
		_ = strings.ToLower(q + "-after")
	}()
	w.WriteHeader(http.StatusAccepted)
}

func handleReadAll(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.readall")
	defer span.Finish()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	s := string(b)
	runSQL(ctx, "INSERT INTO t VALUES ('"+strings.ReplaceAll(s, "-", "_")+"')")
	w.WriteHeader(http.StatusNoContent)
}

func handleBig(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.big")
	defer span.Finish()
	v := r.Header.Get("X-Big")
	runSQL(ctx, "SELECT '"+strings.Repeat(v[:16], 4)+"' "+v)
	w.WriteHeader(http.StatusNoContent)
}

func handleNoSpan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	_ = strings.ToUpper(q) + "x"
	w.Write([]byte(q))
}

func handlePathValue(w http.ResponseWriter, r *http.Request) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "soak.pv")
		defer span.Finish()
		runSQL(ctx, "SELECT * FROM p WHERE id = '"+r.PathValue("id")+"'")
		w.WriteHeader(http.StatusNoContent)
	})
	inner.ServeHTTP(w, r)
}

type nopLogger struct{}

func (nopLogger) Log(string) {}

type soakDriver struct{}

func (soakDriver) Open(string) (driver.Conn, error) { return soakConn{}, nil }

type soakConn struct{}

func (soakConn) Prepare(string) (driver.Stmt, error)                         { return soakStmt{}, nil }
func (soakConn) PrepareContext(context.Context, string) (driver.Stmt, error) { return soakStmt{}, nil }
func (soakConn) Close() error                                                { return nil }
func (soakConn) Begin() (driver.Tx, error)                                   { return nil, errors.New("no tx") }

type soakStmt struct{}

func (soakStmt) Close() error                               { return nil }
func (soakStmt) NumInput() int                              { return -1 }
func (soakStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (soakStmt) Query([]driver.Value) (driver.Rows, error)  { return soakRows{}, nil }

type soakRows struct{}

func (soakRows) Columns() []string         { return []string{"v"} }
func (soakRows) Close() error              { return nil }
func (soakRows) Next([]driver.Value) error { return io.EOF }
