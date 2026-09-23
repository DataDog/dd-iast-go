// Command annrepro independently reproduces crash-stress-app-F1 through a
// realistic surface: a woven net/http server wrapped by dd-trace-go's
// contrib/net/http (every request gets an "http.request" root span), default
// IAST configuration (30% sampling, 2 concurrent analyses), and a tainted query
// parameter flowing into database/sql.
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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	ddhttp "github.com/DataDog/dd-trace-go/contrib/net/http/v2"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"

	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

type drv struct{}
type conn struct{}

func (drv) Open(string) (driver.Conn, error)     { return conn{}, nil }
func (conn) Prepare(string) (driver.Stmt, error) { return nil, fmt.Errorf("unused") }
func (conn) Close() error                        { return nil }
func (conn) Begin() (driver.Tx, error)           { return nil, fmt.Errorf("no tx") }
func (conn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

var (
	db     *sql.DB
	holdMu sync.Mutex
	holds  = map[string]chan struct{}{}
	status = map[string]chan bool{}
	sleep  atomic.Int64 // ns a /slow request sleeps when not held
)

// slowHandler models an ordinary slow endpoint (no sink).
func slowHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	active := taintrequest.FromContext(r.Context()).Active()
	holdMu.Lock()
	st, rel := status[id], holds[id]
	holdMu.Unlock()
	if st != nil {
		st <- active
		<-rel
	} else if d := sleep.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	io.WriteString(w, "ok")
}

// vulnHandler has a SQL injection: tainted query parameter -> db.ExecContext.
func vulnHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if sp, ok := tracer.SpanFromContext(ctx); ok {
		sp.SetTag("victim_id", r.URL.Query().Get("id"))
	}
	q := r.URL.Query().Get("q")
	active := taintrequest.FromContext(ctx).Active()
	_, _ = db.ExecContext(ctx, q)
	fmt.Fprintf(w, "%v %v", active, taint.IsTaintedString(q))
}

type result struct{ active, tainted bool }

func victim(base string, id int) result {
	resp, err := http.Get(base + "/vuln?id=" + strconv.Itoa(id) + "&q=" + url.QueryEscape("SELECT 1 FROM t WHERE n = 'x' OR 1=1 --"))
	if err != nil {
		panic(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var r result
	fmt.Sscanf(string(b), "%t %t", &r.active, &r.tainted)
	return r
}

type heldReq struct{ id string; done chan struct{} }

func startHeld(base, id string) (heldReq, bool) {
	holdMu.Lock()
	status[id] = make(chan bool, 1)
	holds[id] = make(chan struct{})
	st := status[id]
	holdMu.Unlock()
	h := heldReq{id: id, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		if resp, err := http.Get(base + "/slow?id=" + id); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	return h, <-st
}

func (h heldReq) release() {
	holdMu.Lock()
	close(holds[h.id])
	delete(holds, h.id)
	delete(status, h.id)
	holdMu.Unlock()
	<-h.done
}

// reports maps victim_id -> (enabled tag, has IAST payload) from root spans,
// and counts orphan "vulnerability" spans with/without payload.
func reports(mt mocktracer.Tracer) (map[string][2]string, int, int) {
	out := map[string][2]string{}
	orphanEmpty, orphanFull := 0, 0
	for _, s := range mt.FinishedSpans() {
		js, _ := s.Tag("_dd.iast.json").(string)
		if s.OperationName() == "vulnerability" {
			if js == "" {
				orphanEmpty++
			} else {
				orphanFull++
			}
			continue
		}
		if id, ok := s.Tag("victim_id").(string); ok {
			out[id] = [2]string{fmt.Sprint(s.Tag("_dd.iast.enabled")), strconv.FormatBool(js != "")}
		}
	}
	return out, orphanEmpty, orphanFull
}

func main() {
	fmt.Printf("woven=%v DD_IAST_REQUEST_SAMPLING=%q DD_IAST_MAX_CONCURRENT_REQUESTS=%q DD_IAST_DEDUPLICATION_ENABLED=%q (empty = default: 30%%, 2, true)\n",
		built.WithOrchestrion, os.Getenv("DD_IAST_REQUEST_SAMPLING"), os.Getenv("DD_IAST_MAX_CONCURRENT_REQUESTS"), os.Getenv("DD_IAST_DEDUPLICATION_ENABLED"))
	sql.Register("annrepro", drv{})
	db, _ = sql.Open("annrepro", "")

	mt := mocktracer.Start()
	defer mt.Stop()
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", slowHandler)
	mux.HandleFunc("/vuln", vulnHandler)
	srv := httptest.NewServer(ddhttp.WrapHandler(mux, "annrepro", "req"))
	defer srv.Close()

	mode := "deterministic"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "deterministic":
		// Phase BUG: hold two in-flight slow requests that IAST did NOT analyze
		// (sampled out). They hold no analysis permit, only annotation slots.
		var held []heldReq
		tries := 0
		for len(held) < 2 {
			tries++
			h, active := startHeld(srv.URL, "s"+strconv.Itoa(tries))
			if active {
				h.release() // analyzed: give its permit back, keep looking
				continue
			}
			held = append(held, h)
		}
		fmt.Printf("BUG phase: holding 2 in-flight NON-analyzed requests (found after %d slow requests); 0 analysis permits in use\n", tries)
		act, id := 0, 0
		for act < 10 {
			id++
			if r := victim(srv.URL, id); r.active && r.tainted {
				act++
			}
		}
		rep, oe, of := reports(mt)
		reported := 0
		for _, v := range rep {
			if v[1] == "true" {
				reported++
			}
		}
		fmt.Printf("  victims sent=%d analyzed(active && query tainted)=%d reported=%d\n", id, act, reported)
		cnt := map[[2]string]int{}
		for _, v := range rep {
			cnt[v]++
		}
		fmt.Printf("  victim root spans by (_dd.iast.enabled, hasPayload): %v\n", cnt)
		fmt.Printf("  orphan \"vulnerability\" spans: empty=%d withPayload=%d\n", oe, of)
		for _, h := range held {
			h.release()
		}
		// Phase RECOVERY: same sink call site, nothing held. Dropped reports never
		// reached dedup, so this report proves dedup is not what hid them.
		mt.Reset()
		for {
			id++
			if r := victim(srv.URL, id); r.active && r.tainted {
				break
			}
		}
		rep, oe, of = reports(mt)
		fmt.Printf("RECOVERY phase (holders released, same sink site): analyzed victim id=%d -> %v (enabled, hasPayload); orphan empty=%d withPayload=%d\n",
			id, rep[strconv.Itoa(id)], oe, of)
	case "load":
		// Realistic load: C background clients hitting a 50ms endpoint, plus
		// sequential victims. Compare active victims' report rate.
		conc, _ := strconv.Atoi(os.Getenv("LOAD_CLIENTS"))
		sleep.Store(int64(50 * time.Millisecond))
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if resp, err := http.Get(srv.URL + "/slow"); err == nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
				}
			}()
		}
		time.Sleep(200 * time.Millisecond)
		act := 0
		activeIDs := map[string]bool{}
		for id := 1; id <= 300; id++ {
			if r := victim(srv.URL, id); r.active && r.tainted {
				act++
				activeIDs[strconv.Itoa(id)] = true
			}
		}
		close(stop)
		wg.Wait()
		rep, oe, of := reports(mt)
		reported, enabled0 := 0, 0
		for id := range activeIDs {
			if rep[id][1] == "true" {
				reported++
			}
			if rep[id][0] == "0" {
				enabled0++
			}
		}
		fmt.Printf("LOAD clients=%d: victims=300 analyzed=%d reported=%d analyzedButEnabled0=%d orphanEmpty=%d orphanWithPayload=%d\n",
			conc, act, reported, enabled0, oe, of)
	}
}
