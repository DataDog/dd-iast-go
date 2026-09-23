// Command stress drives a woven HTTP server with highly concurrent tainted
// traffic that reaches SQL and command sinks, looking for panics, deadlocks,
// leaks, permit leaks and cross-request taint bleed.
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
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

var (
	flagDuration = flag.Duration("duration", 5*time.Minute, "stress duration")
	flagClients  = flag.Int("clients", 256, "concurrent clients")
	flagAgent    = flag.String("agent", "127.0.0.1:18126", "fake agent listen address")
	flagDumpDir  = flag.String("dumpdir", ".", "goroutine dump directory")
	flagStall    = flag.Duration("stall", 10*time.Second, "stall threshold")
)

// ---- fake SQL driver ----

type fakeDriver struct{}
type fakeConn struct{}
type fakeStmt struct{}
type fakeRows struct{ n int }

var sqlCalls atomic.Int64

func (fakeDriver) Open(string) (driver.Conn, error)  { return fakeConn{}, nil }
func (fakeConn) Prepare(string) (driver.Stmt, error) { return fakeStmt{}, nil }
func (fakeConn) Close() error                        { return nil }
func (fakeConn) Begin() (driver.Tx, error)           { return fakeTx{}, nil }
func (fakeStmt) Close() error                        { return nil }
func (fakeStmt) NumInput() int                       { return -1 }
func (fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	sqlCalls.Add(1)
	return driver.RowsAffected(1), nil
}
func (fakeStmt) Query([]driver.Value) (driver.Rows, error) { sqlCalls.Add(1); return &fakeRows{}, nil }
func (*fakeRows) Columns() []string                        { return []string{"v"} }
func (*fakeRows) Close() error                             { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.n > 0 {
		return io.EOF
	}
	r.n++
	dest[0] = "row"
	return nil
}
func (fakeConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	sqlCalls.Add(1)
	return driver.RowsAffected(1), nil
}
func (fakeConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	sqlCalls.Add(1)
	return &fakeRows{}, nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

var db *sql.DB

// ---- counters ----

var (
	completed, errorsCount, cancelled, analyzed, sinkTainted, sinkUntaintedActive atomic.Int64
	falseTaint, bleed, bleedChecks, poolBleed, lateOutstanding, lateDone          atomic.Int64
	execCalls, handlerPanicsIntended, stalls                                      atomic.Int64
	agentBytes, agentSQL, agentCMD, agentPayloads                                 atomic.Int64
	violationsMu                                                                  sync.Mutex
	violations                                                                    []string
)

func violation(format string, args ...any) {
	violationsMu.Lock()
	if len(violations) < 50 {
		violations = append(violations, fmt.Sprintf(format, args...))
	}
	violationsMu.Unlock()
}

// done[id%len] == id marks a request whose response was fully received, which
// happens only after serverHandler.ServeHTTP (and its deferred Finish) returned.
var done [1 << 20]atomic.Uint64

type sharedEntry struct {
	value string
	id    uint64
}

var ring [4096]atomic.Pointer[sharedEntry]

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

var execSem = make(chan struct{}, 8)

func active(ctx context.Context) bool {
	return taintrequest.FromContext(ctx).Active()
}

type flowKey struct{}

func checkSink(ctx context.Context, value string) {
	if active(ctx) {
		fi, _ := ctx.Value(flowKey{}).(int)
		if taint.IsTaintedString(value) {
			sinkTainted.Add(1)
			flowStats[fi].sinkT.Add(1)
		} else {
			sinkUntaintedActive.Add(1)
			flowStats[fi].sinkU.Add(1)
		}
	}
}

func cleanCheck(v string) {
	if taint.IsTaintedString(v) {
		falseTaint.Add(1)
		violation("false taint on clean value %q", trunc(v))
	}
}

func trunc(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

func runSQL(ctx context.Context, query string) {
	checkSink(ctx, query)
	switch rand.IntN(4) {
	case 0:
		rows, err := db.QueryContext(ctx, query)
		if err == nil {
			for rows.Next() {
			}
			rows.Close()
		}
	case 1:
		_, _ = db.ExecContext(ctx, query)
	case 2:
		stmt, err := db.PrepareContext(ctx, query)
		if err == nil {
			_, _ = stmt.ExecContext(ctx)
			stmt.Close()
		}
	default:
		_, _ = db.ExecContext(ctx, "SELECT ?", query)
	}
}

func runExec(ctx context.Context, args ...string) {
	select {
	case execSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-execSem }()
	execCalls.Add(1)
	if len(args) > 0 {
		checkSink(ctx, args[0])
	}
	_ = exec.CommandContext(ctx, "/bin/true", args...).Run()
}

func publish(id uint64, value string) {
	if len(value) > 0 {
		ring[rand.IntN(len(ring))].Store(&sharedEntry{value: value, id: id})
	}
}

// crossCheck reads a random shared value retained from another request.
func crossCheck(ctx context.Context, mine string) string {
	e := ring[rand.IntN(len(ring))].Load()
	if e == nil {
		return mine
	}
	if done[e.id%uint64(len(done))].Load() == e.id {
		bleedChecks.Add(1)
		if taint.IsTaintedString(e.value) {
			bleed.Add(1)
			violation("value from finished request %d still tainted: %q", e.id, trunc(e.value))
		}
	}
	return e.value + "|" + mine
}

func reqID(r *http.Request) uint64 {
	id, _ := strconv.ParseUint(r.Header.Get("X-Req"), 10, 64)
	return id
}

// ---- handlers (woven root-application handler functions) ----

func withSpan(fi int, next func(ctx context.Context, w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), flowKey{}, fi)
		if active(ctx) {
			analyzed.Add(1)
		}
		switch r.Header.Get("X-Span") {
		case "none":
		case "nested":
			span, sctx := tracer.StartSpanFromContext(ctx, "stress.req")
			defer span.Finish()
			child, cctx := tracer.StartSpanFromContext(sctx, "stress.child")
			defer child.Finish()
			ctx = cctx
		default:
			span, sctx := tracer.StartSpanFromContext(ctx, "stress.req")
			defer span.Finish()
			ctx = sctx
		}
		cleanCheck(strings.Repeat("c", 2+rand.IntN(8)) + "-clean")
		next(ctx, w, r.WithContext(ctx))
		w.WriteHeader(http.StatusNoContent)
	}
}

func hQuery(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	t := strings.TrimSpace(v)
	if len(t) > 4 {
		t = t[1 : len(t)-1]
	}
	q := "SELECT * FROM t WHERE a = '" + t + "' AND b = " + strconv.Itoa(len(t))
	publish(reqID(r), v)
	runSQL(ctx, q)
	runSQL(ctx, crossCheck(ctx, q))
}

func hHeader(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	v := r.Header.Get("X-Data")
	u := strings.ToUpper(v)
	u = strings.Replace(u, "A", "b", -1)
	parts := strings.Split(u, ",")
	q := strings.Join(append([]string{"SELECT"}, parts...), " ")
	publish(reqID(r), u)
	runSQL(ctx, q)
}

func hForm(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		return
	}
	v := r.FormValue("v")
	q := fmt.Sprintf("UPDATE t SET x = '%s' WHERE id = %d", v, rand.IntN(100))
	publish(reqID(r), v)
	runSQL(ctx, q)
	runSQL(ctx, url.QueryEscape(v))
}

type payload struct {
	Name   string            `json:"name"`
	Items  []string          `json:"items"`
	Map    map[string]string `json:"map"`
	Nested struct {
		Value string `json:"value"`
		Num   int    `json:",string"`
	} `json:"nested"`
	Any any `json:"any"`
}

func hJSON(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var p payload
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&p); err != nil {
		return
	}
	var b strings.Builder
	b.WriteString(p.Name)
	b.WriteString("-")
	b.WriteString(p.Nested.Value)
	for _, it := range p.Items {
		b.WriteString(it)
	}
	arg := b.String()
	publish(reqID(r), p.Name)
	if rand.IntN(4) == 0 {
		runExec(ctx, arg, p.Map["k"])
	} else {
		runSQL(ctx, "SELECT '"+arg+"'")
	}
}

func hBody(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return
	}
	body = bytes.TrimSpace(body)
	fields := bytes.Split(body, []byte("&"))
	var strs []string
	for _, f := range fields {
		if len(f) >= 2 {
			strs = append(strs, string(f))
		}
	}
	q := strings.Join(strs, " OR ")
	if len(q) > 2 {
		publish(reqID(r), q[:len(q)/2])
	}
	var p payload
	if json.Unmarshal(body, &p) == nil && p.Name != "" {
		q += p.Name
	}
	runSQL(ctx, "DELETE FROM t WHERE "+q)
}

func hCookie(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sess")
	if err != nil {
		return
	}
	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		v = c.Value
	}
	q := "SELECT " + strconv.Quote(v)
	publish(reqID(r), v)
	runSQL(ctx, q)
}

func hPath(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	runSQL(ctx, "SELECT * FROM u WHERE id = "+id)
	if rand.IntN(8) == 0 {
		runExec(ctx, id)
	}
}

func hBuf(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteString("clean-prefix-")
	buf.WriteString(strconv.Itoa(rand.IntN(1000)))
	clean := buf.String()
	if taint.IsTaintedString(clean) {
		poolBleed.Add(1)
		violation("pooled bytes.Buffer produced tainted clean string %q", trunc(clean))
	}
	buf.WriteString(v)
	fmt.Fprintf(buf, " %s", v)
	q := buf.String()
	bufPool.Put(buf)
	runSQL(ctx, "INSERT INTO t VALUES ('"+q+"')")
}

func hFan(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	body, _ := io.ReadAll(r.Body)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := strings.ToLower(v) + strconv.Itoa(i)
			if len(s) > 3 {
				s = s[:len(s)-1]
			}
			var p payload
			if len(body) > 0 && json.Unmarshal(body, &p) == nil {
				s += p.Name
			}
			var b strings.Builder
			b.WriteString(s)
			b.WriteString(crossCheck(ctx, s))
			runSQL(ctx, b.String())
			_ = taint.IsTaintedString(s)
		}()
	}
	wg.Wait()
	publish(reqID(r), v)
}

func hLate(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	q := "SELECT '" + v + "'"
	lateOutstanding.Add(1)
	go func() {
		defer lateOutstanding.Add(-1)
		defer lateDone.Add(1)
		time.Sleep(time.Duration(rand.IntN(3000)) * time.Microsecond)
		s := q + " -- late"
		_, _ = db.ExecContext(context.Background(), s)
		_, _ = db.ExecContext(ctx, s)
		if rand.IntN(16) == 0 {
			runExec(context.Background(), s)
		}
		_ = taint.IsTaintedString(q)
	}()
	runSQL(ctx, q)
}

func hAbort(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	q := "SELECT " + v
	runSQL(ctx, q)
	handlerPanicsIntended.Add(1)
	if rand.IntN(2) == 0 {
		panic(http.ErrAbortHandler)
	}
	panic("stress: intentional handler panic")
}

func hBig(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var parts []string
	for k, vs := range q {
		for _, v := range vs {
			parts = append(parts, k+"="+v)
		}
	}
	for k, vs := range r.Header {
		if strings.HasPrefix(k, "X-H") {
			parts = append(parts, vs...)
		}
	}
	body, _ := io.ReadAll(r.Body)
	var p payload
	_ = json.Unmarshal(body, &p)
	parts = append(parts, p.Items...)
	joined := strings.Join(parts, ",")
	runSQL(ctx, "SELECT "+joined)
	if len(parts) > 0 && rand.IntN(4) == 0 {
		if len(parts) > 300 {
			parts = parts[:300]
		}
		runExec(ctx, parts...)
	}
}

func hDerive(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	if len(v) < 4 {
		return
	}
	acc := v
	for i := range 3000 {
		j := i % (len(v) - 2)
		s := v[j : j+2]
		switch i % 5 {
		case 0:
			acc = s + "-" + v[:j+1]
		case 1:
			acc = strings.Repeat(s, 3)
		case 2:
			acc = fmt.Sprint(s, i)
		case 3:
			acc = strings.ReplaceAll(v, s, "_")
		default:
			acc = strings.TrimPrefix(acc, s)
		}
		if i%500 == 0 {
			runSQL(ctx, "SELECT "+acc)
		}
	}
	runSQL(ctx, acc)
}

// hCheck is used by the serial post-run verification only.
func hCheck(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("v")
	switch {
	case !active(r.Context()):
		w.Write([]byte("N"))
	case taint.IsTaintedString(v):
		w.Write([]byte("T"))
	default:
		w.Write([]byte("A"))
	}
}

// ---- fake agent ----

func startAgent(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("fake agent: %v", err)
		return
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(r.URL.Path, "traces") {
			agentPayloads.Add(1)
			agentBytes.Add(int64(len(body)))
			agentSQL.Add(int64(bytes.Count(body, []byte("SQL_INJECTION"))))
			agentCMD.Add(int64(bytes.Count(body, []byte("COMMAND_INJECTION"))))
		}
		if r.URL.Path == "/info" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("{}"))
	}))
}

// ---- driver ----

var dumps atomic.Int32

func dumpGoroutines(reason string) {
	n := dumps.Add(1)
	if n > 4 {
		return
	}
	name := fmt.Sprintf("%s/goroutines-%d.txt", *flagDumpDir, n)
	f, err := os.Create(name)
	if err != nil {
		log.Printf("dump: %v", err)
		return
	}
	fmt.Fprintf(f, "reason: %s\n\n", reason)
	pprof.Lookup("goroutine").WriteTo(f, 2)
	f.Close()
	log.Printf("STALL: %s -> goroutine dump %s", reason, name)
}

var flows = [...]string{"q", "h", "form", "json", "body", "cookie", "p", "buf", "fan", "late", "abort", "big", "derive"}

func randString(n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789 '\";-=,&%é日"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[rand.IntN(len(alpha))]
	}
	return string(b)
}

type flowStat struct {
	count, totalNs, maxNs, maxLen, sinkT, sinkU atomic.Int64
}

var flowStats [len(flows)]flowStat

func buildRequest(ctx context.Context, base string, id uint64) (*http.Request, int, int, error) {
	fi := rand.IntN(len(flows))
	flow := flows[fi]
	v := randString(2 + rand.IntN(64))
	if rand.IntN(50) == 0 {
		v = randString(1 + rand.IntN(70000))
	}
	var body io.Reader
	method := http.MethodGet
	path := "/" + flow
	values := url.Values{"v": {v}}
	ctype := ""
	switch flow {
	case "form":
		method = http.MethodPost
		body = strings.NewReader(url.Values{"v": {v}, "w": {randString(8)}}.Encode())
		ctype = "application/x-www-form-urlencoded"
	case "json", "body", "fan":
		method = http.MethodPost
		items := make([]string, rand.IntN(20))
		for i := range items {
			items[i] = randString(4 + rand.IntN(30))
		}
		doc, _ := json.Marshal(map[string]any{"name": v, "items": items, "map": map[string]string{"k": randString(6)},
			"nested": map[string]any{"value": randString(10), "Num": "42"}, "any": v})
		if rand.IntN(20) == 0 {
			doc = doc[:len(doc)/2] // malformed
		}
		if flow == "body" && rand.IntN(2) == 0 {
			doc = []byte(v + "&" + randString(20) + "&x")
		}
		body = bytes.NewReader(doc)
		ctype = "application/json"
	case "p":
		path = "/p/" + url.PathEscape(v)
	case "abort":
		method = http.MethodPost // POST is not retried by the Transport
	case "big":
		method = http.MethodPost
		for i := range 300 + rand.IntN(100) {
			values.Add("k"+strconv.Itoa(i), randString(1+rand.IntN(1000)))
		}
		items := make([]string, 400)
		for i := range items {
			items[i] = randString(100)
		}
		doc, _ := json.Marshal(map[string]any{"items": items})
		body = bytes.NewReader(doc)
	}
	u := base + path + "?" + values.Encode()
	if len(u) > 900000 {
		u = u[:900000]
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fi, len(v), err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("X-Req", strconv.FormatUint(id, 10))
	req.Header.Set("X-Data", v[:min(len(v), 4000)])
	req.AddCookie(&http.Cookie{Name: "sess", Value: url.QueryEscape(v[:min(len(v), 2000)])})
	switch rand.IntN(5) {
	case 0:
		req.Header.Set("X-Span", "none")
	case 1:
		req.Header.Set("X-Span", "nested")
	}
	if flow == "big" {
		for i := range 100 {
			req.Header.Add("X-H"+strconv.Itoa(i), randString(50))
		}
	}
	return req, fi, len(v), nil
}

func main() {
	flag.Parse()
	startAgent(*flagAgent)
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("woven=%v go=%s clients=%d duration=%s GOMAXPROCS=%d env: sampling=%s maxconc=%s dedup=%s vulns=%s",
		built.WithOrchestrion, runtime.Version(), *flagClients, *flagDuration, runtime.GOMAXPROCS(0),
		os.Getenv("DD_IAST_REQUEST_SAMPLING"), os.Getenv("DD_IAST_MAX_CONCURRENT_REQUESTS"),
		os.Getenv("DD_IAST_DEDUPLICATION_ENABLED"), os.Getenv("DD_IAST_VULNERABILITIES_PER_REQUEST"))
	sql.Register("stress", fakeDriver{})
	var err error
	db, err = sql.Open("stress", "")
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(0) // unlimited: the fake driver is free, avoid harness pool starvation
	db.SetMaxIdleConns(512)

	mux := http.NewServeMux()
	routes := map[string]func(context.Context, http.ResponseWriter, *http.Request){
		"/q": hQuery, "/h": hHeader, "/form": hForm, "/json": hJSON, "/body": hBody, "/cookie": hCookie,
		"/p/{id}": hPath, "/buf": hBuf, "/fan": hFan, "/late": hLate, "/abort": hAbort, "/big": hBig, "/derive": hDerive,
	}
	for pattern, h := range routes {
		fi := 0
		for i, f := range flows {
			if strings.TrimPrefix(strings.TrimSuffix(pattern, "/{id}"), "/") == f {
				fi = i
			}
		}
		mux.Handle(pattern, withSpan(fi, h))
	}
	mux.HandleFunc("/check", hCheck)
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Config.MaxHeaderBytes = 4 << 20
	srv.Start()
	defer srv.Close()

	transport := &http.Transport{MaxIdleConns: 1024, MaxIdleConnsPerHost: 1024, MaxConnsPerHost: 0}
	client := &http.Client{Transport: transport}

	start := time.Now()
	deadline := start.Add(*flagDuration)
	inflight := make([]atomic.Int64, *flagClients)
	var nextID atomic.Uint64
	var wg sync.WaitGroup
	for c := range *flagClients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				id := nextID.Add(1)
				ctx, cancel := context.Background(), context.CancelFunc(func() {})
				if rand.IntN(20) == 0 {
					ctx, cancel = context.WithTimeout(ctx, time.Duration(rand.IntN(2000))*time.Microsecond)
				}
				req, fi, vlen, err := buildRequest(ctx, srv.URL, id)
				if err != nil {
					cancel()
					errorsCount.Add(1)
					continue
				}
				t0 := time.Now()
				inflight[c].Store(t0.UnixNano())
				resp, err := client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					done[id%uint64(len(done))].Store(id)
				} else if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
					cancelled.Add(1)
				} else if !strings.Contains(req.URL.Path, "abort") {
					errorsCount.Add(1)
					if errorsCount.Load() < 10 {
						log.Printf("client error %s: %v", req.URL.Path, err)
					}
				}
				inflight[c].Store(0)
				el := time.Since(t0).Nanoseconds()
				fs := &flowStats[fi]
				fs.count.Add(1)
				fs.totalNs.Add(el)
				if el > fs.maxNs.Load() {
					fs.maxNs.Store(el)
					fs.maxLen.Store(int64(vlen))
				}
				cancel()
				completed.Add(1)
			}
		}()
	}

	stop := make(chan struct{})
	go func() {
		var last int64
		lastChange := time.Now()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		lastReport := time.Now()
		var lastDump time.Time
		for {
			select {
			case <-stop:
				return
			case now := <-tick.C:
				cur := completed.Load()
				if cur != last {
					last, lastChange = cur, now
				}
				var oldest time.Duration
				for i := range inflight {
					if t := inflight[i].Load(); t != 0 {
						oldest = max(oldest, now.Sub(time.Unix(0, t)))
					}
				}
				stalled := now.Sub(lastChange) > *flagStall || oldest > *flagStall
				if stalled && now.Sub(lastDump) > 30*time.Second {
					stalls.Add(1)
					lastDump = now
					dumpGoroutines(fmt.Sprintf("no progress for %s, oldest in-flight %s", now.Sub(lastChange), oldest))
				}
				if now.Sub(lastReport) >= 15*time.Second {
					lastReport = now
					var ms runtime.MemStats
					runtime.ReadMemStats(&ms)
					st := taintrequest.ActiveStore()
					log.Printf("t=%3.0fs done=%d rps=%.0f analyzed=%d sinkT=%d sinkU=%d sql=%d exec=%d err=%d canc=%d oldest=%s gor=%d heap=%dMiB storeValues=%d storeCharged=%d falseTaint=%d bleed=%d/%d poolBleed=%d agentSQL=%d agentCMD=%d",
						now.Sub(start).Seconds(), cur, float64(cur)/now.Sub(start).Seconds(), analyzed.Load(), sinkTainted.Load(), sinkUntaintedActive.Load(),
						sqlCalls.Load(), execCalls.Load(), errorsCount.Load(), cancelled.Load(), oldest.Truncate(time.Millisecond), runtime.NumGoroutine(),
						ms.HeapAlloc>>20, st.ProcessValues(), st.ProcessCharged(), falseTaint.Load(), bleed.Load(), bleedChecks.Load(), poolBleed.Load(),
						agentSQL.Load(), agentCMD.Load())
				}
			}
		}
	}()
	wg.Wait()
	log.Printf("load phase finished: %d requests in %s", completed.Load(), time.Since(start).Truncate(time.Second))

	// Late goroutines must drain.
	drainDeadline := time.Now().Add(30 * time.Second)
	for lateOutstanding.Load() > 0 && time.Now().Before(drainDeadline) {
		time.Sleep(50 * time.Millisecond)
	}
	failed := false
	if n := lateOutstanding.Load(); n > 0 {
		failed = true
		dumpGoroutines(fmt.Sprintf("%d late goroutines did not drain", n))
	}
	transport.CloseIdleConnections()
	time.Sleep(2 * time.Second)
	runtime.GC()

	st := taintrequest.ActiveStore()
	log.Printf("quiescent store: values=%d charged=%d acquireDrops=%d", st.ProcessValues(), st.ProcessCharged(), st.AcquireDrops())
	if st.ProcessValues() != 0 || st.ProcessCharged() != 0 {
		failed = true
		log.Printf("FAIL: store not empty at quiescence (leak)")
	}

	// Serial verification: every sampled request must still get a permit and
	// taint its query. A leaked permit or owner would surface as N.
	var results strings.Builder
	for i := range 64 {
		resp, err := client.Get(srv.URL + "/check?v=" + url.QueryEscape("verify-"+strconv.Itoa(i)+"-value"))
		if err != nil {
			results.WriteString("E")
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		results.Write(b)
	}
	log.Printf("serial verification (T=tainted, A=active untainted, N=not analyzed): %s", results.String())
	if strings.ContainsAny(results.String(), "NAE") {
		failed = true
		log.Printf("FAIL: serial verification not all T")
	}

	time.Sleep(4 * time.Second) // let the tracer flush to the fake agent
	close(stop)
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	log.Printf("SUMMARY requests=%d analyzed=%d sinkTainted=%d sinkUntaintedActive=%d sqlCalls=%d execCalls=%d clientErrors=%d cancelled=%d intendedPanics=%d lateDone=%d stalls=%d falseTaint=%d bleed=%d (checks=%d) poolBleed=%d heapAfterGC=%dMiB goroutines=%d agentPayloads=%d agentBytes=%d agentSQL=%d agentCMD=%d",
		completed.Load(), analyzed.Load(), sinkTainted.Load(), sinkUntaintedActive.Load(), sqlCalls.Load(), execCalls.Load(), errorsCount.Load(), cancelled.Load(),
		handlerPanicsIntended.Load(), lateDone.Load(), stalls.Load(), falseTaint.Load(), bleed.Load(), bleedChecks.Load(), poolBleed.Load(), ms.HeapAlloc>>20,
		runtime.NumGoroutine(), agentPayloads.Load(), agentBytes.Load(), agentSQL.Load(), agentCMD.Load())
	for i := range flowStats {
		fs := &flowStats[i]
		n := max(fs.count.Load(), 1)
		log.Printf("flow %-7s n=%-7d avg=%-10s max=%-10s (vlen at max=%d) activeSinks tainted=%d untainted=%d", flows[i], fs.count.Load(),
			time.Duration(fs.totalNs.Load()/n).Truncate(time.Microsecond), time.Duration(fs.maxNs.Load()).Truncate(time.Microsecond), fs.maxLen.Load(),
			fs.sinkT.Load(), fs.sinkU.Load())
	}
	for _, v := range violations {
		log.Printf("VIOLATION: %s", v)
	}
	if stalls.Load() > 0 || falseTaint.Load() > 0 || bleed.Load() > 0 || poolBleed.Load() > 0 {
		failed = true
	}
	if failed {
		log.Printf("RESULT: FAIL")
		tracer.Stop()
		os.Exit(1)
	}
	log.Printf("RESULT: PASS")
}
