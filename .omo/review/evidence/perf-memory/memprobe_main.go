// Command memprobe measures per-request heap allocation and post-request
// retention of dd-iast-go taint tracking (perf-memory review node).
//
// The same source is built twice: plainly (no Orchestrion) and woven. Each
// scenario runs in a fresh process. Handlers have the exact
// func(http.ResponseWriter, *http.Request) shape, so the woven build installs
// the application.http.Handler fallback advice (scope Begin/EagerHTTP/Finish)
// and the handler is invoked directly, without a network round trip. Only the
// handler call is inside the measured window; request construction and the
// mocktracer reset happen outside it.
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
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

var (
	db      *sql.DB
	sinkStr string
	sinkN   int
	diag    bool
	diagOut diagInfo

	typicalNames = []string{"id", "name", "email", "city", "country", "role", "status", "sort", "order", "page"}
	// In-cap worst case: request/lazy.go caps a managed map at 48 names and
	// request/http.go caps eager headers at 32 names; above either cap the whole
	// map is left untainted, so the worst case stays just below them.
	worstParams  = 47
	worstHeaders = 31
	jsonItems    = 200
)

type diagInfo struct {
	Tainted  bool           `json:"tainted_query"`
	Counters store.Counters `json:"owner_drop_counters"`
	Values   int32          `json:"owner_values"`
	Charged  int64          `json:"owner_charged_bytes"`
	Sources  int            `json:"owner_sources"`
	Live     bool           `json:"owner_live"`
	Stages   map[string]any `json:"stages,omitempty"`
	LiveHeap uint64         `json:"live_heap_at_handler_end"`
}

func stage(ctx context.Context, name string, v any) {
	if !diag {
		return
	}
	if diagOut.Stages == nil {
		diagOut.Stages = map[string]any{}
	}
	c, values, charged, sources, _ := taintrequest.PerfMemoryOwner(ctx)
	diagOut.Stages[name] = map[string]any{"v": v, "values": values, "charged": charged, "sources": sources, "drops": c}
}

func probe(ctx context.Context, query string) {
	if !diag {
		return
	}
	diagOut.Tainted = isTaintedQuery(query)
	diagOut.LiveHeap = heapAfterGC()
	diagOut.Counters, diagOut.Values, diagOut.Charged, diagOut.Sources, diagOut.Live = taintrequest.PerfMemoryOwner(ctx)
}

func runQuery(ctx context.Context, query string, args ...any) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err == nil {
		_ = rows.Close()
	}
}

// handleClean: no request data reaches any string operation; constant SQL.
func handleClean(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request")
	defer span.Finish()
	const query = "SELECT id, name FROM users WHERE active = 1"
	runQuery(ctx, query)
	probe(ctx, query)
	w.WriteHeader(http.StatusNoContent)
}

// handleSafe: 10 params read (lazily tainted) but passed as bound arguments.
func handleSafe(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request")
	defer span.Finish()
	q := r.URL.Query()
	args := make([]any, 0, len(typicalNames))
	for _, name := range typicalNames {
		args = append(args, q.Get(name))
	}
	const query = "SELECT * FROM users WHERE id=? AND name=? AND email=? AND city=? AND country=? AND role=? AND status=? AND sort=? AND order=? AND page=?"
	runQuery(ctx, query, args...)
	probe(ctx, query)
	w.WriteHeader(http.StatusNoContent)
}

// handleTypical: 10 params concatenated into SQL text (SQL injection).
func handleTypical(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request")
	defer span.Finish()
	q := r.URL.Query()
	clauses := make([]string, 0, len(typicalNames))
	for _, name := range typicalNames {
		value := q.Get(name)
		clauses = append(clauses, name+" = '"+value+"'")
	}
	query := "SELECT * FROM users WHERE " + strings.Join(clauses, " AND ")
	runQuery(ctx, query)
	probe(ctx, query)
	w.WriteHeader(http.StatusNoContent)
}

// handleWorst drives every per-request bound: 256 params, 64 headers, a JSON
// body near the 64 KiB document bound, >4096 derived windows, >512 roots and
// >2 MiB of derived root bytes, a 64+ range value and 100 distinct SQLi sinks.
func handleWorst(w http.ResponseWriter, r *http.Request) {
	span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request")
	defer span.Finish()
	q := r.URL.Query()
	vals := make([]string, 0, worstParams+worstHeaders+256)
	for i := range len(q) {
		vals = append(vals, q.Get("p"+strconv.Itoa(i)))
	}
	for i := range len(r.Header) - 1 {
		vals = append(vals, r.Header.Get("X-Worst-"+strconv.Itoa(i)))
	}
	core := vals // query + header values; the JSON items are appended after.
	var doc struct {
		Items []string `json:"items"`
	}
	_ = json.NewDecoder(r.Body).Decode(&doc)
	vals = append(vals, doc.Items...)
	if diag {
		n := 0
		for _, v := range vals {
			if taint.IsTaintedString(v) {
				n++
			}
		}
		stage(ctx, "sources", map[string]int{"vals": len(vals), "tainted": n, "json": len(doc.Items)})
	}

	// Ranges: one value with more than 64 tainted segments.
	var b strings.Builder
	for j := range 80 {
		b.WriteString(core[j%len(core)])
		b.WriteString("','")
	}
	big := "SELECT * FROM t WHERE x IN ('" + b.String() + "')"
	stage(ctx, "big", taint.IsTaintedString(big))
	runQuery(ctx, big)
	// Vulnerabilities: 100 distinct tainted queries (hard max 64 per event).
	var last string
	for i := range 100 {
		last = "SELECT * FROM t" + strconv.Itoa(i) + " WHERE a='" + core[i%len(core)] + "' OR b='" + core[(i+1)%len(core)] + "' OR c='" + core[(i+2)%len(core)] + "' OR d='" + core[(i+3)%len(core)] + "'"
		runQuery(ctx, last)
	}
	stage(ctx, "sinks", taint.IsTaintedString(last))
	// Derived roots: saturate MaxRootsPerOwner and RequestRootBytes.
	for i := range 400 {
		sinkStr = strings.Repeat(core[i%len(core)], 60)
		sinkN += len(sinkStr)
		if i == 0 {
			stage(ctx, "repeat0", taint.IsTaintedString(sinkStr))
		}
	}
	stage(ctx, "repeat", taint.IsTaintedString(sinkStr))
	// Derived windows: saturate RequestValueLimit / MaxValuesPerRoot.
	for k := range 16000 {
		v := core[k%len(core)]
		o := (k / len(core)) % (len(v) - 2)
		sinkStr = v[o : o+2]
	}
	stage(ctx, "windows", taint.IsTaintedString(sinkStr))
	probe(ctx, big)
	w.WriteHeader(http.StatusNoContent)
}

func value(i, n int) string {
	prefix := "v" + strconv.Itoa(i) + "-"
	return prefix + strings.Repeat("x", n-len(prefix))
}

func buildRequest(scenario string) *http.Request {
	switch scenario {
	case "clean":
		return httptest.NewRequest(http.MethodGet, "/health", nil)
	case "safe", "typical":
		values := url.Values{}
		for i, name := range typicalNames {
			values.Set(name, value(i, 24))
		}
		return httptest.NewRequest(http.MethodGet, "/users?"+values.Encode(), nil)
	case "typical49":
		values := url.Values{}
		for i, name := range typicalNames {
			values.Set(name, value(i, 24))
		}
		for i := range 39 {
			values.Set("f"+strconv.Itoa(i), "1")
		}
		return httptest.NewRequest(http.MethodGet, "/users?"+values.Encode(), nil)
	case "worst", "overcap":
		params, headers, items := worstParams, worstHeaders, jsonItems
		if scenario == "overcap" {
			params, headers, items = 256, 64, 256
		}
		var sb strings.Builder
		for i := range params {
			if i > 0 {
				sb.WriteByte('&')
			}
			sb.WriteString("p" + strconv.Itoa(i) + "=" + value(i, 200))
		}
		jsonDoc := make([]string, 0, items)
		for i := range items {
			jsonDoc = append(jsonDoc, value(1000+i, 230))
		}
		body, _ := json.Marshal(map[string][]string{"items": jsonDoc})
		req := httptest.NewRequest(http.MethodPost, "/search?"+sb.String(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		for i := range headers {
			req.Header.Set("X-Worst-"+strconv.Itoa(i), value(2000+i, 200))
		}
		return req
	}
	panic("unknown scenario " + scenario)
}

func handlerFor(scenario string) func(http.ResponseWriter, *http.Request) {
	switch scenario {
	case "clean":
		return handleClean
	case "safe":
		return handleSafe
	case "typical", "typical49":
		return handleTypical
	case "worst", "overcap":
		return handleWorst
	}
	return nil
}

type stats struct {
	Mean, P50, P99, Max float64
}

func summarize(xs []uint64) stats {
	s := slices.Clone(xs)
	slices.Sort(s)
	var sum float64
	for _, x := range s {
		sum += float64(x)
	}
	return stats{Mean: sum / float64(len(s)), P50: float64(s[len(s)/2]), P99: float64(s[len(s)*99/100]), Max: float64(s[len(s)-1])}
}

func heapAfterGC() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

type iastGauges struct {
	Process          taintrequest.PerfMemoryGauges `json:"process"`
	Annotations      int                           `json:"span_annotations"`
	EventSourceBytes int64                         `json:"event_source_bytes"`
	OwnerBindings    int                           `json:"owner_span_bindings"`
}

func gauges() iastGauges {
	a, e, o := spans.PerfMemoryStats()
	return iastGauges{Process: taintrequest.PerfMemoryProcess(), Annotations: a, EventSourceBytes: e, OwnerBindings: o}
}

func main() {
	scenario := flag.String("scenario", "typical", "clean|safe|typical|worst|idle")
	n := flag.Int("n", 2000, "measured requests")
	warm := flag.Int("warm", 200, "warmup requests")
	variant := flag.String("variant", "", "label")
	memprofile := flag.String("memprofile", "", "write an alloc profile (MemProfileRate=1) covering the whole run")
	flag.Parse()
	if *memprofile != "" {
		runtime.MemProfileRate = 1
	}

	sql.Register("memprobe", memDriver{})
	var err error
	if db, err = sql.Open("memprobe", ""); err != nil {
		panic(err)
	}
	db.SetMaxIdleConns(4)
	mt := mocktracer.Start()
	defer mt.Stop()

	sc := *scenario
	handle := handlerFor(sc)
	if sc == "idle" {
		handle = func(http.ResponseWriter, *http.Request) {}
		sc = "clean"
	}

	heapPre := heapAfterGC()
	var ms0, ms1 runtime.MemStats
	var first struct{ Bytes, Objects uint64 }
	// First request: includes one-time process initialization (manager/store).
	{
		req, rec := buildRequest(sc), httptest.NewRecorder()
		runtime.ReadMemStats(&ms0)
		handle(rec, req)
		runtime.ReadMemStats(&ms1)
		first.Bytes, first.Objects = ms1.TotalAlloc-ms0.TotalAlloc, ms1.Mallocs-ms0.Mallocs
		mt.Reset()
	}
	heapAfterFirst := heapAfterGC()
	for range *warm {
		handle(httptest.NewRecorder(), buildRequest(sc))
		mt.Reset()
	}
	heapWarm := heapAfterGC()
	gWarm := gauges()

	bytesPer := make([]uint64, 0, *n)
	objsPer := make([]uint64, 0, *n)
	for range *n {
		req, rec := buildRequest(sc), httptest.NewRecorder()
		runtime.ReadMemStats(&ms0)
		handle(rec, req)
		runtime.ReadMemStats(&ms1)
		bytesPer = append(bytesPer, ms1.TotalAlloc-ms0.TotalAlloc)
		objsPer = append(objsPer, ms1.Mallocs-ms0.Mallocs)
		mt.Reset()
	}
	heapEnd := heapAfterGC()
	gEnd := gauges()

	// Diagnostic request (not measured): owner counters and emitted event.
	diag = true
	handle(httptest.NewRecorder(), buildRequest(sc))
	diag = false
	var vulns, payloadBytes int
	var tag string
	for _, s := range mt.FinishedSpans() {
		if raw, ok := s.Tag(spans.SpanTagJson).(string); ok && raw != "" {
			payloadBytes = len(raw)
			tag = "json"
			var ev struct {
				Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
			}
			if json.Unmarshal([]byte(raw), &ev) == nil {
				vulns += len(ev.Vulnerabilities)
			}
		}
		if s.Tag(spans.SpanTagEnabled) == float64(1) && tag == "" {
			tag = "enabled-no-event"
		}
	}
	mt.Reset()
	gDiag := gauges()

	out := map[string]any{
		"variant":                  *variant,
		"scenario":                 *scenario,
		"woven":                    built.WithOrchestrion,
		"go":                       runtime.Version(),
		"iast_enabled":             config.Enabled,
		"sampling":                 config.RequestSamplingPct,
		"max_ranges":               config.MaxRangeCount,
		"vulns_per_req":            config.VulnerabilitiesPerRequest,
		"dedup":                    config.DeduplicationEnabled,
		"n":                        *n,
		"first_req_bytes":          first.Bytes,
		"first_req_objects":        first.Objects,
		"bytes_per_req":            summarize(bytesPer),
		"objects_per_req":          summarize(objsPer),
		"heap_pre":                 heapPre,
		"heap_after_first":         heapAfterFirst,
		"heap_after_warm":          heapWarm,
		"heap_end":                 heapEnd,
		"one_time_init_heap":       int64(heapAfterFirst) - int64(heapPre),
		"retained_over_n":          int64(heapEnd) - int64(heapWarm),
		"retained_per_req":         float64(int64(heapEnd)-int64(heapWarm)) / float64(*n),
		"gauges_warm":              gWarm,
		"gauges_end":               gEnd,
		"gauges_after_diag":        gDiag,
		"diag_owner":               diagOut,
		"live_in_request_over_end": int64(diagOut.LiveHeap) - int64(heapEnd),
		"diag_vulns":               vulns,
		"diag_event_json_bytes":    payloadBytes,
		"diag_span_tag":            tag,
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
		out["profiled_requests"] = 1 + *warm + *n + 1
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func isTaintedQuery(query string) bool { return taint.IsTaintedString(query) }

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
