// Independent reproducer for phase-3 verification of life-cross-request-F3.
// Written from scratch for node fx-life-cross-request-F3; it does not share
// code with the phase-2 finder harness.
//
// Request A (attacker) writes a tainted query parameter into a bytes.Buffer
// wrapping a pooled slice and returns the slice to the pool while A is still
// in flight. Request B (a different user) takes the slice from the pool,
// refills it with a constant clean query via append (un-woven; models a pool
// helper in a dependency), reads it with bytes.NewBuffer(b).String(), and
// executes it. The desired behavior: B's query is clean and B's span carries
// no vulnerability and none of A's source. A sequential control (A finished
// before B) must always be clean.

package testapp_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

const f3CleanQuery = "SELECT status FROM users" // 24 bytes, constant, clean

var f3Attack = "1' OR '1'='1' --" + strings.Repeat("x", len("SELECT status FROM users")-len("1' OR '1'='1' --"))

func init() {
	if len(f3Attack) != len(f3CleanQuery) {
		panic("f3 fixture lengths changed")
	}
}

func TestF3PooledNewBufferCrossRequest(t *testing.T) {
	requireWoven(t)
	for _, tc := range []struct {
		name       string
		sequential bool
	}{
		{"concurrent-bleed", false},
		{"sequential-control", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := runtime.GOMAXPROCS(1) // deterministic sync.Pool handoff
			defer runtime.GOMAXPROCS(previous)
			mock := mocktracer.Start()
			defer mock.Stop()

			var pool sync.Pool
			pool.New = func() any { return make([]byte, 0, 128) }
			var aPointer uintptr
			var handedOff bool

			db, err := sql.Open(driverName, "")
			require.NoError(t, err)
			defer db.Close()

			aReady := make(chan struct{})
			bDone := make(chan struct{})
			aErr := make(chan error, 1)

			mux := http.NewServeMux()
			mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
				span, _ := tracer.StartSpanFromContext(r.Context(), "f3.a")
				defer span.Finish()
				uid := r.URL.Query().Get("uid") // tainted source of request A
				if !taint.IsTaintedString(uid) {
					t.Errorf("sanity: A query parameter not tainted")
				}
				backing := pool.Get().([]byte)
				aPointer = uintptr(unsafe.Pointer(unsafe.SliceData(backing)))
				out := testapp.F3WriteTainted(backing, uid) // woven WriteString into NewBuffer(backing[:0])
				if !taint.IsTaintedString(out) {
					t.Errorf("sanity: A buffer output not tainted")
				}
				pool.Put(backing[:0]) // recycle while A is still in flight
				close(aReady)
				if !tc.sequential {
					<-bDone // A stays active (e.g. slow DB call) while B runs
				}
				w.WriteHeader(http.StatusNoContent)
			})
			mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
				span, ctx := tracer.StartSpanFromContext(r.Context(), "f3.b")
				defer span.Finish()
				backing := pool.Get().([]byte)
				if uintptr(unsafe.Pointer(unsafe.SliceData(backing))) != aPointer {
					w.WriteHeader(http.StatusNoContent) // pool did not hand A's slice to B
					return
				}
				handedOff = true
				backing = append(backing[:0], f3CleanQuery...) // un-woven refill
				query := testapp.F3NewBufferString(backing)    // woven String on a NEW Buffer
				t.Logf("B: query=%q tainted=%v", query, taint.IsTaintedString(query))
				if _, err := db.ExecContext(ctx, query); err != nil {
					t.Errorf("exec: %v", err)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			client := server.Client()

			go func() {
				request, err := http.NewRequest(http.MethodGet,
					server.URL+"/a?uid="+url.QueryEscape(f3Attack), nil)
				if err != nil {
					aErr <- err
					return
				}
				response, err := client.Do(request)
				if err == nil {
					err = response.Body.Close()
				}
				aErr <- err
			}()
			<-aReady
			if tc.sequential {
				require.NoError(t, <-aErr)
			}
			response, err := client.Get(server.URL + "/b")
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			close(bDone)
			if !tc.sequential {
				require.NoError(t, <-aErr)
			}
			if !handedOff {
				t.Skipf("sync.Pool did not hand A's slice to B (pointer %x)", aPointer)
			}

			var eventB model.Event
			for _, span := range mock.FinishedSpans() {
				if span.OperationName() != "f3.b" {
					continue
				}
				raw, _ := span.Tag(spans.SpanTagJson).(string)
				t.Logf("span f3.b: %s", raw)
				if raw != "" {
					require.NoError(t, json.Unmarshal([]byte(raw), &eventB))
				}
			}
			var sources []string
			for _, source := range eventB.Sources {
				sources = append(sources, fmt.Sprintf("%s:%s=%q", source.Origin, source.Name, source.Value))
			}
			if len(eventB.Vulnerabilities) != 0 || len(eventB.Sources) != 0 {
				t.Errorf("CROSS-REQUEST BLEED: request B executed the constant query %q but its span reports %d vulnerabilities with sources %v",
					f3CleanQuery, len(eventB.Vulnerabilities), sources)
			}
		})
	}
}
