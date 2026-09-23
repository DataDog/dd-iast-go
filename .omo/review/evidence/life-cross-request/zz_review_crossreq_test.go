// Review reproducers for node life-cross-request. Not part of the product.
//
// Two real HTTP requests go through the woven net/http server, so each one gets
// its own sampled request analysis, root span and SQL sink. Request A handles
// attacker-controlled input and recycles memory while it is still in flight.
// Request B (a different user, clean input) reuses that memory and executes a
// constant query. B's span must carry no vulnerability, and it must never
// carry A's source value.
//
// Code in this external test package is NOT woven (see chains.go), so plain
// calls here model un-woven code such as a pool helper in a dependency. Every
// woven call goes through a helper in zz_review_crossreq.go.

package testapp_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

const (
	reviewCleanQuery = "SELECT id FROM customers" // 24 bytes, constant, clean
	reviewAttack     = "x' OR '1'='1' --comment"  // 23 bytes
)

func init() {
	if len(reviewCleanQuery) != 24 || len(reviewAttack)+1 != 24 {
		panic("review fixture lengths changed")
	}
}

// reviewAttack24 is A's attacker input, the same length as B's clean query.
var reviewAttack24 = reviewAttack + "!"

// reviewSkip records a skip reason from a handler goroutine; t.Skip and
// require may only be called from the test goroutine.
type reviewSkip struct {
	mu     sync.Mutex
	reason string
}

func (s *reviewSkip) set(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason == "" {
		s.reason = reason
	}
}

func (s *reviewSkip) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason != "" {
		t.Skip(s.reason)
	}
}

func sanity(t *testing.T, ok bool, message string) {
	if !ok {
		t.Errorf("sanity failed: %s", message)
	}
}

type reviewPair struct {
	// a runs in request A while it is still active. It must not block.
	a func(ctx context.Context, r *http.Request)
	// b runs in request B, concurrently with a still-active A (or after A
	// finished when sequential is true).
	b          func(ctx context.Context, r *http.Request)
	sequential bool
	aQuery     string
	aBody      string
}

// runReviewPair drives two real requests through the woven server and returns
// the IAST events attached to A's and B's root spans.
func runReviewPair(t *testing.T, pair reviewPair) (eventA, eventB model.Event) {
	t.Helper()
	previous := runtime.GOMAXPROCS(1) // deterministic sync.Pool per-P handoff
	defer runtime.GOMAXPROCS(previous)
	mock := mocktracer.Start()
	defer mock.Stop()

	aReady := make(chan struct{})
	bDone := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "review.a")
		defer span.Finish()
		pair.a(ctx, r.WithContext(ctx))
		close(aReady)
		if !pair.sequential {
			<-bDone // A stays in flight (e.g. slow DB call) while B runs.
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "review.b")
		defer span.Finish()
		pair.b(ctx, r.WithContext(ctx))
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := server.Client()

	aResult := make(chan error, 1)
	go func() {
		request, err := http.NewRequest(http.MethodPost, server.URL+"/a?q="+urlQueryEscape(pair.aQuery), strings.NewReader(pair.aBody))
		if err != nil {
			aResult <- err
			return
		}
		response, err := client.Do(request)
		if err == nil {
			err = response.Body.Close()
		}
		aResult <- err
	}()
	<-aReady
	if pair.sequential {
		require.NoError(t, <-aResult)
	}
	response, err := client.Get(server.URL + "/b")
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	close(bDone)
	if !pair.sequential {
		require.NoError(t, <-aResult)
	}

	for _, span := range mock.FinishedSpans() {
		raw, _ := span.Tag(spans.SpanTagJson).(string)
		enabled := span.Tag(spans.SpanTagEnabled)
		var event model.Event
		if raw != "" {
			require.NoError(t, json.Unmarshal([]byte(raw), &event))
		}
		t.Logf("span %s: _dd.iast.enabled=%v _dd.iast.json=%s", span.OperationName(), enabled, raw)
		switch span.OperationName() {
		case "review.a":
			require.Equal(t, float64(1), enabled, "request A was not analyzed")
			eventA = event
		case "review.b":
			require.Equal(t, float64(1), enabled, "request B was not analyzed")
			eventB = event
		}
	}
	return eventA, eventB
}

func urlQueryEscape(value string) string {
	return strings.NewReplacer("%", "%25", " ", "%20", "'", "%27", "=", "%3D", "!", "%21", "-", "%2D").Replace(value)
}

func reviewRanges(value string) []string {
	var out []string
	taint.VisitString(value, func(r taint.Range) bool {
		out = append(out, fmt.Sprintf("[%d,+%d) origin=%s name=%q value=%q", r.Start, r.Length, r.Source.Origin, r.Source.Name, r.Source.Value))
		return true
	})
	return out
}

func sourceValues(event model.Event) []string {
	var out []string
	for _, source := range event.Sources {
		out = append(out, fmt.Sprintf("%s:%s=%q", source.Origin, source.Name, source.Value))
	}
	return out
}

var reviewDB = sync.OnceValue(func() *sql.DB {
	db, err := sql.Open(driverName, "")
	if err != nil {
		panic(err)
	}
	return db
})

func reviewExec(t *testing.T, ctx context.Context, query string) {
	if _, err := reviewDB().ExecContext(ctx, query); err != nil {
		t.Errorf("exec: %v", err)
	}
}

func assertNoBleed(t *testing.T, label string, eventB model.Event) {
	t.Helper()
	if len(eventB.Vulnerabilities) != 0 || len(eventB.Sources) != 0 {
		t.Errorf("CROSS-REQUEST BLEED (%s): request B executed the constant query %q but its span reports %d vulnerabilities with sources %v",
			label, reviewCleanQuery, len(eventB.Vulnerabilities), sourceValues(eventB))
	}
}

// R1. A []byte adopted from io.ReadAll(r.Body) is recycled through a sync.Pool
// while A is in flight. B refills it with a clean constant query and converts it.
func TestReviewPooledReadAllSliceAcrossRequests(t *testing.T) {
	requireWoven(t)
	for _, tc := range []struct {
		name       string
		sequential bool
		clean      string
	}{
		{"concurrent-same-length", false, reviewCleanQuery},
		{"concurrent-different-length", false, reviewCleanQuery + " "},
		{"sequential-A-finished", true, reviewCleanQuery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pool sync.Pool
			var aPointer uintptr
			var skip reviewSkip
			_, eventB := runReviewPair(t, reviewPair{
				sequential: tc.sequential,
				aBody:      reviewAttack24,
				a: func(ctx context.Context, r *http.Request) {
					body := testapp.ReviewReadBody(r.Body)
					sanity(t, taint.IsTaintedBytes(body), "sanity: io.ReadAll body is tainted in A")
					aPointer = uintptr(unsafe.Pointer(unsafe.SliceData(body)))
					pool.Put(body[:0]) // recycle, as with any []byte pool
				},
				b: func(ctx context.Context, r *http.Request) {
					buf, _ := pool.Get().([]byte)
					if uintptr(unsafe.Pointer(unsafe.SliceData(buf))) != aPointer {
						skip.set("sync.Pool did not hand A's slice to B")
						return
					}
					query := testapp.ReviewQueryFromPooled(buf, tc.clean)
					t.Logf("B: query=%q tainted=%v ranges=%v", query, taint.IsTaintedString(query), reviewRanges(query))
					reviewExec(t, ctx, query)
				},
			})
			skip.check(t)
			assertNoBleed(t, tc.name, eventB)
		})
	}
}

// R2. A strings.Builder is recycled through a sync.Pool whose helper resets it
// outside woven code (a dependency, a method value, or `*b = strings.Builder{}`).
// B formats a clean constant query with fmt.Fprintf and calls b.String() directly.
// The tracked backing is not anchored, so GC can reuse its address.
func TestReviewPooledBuilderAcrossRequestsAfterGC(t *testing.T) {
	requireWoven(t)
	for _, tc := range []struct {
		name       string
		sequential bool
	}{
		{"concurrent", false},
		{"sequential-A-finished", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pool sync.Pool
			var pointer uintptr
			var length, capacity int
			attempts := 0
			var skip reviewSkip
			_, eventB := runReviewPair(t, reviewPair{
				sequential: tc.sequential,
				aQuery:     reviewAttack24,
				a: func(ctx context.Context, r *http.Request) {
					input := r.URL.Query().Get("q")
					sanity(t, taint.IsTaintedString(input), "sanity: query parameter tainted")
					sb := new(strings.Builder)
					out := testapp.ReviewBuilderWrite(sb, input)
					sanity(t, taint.IsTaintedString(out), "sanity: builder output tainted in A")
					pointer = uintptr(unsafe.Pointer(unsafe.StringData(sb.String()))) // un-woven read
					length, capacity = sb.Len(), sb.Cap()
					sb.Reset() // un-woven: pool helper outside the root module
					pool.Put(sb)
				},
				b: func(ctx context.Context, r *http.Request) {
					sb, _ := pool.Get().(*strings.Builder)
					if sb == nil {
						skip.set("sync.Pool did not hand A's builder to B")
						return
					}
					runtime.GC() // stands in for a natural GC cycle
					runtime.GC()
					hit := false
					for ; attempts < 50000 && !hit; attempts++ {
						// Each iteration models one more clean use of the pooled builder.
						*sb = strings.Builder{}
						fmt.Fprintf(sb, "%s", reviewCleanQuery) // un-woven write via io.Writer
						hit = uintptr(unsafe.Pointer(unsafe.StringData(sb.String()))) == pointer && sb.Len() == length && sb.Cap() == capacity
					}
					if !hit {
						skip.set("allocator did not reuse the builder backing address")
						return
					}
					query := testapp.ReviewBuilderString(sb)
					t.Logf("B: backing %#x (len %d cap %d) reused after %d clean writes; query=%q tainted=%v ranges=%v",
						pointer, length, capacity, attempts, query, taint.IsTaintedString(query), reviewRanges(query))
					reviewExec(t, ctx, query)
				},
			})
			skip.check(t)
			assertNoBleed(t, tc.name, eventB)
		})
	}
}

// R3. Controls and variants for bytes.Buffer pooling.
func TestReviewPooledBufferAcrossRequests(t *testing.T) {
	requireWoven(t)
	type mode struct {
		name string
		b    func(t *testing.T, buf *bytes.Buffer) string
	}
	for _, m := range []mode{
		{"woven-reset", func(t *testing.T, buf *bytes.Buffer) string {
			testapp.ReviewBufferReset(buf)
			return testapp.ReviewBufferWrite(buf, reviewCleanQuery)
		}},
		{"unwoven-reset-unwoven-write", func(t *testing.T, buf *bytes.Buffer) string {
			buf.Reset()                       // un-woven; the native bytes hook still fires
			buf.WriteString(reviewCleanQuery) // un-woven
			return testapp.ReviewBufferString(buf)
		}},
		{"no-reset-truncate-via-dependency", func(t *testing.T, buf *bytes.Buffer) string {
			buf.Truncate(0)
			fmt.Fprintf(buf, "%s", reviewCleanQuery)
			return testapp.ReviewBufferString(buf)
		}},
	} {
		t.Run(m.name, func(t *testing.T) {
			var pool sync.Pool
			var skip reviewSkip
			_, eventB := runReviewPair(t, reviewPair{
				aQuery: reviewAttack24,
				a: func(ctx context.Context, r *http.Request) {
					input := r.URL.Query().Get("q")
					buf := new(bytes.Buffer)
					out := testapp.ReviewBufferWrite(buf, input)
					sanity(t, taint.IsTaintedString(out), "sanity: buffer output tainted in A")
					pool.Put(buf) // no reset before Put
				},
				b: func(ctx context.Context, r *http.Request) {
					buf, _ := pool.Get().(*bytes.Buffer)
					if buf == nil {
						skip.set("sync.Pool did not hand A's buffer to B")
						return
					}
					query := m.b(t, buf)
					sanity(t, query == reviewCleanQuery, "B query content")
					t.Logf("B: query=%q tainted=%v ranges=%v", query, taint.IsTaintedString(query), reviewRanges(query))
					reviewExec(t, ctx, query)
				},
			})
			skip.check(t)
			assertNoBleed(t, m.name, eventB)
		})
	}
}

// R4. Pooled []byte wrapped with bytes.NewBuffer. A's writer view is matched by
// (backing, len, cap) across receivers (the value-copy feature), so B's new
// Buffer over the refilled slice is looked up as A's tracked view.
func TestReviewPooledSliceNewBufferViewAcrossRequests(t *testing.T) {
	requireWoven(t)
	for _, tc := range []struct {
		name       string
		sequential bool
	}{
		{"concurrent", false},
		{"sequential-A-finished", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pool sync.Pool
			pool.New = func() any { return make([]byte, 0, 64) }
			var skip reviewSkip
			_, eventB := runReviewPair(t, reviewPair{
				sequential: tc.sequential,
				aQuery:     reviewAttack24,
				a: func(ctx context.Context, r *http.Request) {
					input := r.URL.Query().Get("q")
					backing := pool.Get().([]byte)
					buf := bytes.NewBuffer(backing[:0])
					out := testapp.ReviewBufferWrite(buf, input)
					sanity(t, taint.IsTaintedString(out), "sanity: buffer output tainted in A")
					pool.Put(backing[:0])
				},
				b: func(ctx context.Context, r *http.Request) {
					backing := pool.Get().([]byte)
					backing = append(backing[:0], reviewCleanQuery...) // un-woven fill
					query := testapp.ReviewNewBufferString(backing)
					t.Logf("B: query=%q tainted=%v ranges=%v", query, taint.IsTaintedString(query), reviewRanges(query))
					reviewExec(t, ctx, query)
				},
			})
			skip.check(t)
			assertNoBleed(t, tc.name, eventB)
		})
	}
}

// R5. After A finished, GC reuses the address of A's io.ReadAll body for a
// fresh clean slice of the same length in B.
func TestReviewReadAllAddressReuseAfterFinish(t *testing.T) {
	requireWoven(t)
	var pointer uintptr
	var capacity int
	attempts := -1
	var skip reviewSkip
	_, eventB := runReviewPair(t, reviewPair{
		sequential: true,
		aBody:      reviewAttack24,
		a: func(ctx context.Context, r *http.Request) {
			body := testapp.ReviewReadBody(r.Body)
			sanity(t, taint.IsTaintedBytes(body), "A body tainted")
			pointer, capacity = uintptr(unsafe.Pointer(unsafe.SliceData(body))), cap(body)
		},
		b: func(ctx context.Context, r *http.Request) {
			runtime.GC()
			runtime.GC()
			var reused []byte
			fillers := make([][]byte, 0, 50000)
			for i := 0; i < 50000; i++ {
				candidate := make([]byte, 0, capacity)
				if uintptr(unsafe.Pointer(unsafe.SliceData(candidate))) == pointer {
					reused, attempts = candidate, i
					break
				}
				fillers = append(fillers, candidate)
			}
			runtime.KeepAlive(fillers)
			if reused == nil {
				skip.set("allocator did not reuse A's body address")
				return
			}
			query := testapp.ReviewQueryFromPooled(reused, reviewCleanQuery)
			t.Logf("B: A's body address %#x (cap %d) reused after %d allocations; query=%q tainted=%v", pointer, capacity, attempts, query, taint.IsTaintedString(query))
			reviewExec(t, ctx, query)
		},
	})
	skip.check(t)
	assertNoBleed(t, "address-reuse-after-finish", eventB)
}
