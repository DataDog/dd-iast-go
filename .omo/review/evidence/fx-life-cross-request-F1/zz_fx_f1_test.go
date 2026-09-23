// Independent reproducer for fx-life-cross-request-F1. Not part of the product.

package testapp_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// A's attacker body: 36 bytes, the same length as B's query for id 4242.
const fxAttackBody = `{"name":"x' UNION SELECT pass--"}   `

func TestFxF1PooledReadAllBody(t *testing.T) {
	requireWoven(t)
	require.Len(t, fxAttackBody, 36)
	require.Len(t, "SELECT name FROM users WHERE id=4242", 36)
	for _, tc := range []struct {
		name       string
		sequential bool
		id         int64
		wantBleed  bool
	}{
		{"concurrent-same-length", false, 4242, true},
		{"concurrent-different-length", false, 42, false},
		{"sequential-A-finished", true, 4242, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := sql.Open(driverName, "")
			require.NoError(t, err)
			defer db.Close()
			mock := mocktracer.Start()
			defer mock.Stop()
			pool := testapp.NewFxBodyPool()
			aReady, bDone := make(chan struct{}), make(chan struct{})
			var aPtr, bPtr uintptr
			var aTainted, bTainted bool
			var bQuery string
			mux := http.NewServeMux()
			mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
				span, ctx := tracer.StartSpanFromContext(r.Context(), "fx.A")
				defer span.Finish()
				body := testapp.FxIngest(r.WithContext(ctx), pool)
				aPtr, aTainted = uintptr(unsafe.Pointer(unsafe.SliceData(body))), taint.IsTaintedBytes(body)
				close(aReady)
				if !tc.sequential {
					<-bDone // A is still in flight (e.g. waiting on a slow backend)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			mux.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) {
				span, ctx := tracer.StartSpanFromContext(r.Context(), "fx.B")
				defer span.Finish()
				query, buf, err := testapp.FxLookup(ctx, db, pool, tc.id)
				if err != nil {
					t.Errorf("exec: %v", err)
				}
				bQuery, bPtr, bTainted = query, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), taint.IsTaintedString(query)
				w.WriteHeader(http.StatusNoContent)
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			aErr := make(chan error, 1)
			go func() {
				resp, err := server.Client().Post(server.URL+"/ingest", "application/json", strings.NewReader(fxAttackBody))
				if err == nil {
					err = resp.Body.Close()
				}
				aErr <- err
			}()
			<-aReady
			if tc.sequential {
				require.NoError(t, <-aErr)
			}
			resp, err := server.Client().Get(server.URL + "/lookup")
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			close(bDone)
			if !tc.sequential {
				require.NoError(t, <-aErr)
			}
			t.Logf("A: body ptr=%#x tainted=%v", aPtr, aTainted)
			t.Logf("B: buf ptr=%#x sameBacking=%v query=%q tainted=%v", bPtr, aPtr == bPtr, bQuery, bTainted)
			require.True(t, aTainted, "sanity: A's io.ReadAll body must be tainted")
			require.Equal(t, aPtr, bPtr, "sanity: B must reuse A's recycled buffer")
			var eventB model.Event
			for _, s := range mock.FinishedSpans() {
				raw, _ := s.Tag(spans.SpanTagJson).(string)
				t.Logf("span %s: enabled=%v json=%s", s.OperationName(), s.Tag(spans.SpanTagEnabled), raw)
				if s.OperationName() == "fx.B" && raw != "" {
					require.NoError(t, json.Unmarshal([]byte(raw), &eventB))
				}
			}
			bled := len(eventB.Vulnerabilities) > 0 || len(eventB.Sources) > 0
			if bled {
				for _, src := range eventB.Sources {
					t.Logf("B span source: origin=%s value=%q", src.Origin, src.Value)
				}
			}
			if bled != tc.wantBleed {
				t.Errorf("bleed=%v want %v", bled, tc.wantBleed)
			}
			if bled {
				t.Logf("CONFIRMED CROSS-REQUEST BLEED: clean server-built query %q in request B reported with A's body as source", bQuery)
			}
		})
	}
}
