// Independent end-to-end review reproducer. Not product code.
package testapp_test

import (
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
	independentAttack = "x' OR '1'='1' --comment!"
	independentClean  = "SELECT id FROM customers"
)

type independentResult struct {
	query    string
	tainted  bool
	attempts int
	err      error
}

func TestIndependentPooledBuilderBleedsAcrossWovenRequests(t *testing.T) {
	requireWoven(t)
	require.Equal(t, len(independentAttack), len(independentClean))

	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	mock := mocktracer.Start()
	defer mock.Stop()
	db := openDB(t)

	var pool sync.Pool
	var trackedPointer uintptr
	var trackedLength, trackedCapacity int
	aReady := make(chan struct{})
	bDone := make(chan struct{})
	aDone := make(chan error, 1)
	bResult := make(chan independentResult, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/a":
			span, _ := tracer.StartSpanFromContext(request.Context(), "independent.a")
			defer span.Finish()
			input := request.URL.Query().Get("q")
			builder := new(strings.Builder)
			tainted := testapp.IndependentBuilderWrite(builder, input)
			if !taint.IsTaintedString(tainted) {
				aDone <- fmt.Errorf("request A parameter did not reach the woven builder as tainted")
				return
			}
			trackedPointer = uintptr(unsafe.Pointer(unsafe.StringData(builder.String())))
			trackedLength, trackedCapacity = builder.Len(), builder.Cap()
			builder.Reset()
			pool.Put(builder)
			close(aReady)
			<-bDone
			w.WriteHeader(http.StatusNoContent)
		case "/b":
			span, ctx := tracer.StartSpanFromContext(request.Context(), "independent.b")
			defer span.Finish()
			builder, _ := pool.Get().(*strings.Builder)
			if builder == nil {
				bResult <- independentResult{err: fmt.Errorf("pool did not return request A builder")}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			runtime.GC()
			runtime.GC()
			hit := false
			for attempts := 0; attempts < 50000; attempts++ {
				*builder = strings.Builder{}
				_, _ = fmt.Fprintf(builder, "%s", independentClean)
				if uintptr(unsafe.Pointer(unsafe.StringData(builder.String()))) == trackedPointer &&
					builder.Len() == trackedLength && builder.Cap() == trackedCapacity {
					hit = true
					query := testapp.IndependentBuilderString(builder)
					if taint.IsTaintedString(query) {
						_, err := db.ExecContext(ctx, query)
						bResult <- independentResult{query: query, tainted: true, attempts: attempts, err: err}
						w.WriteHeader(http.StatusNoContent)
						return
					}
				}
			}
			if !hit {
				bResult <- independentResult{err: fmt.Errorf("allocator did not reuse tracked builder backing")}
			} else {
				bResult <- independentResult{query: independentClean}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	aRequest, err := http.NewRequest(http.MethodGet, server.URL+"/a?q=x%27%20OR%20%271%27%3D%271%27%20--comment!", nil)
	require.NoError(t, err)
	aResponse := make(chan error, 1)
	go func() {
		response, requestErr := server.Client().Do(aRequest)
		if requestErr == nil {
			requestErr = response.Body.Close()
		}
		aResponse <- requestErr
	}()
	<-aReady

	bResponse, err := server.Client().Get(server.URL + "/b")
	require.NoError(t, err)
	require.NoError(t, bResponse.Body.Close())
	result := <-bResult
	close(bDone)
	require.NoError(t, <-aResponse)
	select {
	case err = <-aDone:
		require.NoError(t, err)
	default:
	}
	require.NoError(t, result.err)

	var eventB model.Event
	for _, span := range mock.FinishedSpans() {
		if span.OperationName() != "independent.b" {
			continue
		}
		raw, _ := span.Tag(spans.SpanTagJson).(string)
		require.NotEmpty(t, raw)
		require.NoError(t, json.Unmarshal([]byte(raw), &eventB))
	}
	t.Logf("B query=%q tainted=%v attempts=%d findings=%d sources=%v", result.query, result.tainted, result.attempts, len(eventB.Vulnerabilities), eventB.Sources)
	require.False(t, result.tainted, "clean request-B query inherited request-A taint")
	require.Empty(t, eventB.Vulnerabilities, "request-B SQL sink reported request-A provenance")
}
