package testapp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func fxRawSpanPayload(t *testing.T, prefixLen int) string {
	db := openDB(t)
	mock := mocktracer.Start()
	defer mock.Stop()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.fx.request")
		defer span.Finish()
		sort := r.URL.Query().Get("sort")
		query := testapp.FXBoundaryQuery(sort, prefixLen)
		fmt.Printf("CASE prefix=%d query_len=%d sort_tainted=%t query_tainted=%t\n", prefixLen, len(query), taint.IsTaintedString(sort), taint.IsTaintedString(query))
		rows, err := db.QueryContext(ctx, query)
		if rows != nil {
			rows.Close()
		}
		if err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/?sort=name")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	finished := mock.FinishedSpans()
	if len(finished) != 1 {
		t.Fatalf("finished spans = %d", len(finished))
	}
	raw, _ := finished[0].Tag(spans.SpanTagJson).(string)
	return raw
}

func TestFXTruncationBoundaryWireParts(t *testing.T) {
	requireWoven(t)
	config.TruncationMaxValue = 250
	for _, prefixLen := range []int{250, 249, 120} {
		raw := fxRawSpanPayload(t, prefixLen)
		fmt.Printf("CASE prefix=%d payload_len=%d tail=%s\n", prefixLen, len(raw), raw[max(0, len(raw)-140):])
		if dir := os.Getenv("FX_DUMP_DIR"); dir != "" {
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("span_iast_json_prefix%d.json", prefixLen)), []byte(raw), 0o644)
		}
		if raw == "" {
			t.Errorf("prefix=%d: no IAST payload on span", prefixLen)
		}
	}
}
