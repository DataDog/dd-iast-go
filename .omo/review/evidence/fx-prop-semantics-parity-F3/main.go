package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "REGRESSION:", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Printf("runtime=%s woven=%t enabled=%t sampling=%d redaction=%t dedup=%t\n",
		runtime.Version(), built.WithOrchestrion, config.Enabled,
		config.RequestSamplingPct, config.RedactionEnabled, config.DeduplicationEnabled)
	mt := mocktracer.Start()
	defer mt.Stop()
	sql.Register("f3-recording-driver", recordingDriver{})
	db, err := sql.Open("f3-recording-driver", "")
	if err != nil {
		return err
	}
	defer db.Close()

	// Given: an ordinary HTTP handler; instrumentation must create its sources.
	req := httptest.NewRequest(http.MethodGet, "http://example.test/map", nil)
	req.Header.Set("X-Discard", "~~~~")
	var failure error
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failure = inspect(r, db)
		w.WriteHeader(http.StatusNoContent)
	})
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return failure
}

func inspect(req *http.Request, db *sql.DB) error {
	span, ctx := tracer.StartSpanFromContext(req.Context(), "f3.request")
	defer span.Finish()
	_, annotation, bound := spans.ExistingForSpan(span)
	if built.WithOrchestrion && !bound {
		return errors.New("woven HTTP scope was not bound to the span")
	}
	input := strings.Join([]string{"SELECT ", req.Header.Get("X-Discard"), "42"}, "")
	inputRanges := 0
	correctInputRange := true
	taint.VisitString(input, func(r taint.Range) bool {
		inputRanges++
		fmt.Printf("input_range=[%d,%d) source=%q value=%q\n",
			r.Start, r.Start+r.Length, r.Source.Name, r.Source.Value)
		correctInputRange = correctInputRange && r.Start == 7 && r.Length == 4 &&
			r.Source.Name == "X-Discard" && r.Source.Value == "~~~~"
		return true
	})
	if built.WithOrchestrion && (inputRanges != 1 || !correctInputRange) {
		return errors.New("source/join precondition failed")
	}

	// When: the mapping emits no bytes for any tainted input rune.
	calls := 0
	mapping := func(r rune) rune {
		calls++
		if r == '~' {
			return -1
		}
		return r
	}
	mapped := strings.Map(mapping, input)
	mappedCalls := calls
	calls = 0
	nativeMap := strings.Map // Function-value calls intentionally bypass advice.
	native := nativeMap(mapping, input)
	nativeCalls := calls
	replaced := strings.ReplaceAll(input, "~", "")
	empty := strings.Map(func(rune) rune { return -1 }, req.Header.Get("X-Discard"))
	fmt.Printf("mapped=%q calls=%d native_calls=%d empty=%q empty_tainted=%t\n",
		mapped, mappedCalls, nativeCalls, empty, taint.IsTaintedString(empty))
	if mapped != "SELECT 42" || native != mapped || replaced != mapped ||
		mappedCalls != len(input) || nativeCalls != mappedCalls || empty != "" ||
		taint.IsTaintedString(empty) {
		return errors.New("native result, callback count, or empty-output control failed")
	}

	// Then: compare identical SQL through the actual woven database/sql sink.
	for _, control := range []struct {
		name  string
		query string
	}{
		{"literal", "SELECT 42"},
		{"native_map", native},
		{"exact_replace", replaced},
	} {
		_, status := evidence.CollectString(control.query, constants.VulnerabilityTypeSqlInjection)
		fmt.Printf("control=%s tainted=%t sql_collection=%d\n",
			control.name, taint.IsTaintedString(control.query), status)
		if taint.IsTaintedString(control.query) || status != evidence.StatusNone {
			return fmt.Errorf("control %s unexpectedly tainted", control.name)
		}
		if _, err := db.ExecContext(ctx, control.query); err != nil {
			return err
		}
	}
	before := 0
	if bound {
		annotation.RLock()
		before = len(annotation.Vulnerabilities)
		annotation.RUnlock()
	}
	_, status := evidence.CollectString(mapped, constants.VulnerabilityTypeSqlInjection)
	taint.VisitString(mapped, func(r taint.Range) bool {
		fmt.Printf("mapped_range=[%d,%d) source=%q value=%q\n",
			r.Start, r.Start+r.Length, r.Source.Name, r.Source.Value)
		return true
	})
	if _, err := db.ExecContext(ctx, mapped); err != nil {
		return err
	}
	after := 0
	if bound {
		annotation.RLock()
		after = len(annotation.Vulnerabilities)
		event, err := json.Marshal(annotation.Event)
		annotation.RUnlock()
		if err != nil {
			return err
		}
		fmt.Printf("event=%s\n", event)
	}
	fmt.Printf("mapped_tainted=%t sql_collection=%d control_reports=%d map_reports=%d\n",
		taint.IsTaintedString(mapped), status, before, after-before)
	if before != 0 {
		return errors.New("clean controls unexpectedly reported")
	}
	if taint.IsTaintedString(mapped) || status != evidence.StatusNone || after != 0 {
		return errors.New("strings.Map retained deleted-source provenance on constant SQL")
	}
	fmt.Println("PASS: constant SQL has no deleted-source provenance")
	return nil
}

// The in-memory driver accepts the actual query passed by database/sql. It does
// not manufacture taint or reports, and does not require an external database.
type recordingDriver struct{}
type recordingConn struct{}

func (recordingDriver) Open(string) (driver.Conn, error) { return recordingConn{}, nil }
func (recordingConn) Close() error                       { return nil }
func (recordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (recordingConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected Begin")
}
func (recordingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if query != "SELECT 42" {
		return nil, fmt.Errorf("unexpected SQL %q", query)
	}
	fmt.Printf("driver_query=%q\n", query)
	return driver.RowsAffected(1), nil
}
