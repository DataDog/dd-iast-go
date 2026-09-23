package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

const attack = "untrusted_sort_marker"

var calls atomic.Int32

type column string

func (c column) String() string {
	calls.Add(1)
	if c == "name" {
		return "name"
	}
	return "id"
}

type columnError string

func (columnError) Error() string {
	calls.Add(1)
	return "id"
}

type columnFormat string

func (columnFormat) Format(s fmt.State, _ rune) {
	calls.Add(1)
	if _, err := io.WriteString(s, "id"); err != nil {
		panic(err)
	}
}

type columnGoString string

func (columnGoString) GoString() string {
	calls.Add(1)
	return "id"
}

type columnBytes []byte

func (columnBytes) String() string {
	calls.Add(1)
	return "id"
}

// This driver only replaces the external database. The real database/sql
// boundary and all IAST source, propagation, and sink hooks remain intact.
type recordingDriver struct{ query chan string }
type recordingConn struct{ query chan string }

func (d recordingDriver) Open(string) (driver.Conn, error) {
	return recordingConn(d), nil
}
func (recordingConn) Close() error { return nil }
func (recordingConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions unused")
}
func (recordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unused")
}
func (c recordingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.query <- query
	return driver.RowsAffected(1), nil
}

type observation struct {
	Mode         string
	InputTainted bool
	Query        string
	Ranges       []taint.Range
	Calls        int32
	Event        model.Event
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 || !built.WithOrchestrion {
		return errors.New("run woven executable with one mode argument")
	}
	mode := os.Args[1]
	fmt.Printf("CONFIG enabled=%t sampling=%d concurrent=%d vulnerabilities=%d dedup=%t redaction=%t\n",
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests,
		config.VulnerabilitiesPerRequest, config.DeduplicationEnabled, config.RedactionEnabled)
	// Keep every production default except sampling, made deterministic here.
	config.RequestSamplingPct = 100
	mock := mocktracer.Start()
	defer mock.Stop()
	executed := make(chan string, 1)
	sql.Register("fx-coarse", recordingDriver{executed})
	db, err := sql.Open("fx-coarse", "")
	if err != nil {
		return err
	}
	defer db.Close()
	done := make(chan observation, 1)
	handlerErrors := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "fx.coarse")
		o := observation{Mode: mode}
		defer func() {
			o.Calls = calls.Load()
			span.Finish()
			done <- o
		}()
		input := r.URL.Query().Get("sort")
		o.InputTainted = taint.IsTaintedString(input)
		switch mode {
		case "stringer":
			o.Query = fmt.Sprintf("SELECT %s FROM accounts", column(input))
		case "error":
			o.Query = fmt.Sprintf("SELECT %s FROM accounts", columnError(input))
		case "formatter":
			o.Query = fmt.Sprintf("SELECT %v FROM accounts", columnFormat(input))
		case "gostring":
			o.Query = fmt.Sprintf("SELECT %#v FROM accounts", columnGoString(input))
		case "sprint":
			o.Query = fmt.Sprint("SELECT ", column(input), " FROM accounts")
		case "sprintln":
			o.Query = fmt.Sprintln("SELECT", column(input), "FROM accounts")
		case "bytes":
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				handlerErrors <- readErr
				return
			}
			o.InputTainted = taint.IsTaintedBytes(body)
			o.Query = fmt.Sprintf("SELECT %s FROM accounts", columnBytes(body))
		case "explicit":
			o.Query = fmt.Sprintf("SELECT %s FROM accounts", column(input).String())
		case "clean":
			o.Query = fmt.Sprintf("SELECT %s FROM accounts", column("constant"))
		case "direct":
			o.Query = fmt.Sprintf("SELECT %s FROM accounts", input)
		default:
			handlerErrors <- errors.New("unknown mode")
			return
		}
		taint.VisitString(o.Query, func(found taint.Range) bool {
			found.Source.Name = strings.Clone(found.Source.Name)
			found.Source.Value = strings.Clone(found.Source.Value)
			o.Ranges = append(o.Ranges, found)
			return true
		})
		if _, execErr := db.ExecContext(ctx, o.Query); execErr != nil {
			handlerErrors <- execErr
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/?sort="+attack, strings.NewReader(attack))
	if err != nil {
		return err
	}
	response, err := server.Client().Do(req)
	if err != nil {
		return err
	}
	if err := response.Body.Close(); err != nil {
		return err
	}
	var o observation
	select {
	case o = <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-handlerErrors:
		return err
	default:
	}
	select {
	case query := <-executed:
		if query != o.Query {
			return errors.New("database driver received a different query")
		}
	default:
		return errors.New("database driver was never called")
	}
	finished := mock.FinishedSpans()
	if len(finished) != 1 || !o.InputTainted {
		return errors.New("woven HTTP source or span precondition failed")
	}
	if raw, ok := finished[0].Tag(spans.SpanTagJson).(string); ok {
		if err := json.Unmarshal([]byte(raw), &o.Event); err != nil {
			return err
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(o); err != nil {
		return err
	}
	expectedQuery := "SELECT id FROM accounts"
	if mode == "direct" {
		expectedQuery = "SELECT untrusted_sort_marker FROM accounts"
	}
	if strings.TrimSpace(o.Query) != expectedQuery {
		return errors.New("native formatting value mismatch")
	}
	if mode == "direct" {
		if len(o.Ranges) != 1 || len(o.Event.Vulnerabilities) != 1 ||
			o.Event.Vulnerabilities[0].Type != constants.VulnerabilityTypeSqlInjection {
			return errors.New("direct tainted SQL positive control failed")
		}
		return nil
	}
	if o.Calls != 1 {
		return errors.New("formatting method was not called exactly once")
	}
	if len(o.Ranges) != 0 || len(o.Event.Vulnerabilities) != 0 {
		return errors.New("ASSERTION FAILED: constant-only SQL must have no taint and no SQL_INJECTION event")
	}
	return nil
}
