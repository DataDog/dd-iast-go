// Command e2etruepos is a deliberately vulnerable demo service woven with
// Orchestrion + dd-iast-go, used to verify SQLi/CMDi true/false positives.
package main

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

var db *sql.DB

// sinkLine reports the line immediately after the caller's line: put the
// call on the line right before the sink expression.
func sinkLine(w http.ResponseWriter) {
	_, file, line, _ := runtime.Caller(1)
	w.Header().Set("X-Sink-File", file)
	w.Header().Set("X-Sink-Line", strconv.Itoa(line+1))
}

func main() {
	var mt mocktracer.Tracer
	if os.Getenv("E2E_MODE") == "mock" {
		mt = mocktracer.Start()
	}
	sql.Register("fake", fakeDriver{})
	var err error
	db, err = sql.Open("fake", "")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	registerHandlers(mux)
	srv := &http.Server{Handler: mux}
	mux.HandleFunc("POST /__shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go srv.Close()
	})
	ln, err := net.Listen("tcp", "127.0.0.1:"+os.Getenv("E2E_PORT"))
	if err != nil {
		panic(err)
	}
	_ = srv.Serve(ln)
	if mt != nil {
		dumpMock(mt)
		mt.Stop()
	}
}

func dumpMock(mt mocktracer.Tracer) {
	type span struct {
		Name     string         `json:"name"`
		Resource string         `json:"resource"`
		SpanID   uint64         `json:"span_id"`
		ParentID uint64         `json:"parent_id"`
		Tags     map[string]any `json:"tags"`
	}
	var out []span
	for _, s := range mt.FinishedSpans() {
		tags := map[string]any{}
		for k, v := range s.Tags() {
			switch v.(type) {
			case string, float64, int, int64, uint64, bool:
				tags[k] = v
			default:
				tags[k] = "<non-scalar>"
			}
		}
		out = append(out, span{Name: s.OperationName(), Resource: s.Tag("resource.name").(string), SpanID: s.SpanID(), ParentID: s.ParentID(), Tags: tags})
	}
	f, err := os.Create(os.Getenv("E2E_MOCK_OUT"))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(out)
}
