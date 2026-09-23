// Command driver is built WITHOUT orchestrion. It runs a fake trace-agent,
// launches the woven demo, drives it over real HTTP, and checks IAST payloads.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tinylib/msgp/msgp"
)

type fakeAgent struct {
	addr  string
	mu    sync.Mutex
	spans []map[string]any
}

func startFakeAgent() *fakeAgent {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	fa := &fakeAgent{addr: ln.Addr().String()}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "7.99.0", "endpoints": []string{"/v0.4/traces", "/v0.6/stats"},
			"span_meta_structs": true, "client_drop_p0s": false,
		})
	})
	mux.HandleFunc("/v0.4/traces", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if v, _, err := msgp.ReadIntfBytes(body); err == nil {
			fa.add(v)
		} else {
			fmt.Fprintln(os.Stderr, "agent decode error:", err)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{}`))
	})
	go (&http.Server{Handler: mux}).Serve(ln)
	return fa
}

func (fa *fakeAgent) add(v any) {
	traces, _ := v.([]any)
	fa.mu.Lock()
	defer fa.mu.Unlock()
	for _, tr := range traces {
		list, _ := tr.([]any)
		for _, s := range list {
			m, _ := s.(map[string]any)
			if m == nil {
				continue
			}
			if ms, ok := m["meta_struct"].(map[string]any); ok {
				dec := map[string]any{}
				for k, raw := range ms {
					b, _ := raw.([]byte)
					var buf bytes.Buffer
					if _, err := msgp.UnmarshalAsJSON(&buf, b); err != nil {
						dec[k] = map[string]any{"decode_error": err.Error()}
						continue
					}
					var j any
					_ = json.Unmarshal(buf.Bytes(), &j)
					dec[k] = j
				}
				m["meta_struct"] = dec
			}
			fa.spans = append(fa.spans, m)
		}
	}
}

type tcase struct {
	Name       string
	Method     string
	Path       string
	Query      url.Values
	Header     map[string]string
	Body       string
	CType      string
	WantTypes  map[string]int // vulnerability type -> count (empty = no vulns)
	WantSource []string       // "origin|name" set expected in sources
	CheckLine  bool
}

type result struct {
	Case       string         `json:"case"`
	URL        string         `json:"url"`
	Status     int            `json:"status"`
	SinkFile   string         `json:"sink_file,omitempty"`
	SinkLine   string         `json:"sink_line,omitempty"`
	XOut       string         `json:"x_out,omitempty"`
	Enabled    any            `json:"iast_enabled"`
	ManualKeep any            `json:"manual_keep,omitempty"`
	Channel    string         `json:"channel"`
	Event      map[string]any `json:"event"`
	Verdict    []string       `json:"verdict"`
}

func main() {
	bin := flag.String("bin", "", "woven demo binary")
	mode := flag.String("mode", "agent", "agent|mock")
	out := flag.String("out", "results.json", "output")
	phase := flag.String("phase", "seq", "seq|conc")
	nodedup := flag.Bool("nodedup", false, "disable IAST deduplication")
	flag.Parse()

	fa := startFakeAgent()
	port := freePort()
	mockOut := filepath.Join(os.TempDir(), fmt.Sprintf("e2e-mock-%s.json", port))
	cmd := exec.Command(*bin)
	cmd.Env = append(os.Environ(),
		"E2E_MODE="+*mode, "E2E_PORT="+port, "E2E_MOCK_OUT="+mockOut,
		"DD_TRACE_AGENT_URL=http://"+fa.addr, "DD_SERVICE=e2e-demo",
		"DD_IAST_ENABLED=true", "DD_IAST_REQUEST_SAMPLING=100",
		"DD_INSTRUMENTATION_TELEMETRY_ENABLED=false", "DD_REMOTE_CONFIGURATION_ENABLED=false",
		"DD_TRACE_STARTUP_LOGS=false",
	)
	if *phase == "conc" {
		cmd.Env = append(cmd.Env, "DD_IAST_DEDUPLICATION_ENABLED=false", "DD_IAST_MAX_CONCURRENT_REQUESTS=64")
	}
	if *nodedup {
		cmd.Env = append(cmd.Env, "DD_IAST_DEDUPLICATION_ENABLED=false")
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	must(cmd.Start())
	base := "http://127.0.0.1:" + port
	waitUp(base)

	sqlT := map[string]int{"SQL_INJECTION": 1}
	cmdT := map[string]int{"COMMAND_INJECTION": 1}
	none := map[string]int{}
	cases := []tcase{
		{Name: "sql-sprintf", Method: "GET", Path: "/sql/sprintf", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-sprintf-literal", Method: "GET", Path: "/sql/sprintf-literal", Query: url.Values{"name": {"x' OR '1'='1"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|name"}, CheckLine: true},
		{Name: "sql-concat", Method: "GET", Path: "/sql/concat", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-concat-literal", Method: "GET", Path: "/sql/concat-literal", Query: url.Values{"name": {"x' OR '1'='1"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|name"}, CheckLine: true},
		{Name: "sql-builder", Method: "GET", Path: "/sql/builder", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-json-decoder", Method: "POST", Path: "/sql/json-decoder", Body: `{"col":"name; DROP TABLE users"}`, CType: "application/json", WantTypes: sqlT, WantSource: []string{"http.request.body|"}, CheckLine: true},
		{Name: "sql-json-unmarshal", Method: "POST", Path: "/sql/json-unmarshal", Body: `{"col":"name; DROP TABLE users"}`, CType: "application/json", WantTypes: sqlT, WantSource: []string{"http.request.body|"}, CheckLine: true},
		{Name: "sql-header", Method: "GET", Path: "/sql/header", Header: map[string]string{"X-Sort": "name; DROP TABLE users"}, WantTypes: sqlT, WantSource: []string{"http.request.header|X-Sort"}, CheckLine: true},
		{Name: "sql-cookie", Method: "GET", Path: "/sql/cookie", Header: map[string]string{"Cookie": "sort=name--x"}, WantTypes: sqlT, WantSource: []string{"http.request.cookie.value|sort"}, CheckLine: true},
		{Name: "sql-form", Method: "POST", Path: "/sql/form", Body: "col=name%3B+DROP+TABLE+users", CType: "application/x-www-form-urlencoded", WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-path", Method: "GET", Path: "/sql/path/name--x", WantTypes: sqlT, WantSource: []string{"http.request.path.parameter|col"}, CheckLine: true},
		{Name: "sql-two-sources", Method: "GET", Path: "/sql/two-sources", Query: url.Values{"col": {"secret_col"}, "table": {"users_tbl"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col", "http.request.parameter|table"}, CheckLine: true},
		{Name: "sql-prepare", Method: "GET", Path: "/sql/prepare", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: map[string]int{"SQL_INJECTION": 2}, WantSource: []string{"http.request.parameter|col"}},
		{Name: "sql-redact-name", Method: "GET", Path: "/sql/redact-name", Query: url.Values{"password": {"hunter2hunter2"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|password"}, CheckLine: true},
		{Name: "sql-comment", Method: "GET", Path: "/sql/comment", Query: url.Values{"col": {"name /* token=ghp_TAINTEDSECRETINCOMMENT */"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-literal-func", Method: "GET", Path: "/sql/literal-func", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-inline-concat", Method: "GET", Path: "/sql/inline-concat", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-inline-sprintf", Method: "GET", Path: "/sql/inline-sprintf", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "doc-fn-sql-plus-assign", Method: "GET", Path: "/sql/plus-assign", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: none},
		{Name: "sql-noctx", Method: "GET", Path: "/sql/noctx", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-body-string", Method: "POST", Path: "/sql/body-string", Body: "name; DROP TABLE users", CType: "text/plain", WantTypes: sqlT, WantSource: []string{"http.request.body|"}, CheckLine: true},
		{Name: "sql-multipart", Method: "POST", Path: "/sql/multipart", Body: "--XX\r\nContent-Disposition: form-data; name=\"col\"\r\n\r\nname; DROP TABLE users\r\n--XX--\r\n", CType: "multipart/form-data; boundary=XX", WantTypes: sqlT, WantSource: []string{"http.request.multipart.parameter|col"}, CheckLine: true},
		{Name: "sql-method-handler", Method: "GET", Path: "/sql/method", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-transform", Method: "GET", Path: "/sql/transform", Query: url.Values{"col": {"  NAME; DROP TABLE users  "}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-query-index", Method: "GET", Path: "/sql/query-index", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "sql-json-map", Method: "POST", Path: "/sql/json-map", Body: `{"col":"name; DROP TABLE users"}`, CType: "application/json", WantTypes: sqlT, WantSource: []string{"http.request.body|"}, CheckLine: true},
		{Name: "sql-validated-string", Method: "GET", Path: "/sql/validated-string", Query: url.Values{"id": {"42"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|id"}, CheckLine: true},
		{Name: "sql-goroutine", Method: "GET", Path: "/sql/goroutine", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}},
		{Name: "neg-sql-allowlist", Method: "GET", Path: "/sql/allowlist", Query: url.Values{"col": {"name"}}, WantTypes: none},
		{Name: "neg-sql-branch", Method: "GET", Path: "/sql/branch", Query: url.Values{"col": {"name"}}, WantTypes: none},
		{Name: "cmd-inline-concat", Method: "GET", Path: "/cmd/inline-concat", Query: url.Values{"dir": {"/tmp; id"}}, WantTypes: cmdT, WantSource: []string{"http.request.parameter|dir"}, CheckLine: true},
		{Name: "cmd-join", Method: "GET", Path: "/cmd/join", Query: url.Values{"dir": {"/tmp; id"}}, WantTypes: cmdT, WantSource: []string{"http.request.parameter|dir"}, CheckLine: true},
		{Name: "neg-fp-builder-reset", Method: "GET", Path: "/fp/builder-reset", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: none},
		{Name: "sql-buffer-shared-a", Method: "GET", Path: "/fp/buffer-shared-a", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}, CheckLine: true},
		{Name: "neg-fp-buffer-shared-b", Method: "GET", Path: "/fp/buffer-shared-b", WantTypes: none},
		{Name: "neg-fp-json-clean-doc", Method: "POST", Path: "/fp/json-clean-doc", Body: `{"col":"name; DROP TABLE users"}`, CType: "application/json", WantTypes: none},
		{Name: "neg-fp-query-set", Method: "GET", Path: "/fp/query-set", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: none},
		{Name: "neg-fp-header-set", Method: "GET", Path: "/fp/header-set", Header: map[string]string{"X-Sort": "name; DROP TABLE users"}, WantTypes: none},
		{Name: "neg-fp-replace-all", Method: "GET", Path: "/fp/replace-all", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: none},
		{Name: "obs-fp-sprintf-hex", Method: "GET", Path: "/fp/sprintf-hex", Query: url.Values{"name": {"x' OR '1'='1"}}, WantTypes: none},
		{Name: "neg-fp-sprintf-type", Method: "GET", Path: "/fp/sprintf-type", Query: url.Values{"name": {"x' OR '1'='1"}}, WantTypes: none},
		{Name: "neg-fp-sprintf-len", Method: "GET", Path: "/fp/sprintf-len", Query: url.Values{"name": {"x' OR '1'='1"}}, WantTypes: none},
		{Name: "doc-fp-body-overwrite", Method: "POST", Path: "/fp/body-overwrite", Body: "name; DROP TABLE users; -------xxx", CType: "text/plain", WantTypes: none},
		{Name: "sql-urlpath", Method: "GET", Path: "/sql/urlpath/name--x", WantTypes: sqlT, WantSource: []string{"http.request.path|"}, CheckLine: true},
		{Name: "sql-rawquery", Method: "GET", Path: "/sql/rawquery", Query: url.Values{"a": {"1 OR 1=1"}}, WantTypes: sqlT, WantSource: []string{"http.request.query|"}, CheckLine: true},
		{Name: "sql-header-index", Method: "GET", Path: "/sql/header-index", Header: map[string]string{"X-Sort": "name; DROP TABLE users"}, WantTypes: sqlT, WantSource: []string{"http.request.header|X-Sort"}, CheckLine: true},
		{Name: "sql-auth-header", Method: "GET", Path: "/sql/auth-header", Header: map[string]string{"Authorization": "Bearer abc.def.ghi"}, WantTypes: sqlT, WantSource: []string{"http.request.header|Authorization"}, CheckLine: true},
		{Name: "sql-login-control", Method: "GET", Path: "/sql/login", Query: url.Values{"user": {"alice"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|user"}, CheckLine: true},
		{Name: "sql-login-comment-injection", Method: "GET", Path: "/sql/login", Query: url.Values{"user": {"admin' --"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|user"}, CheckLine: true},
		{Name: "sql-login-block-comment-injection", Method: "GET", Path: "/sql/login", Query: url.Values{"user": {"admin' /*"}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|user"}, CheckLine: true},
		{Name: "neg-sql-safe-param", Method: "GET", Path: "/sql/safe-param", Query: url.Values{"name": {"x' OR '1'='1"}}, WantTypes: none},
		{Name: "neg-sql-atoi", Method: "GET", Path: "/sql/atoi", Query: url.Values{"id": {"42"}}, WantTypes: none},
		{Name: "neg-sql-clean-literal", Method: "GET", Path: "/sql/clean-literal", Query: url.Values{"col": {"name"}}, WantTypes: none},
		{Name: "neg-leak-set", Method: "GET", Path: "/sql/leak-set", Query: url.Values{"col": {"name; DROP TABLE users"}}, WantTypes: none},
		{Name: "neg-leak-use", Method: "GET", Path: "/sql/leak-use", WantTypes: none},
		{Name: "cmd-shell", Method: "GET", Path: "/cmd/shell", Query: url.Values{"cmd": {"echo ddiast-$((40+2))"}}, WantTypes: cmdT, WantSource: []string{"http.request.parameter|cmd"}, CheckLine: true},
		{Name: "cmd-arg", Method: "GET", Path: "/cmd/arg", Query: url.Values{"file": {"/tmp; id"}}, WantTypes: cmdT, WantSource: []string{"http.request.parameter|file"}, CheckLine: true},
		{Name: "neg-cmd-safe", Method: "GET", Path: "/cmd/safe", Query: url.Values{"cmd": {"echo pwned"}}, WantTypes: none},
		{Name: "neg-cmd-atoi", Method: "GET", Path: "/cmd/atoi", Query: url.Values{"n": {"7"}}, WantTypes: none},
	}
	var meta []result
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	send := func(c tcase) result {
		u := base + c.Path
		if len(c.Query) > 0 {
			u += "?" + c.Query.Encode()
		}
		var body io.Reader
		if c.Body != "" {
			body = strings.NewReader(c.Body)
		}
		req, err := http.NewRequest(c.Method, u, body)
		must(err)
		if c.CType != "" {
			req.Header.Set("Content-Type", c.CType)
		}
		for k, v := range c.Header {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		must(err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return result{Case: c.Name, URL: u, Status: resp.StatusCode, SinkFile: resp.Header.Get("X-Sink-File"), SinkLine: resp.Header.Get("X-Sink-Line"), XOut: resp.Header.Get("X-Out")}
	}
	if *phase == "conc" {
		cases = nil
		for i := 0; i < 32; i++ {
			if i%2 == 0 {
				col := fmt.Sprintf("c%02d; DROP TABLE t%02d", i, i)
				cases = append(cases, tcase{Name: fmt.Sprintf("conc-tainted-%02d", i), Method: "GET", Path: "/conc", Query: url.Values{"kind": {"tainted"}, "col": {col}, "i": {fmt.Sprint(i)}}, WantTypes: sqlT, WantSource: []string{"http.request.parameter|col"}})
			} else {
				cases = append(cases, tcase{Name: fmt.Sprintf("conc-clean-%02d", i), Method: "GET", Path: "/conc", Query: url.Values{"kind": {"clean"}, "col": {"name"}, "i": {fmt.Sprint(i)}}, WantTypes: none})
			}
		}
		meta = make([]result, len(cases))
		var wg sync.WaitGroup
		for i := range cases {
			wg.Add(1)
			go func(i int) { defer wg.Done(); meta[i] = send(cases[i]) }(i)
		}
		wg.Wait()
	} else {
		for _, c := range cases {
			meta = append(meta, send(c))
		}
	}
	resp, err := client.Post(base+"/__shutdown", "text/plain", nil)
	must(err)
	resp.Body.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		fmt.Fprintln(os.Stderr, "demo exited:", err)
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		fmt.Fprintln(os.Stderr, "demo killed after timeout")
	}

	// Collect server root spans in request order.
	var spans []map[string]any
	if *mode == "mock" {
		data, err := os.ReadFile(mockOut)
		must(err)
		var list []map[string]any
		must(json.Unmarshal(data, &list))
		for _, s := range list {
			if s["name"] == "http.request" && s["parent_id"] == float64(0) {
				tags := s["tags"].(map[string]any)
				s["meta"] = tags
				spans = append(spans, s)
			}
		}
	} else {
		time.Sleep(0) // tracer.Stop flushed synchronously before exit
		fa.mu.Lock()
		for _, s := range fa.spans {
			if s["name"] == "http.request" && (s["parent_id"] == nil || fmt.Sprint(s["parent_id"]) == "0") {
				spans = append(spans, s)
			}
		}
		fa.mu.Unlock()
		sort.Slice(spans, func(i, j int) bool { return toF(spans[i]["start"]) < toF(spans[j]["start"]) })
	}
	byPath := map[string][]map[string]any{}
	for _, s := range spans {
		m, _ := s["meta"].(map[string]any)
		u, _ := m["http.url"].(string)
		pu, _ := url.Parse(u)
		if pu != nil {
			byPath[pu.RequestURI()] = append(byPath[pu.RequestURI()], s)
			if pu.RequestURI() != pu.Path {
				byPath["path:"+pu.Path] = append(byPath["path:"+pu.Path], s)
			}
		}
	}
	fails := 0
	for i := range meta {
		r := &meta[i]
		c := cases[i]
		pu, _ := url.Parse(r.URL)
		key := pu.RequestURI()
		list := byPath[key]
		if len(list) == 0 {
			key = "path:" + pu.Path
			list = byPath[key]
		}
		if len(list) == 0 {
			r.Verdict = append(r.Verdict, "FAIL: no server span captured")
			fails++
			continue
		}
		s := list[0]
		byPath[key] = list[1:]
		m, _ := s["meta"].(map[string]any)
		metrics, _ := s["metrics"].(map[string]any)
		r.Enabled = first(m["_dd.iast.enabled"], metrics["_dd.iast.enabled"])
		r.ManualKeep = first(m["manual.keep"], metrics["_sampling_priority_v1"])
		if ms, ok := s["meta_struct"].(map[string]any); ok && ms["iast"] != nil {
			r.Channel = "meta_struct.iast"
			r.Event, _ = ms["iast"].(map[string]any)
		} else if raw, ok := m["_dd.iast.json"].(string); ok {
			r.Channel = "meta._dd.iast.json"
			_ = json.Unmarshal([]byte(raw), &r.Event)
		} else {
			r.Channel = "none"
		}
		got := map[string]int{}
		vulns, _ := r.Event["vulnerabilities"].([]any)
		srcs, _ := r.Event["sources"].([]any)
		for _, v := range vulns {
			vm := v.(map[string]any)
			got[fmt.Sprint(vm["type"])]++
			if c.CheckLine {
				loc, _ := vm["location"].(map[string]any)
				if fmt.Sprint(loc["path"]) == "" || !strings.HasSuffix(r.SinkFile, fmt.Sprint(loc["path"])) || fmt.Sprint(toF(loc["line"])) != r.SinkLine {
					r.Verdict = append(r.Verdict, fmt.Sprintf("FAIL: location %v:%v want %s:%s", loc["path"], loc["line"], filepath.Base(r.SinkFile), r.SinkLine))
					fails++
				}
			}
			ev, _ := vm["evidence"].(map[string]any)
			parts, _ := ev["valueParts"].([]any)
			var sb strings.Builder
			for _, p := range parts {
				pm := p.(map[string]any)
				seg := fmt.Sprint(first(pm["value"], pm["pattern"]))
				if si, ok := pm["source"]; ok {
					seg = fmt.Sprintf("[%s#%v]", seg, si)
				}
				sb.WriteString(seg)
			}
			r.Verdict = append(r.Verdict, "evidence: "+sb.String())
		}
		for _, sr := range srcs {
			sm := sr.(map[string]any)
			r.Verdict = append(r.Verdict, fmt.Sprintf("source: origin=%v name=%v value=%v pattern=%v redacted=%v", sm["origin"], sm["name"], sm["value"], sm["pattern"], sm["redacted"]))
		}
		if *phase == "conc" && fmt.Sprint(r.Enabled) != "1" {
			r.Verdict = append(r.Verdict, "SKIP: not analyzed (admission)")
			continue
		}
		if own := c.Query.Get("col"); *phase == "conc" && len(c.WantTypes) > 0 {
			for _, sr := range srcs {
				sm := sr.(map[string]any)
				if fmt.Sprint(sm["value"]) != own {
					r.Verdict = append(r.Verdict, fmt.Sprintf("FAIL: foreign source value %v (own %q)", sm["value"], own))
					fails++
				}
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(c.WantTypes) {
			r.Verdict = append(r.Verdict, fmt.Sprintf("FAIL: types %v want %v", got, c.WantTypes))
			fails++
		}
		for _, want := range c.WantSource {
			found := false
			for _, sr := range srcs {
				sm := sr.(map[string]any)
				if fmt.Sprintf("%v|%v", sm["origin"], nz(sm["name"])) == want {
					found = true
				}
			}
			if !found {
				r.Verdict = append(r.Verdict, "FAIL: missing source "+want)
				fails++
			}
		}
		if len(c.WantTypes) > 0 && fmt.Sprint(r.Enabled) != "1" {
			r.Verdict = append(r.Verdict, fmt.Sprintf("FAIL: _dd.iast.enabled=%v", r.Enabled))
			fails++
		}
	}
	for _, r := range meta {
		status := "PASS"
		for _, v := range r.Verdict {
			if strings.HasPrefix(v, "FAIL") {
				status = "FAIL"
			}
		}
		fmt.Printf("=== %s %s (http %d, channel=%s, enabled=%v, keep=%v)\n", status, r.Case, r.Status, r.Channel, r.Enabled, r.ManualKeep)
		for _, v := range r.Verdict {
			fmt.Println("    " + v)
		}
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	must(os.WriteFile(*out, data, 0o644))
	all, _ := json.MarshalIndent(spans, "", "  ")
	must(os.WriteFile(strings.TrimSuffix(*out, ".json")+".spans.json", all, 0o644))
	fmt.Printf("TOTAL FAILS=%d cases=%d mode=%s\n", fails, len(cases), *mode)
}

func nz(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func first(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

func toF(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	case int:
		return float64(x)
	case uint32:
		return float64(x)
	case int32:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return -1
}

func freePort() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer ln.Close()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

func waitUp(base string) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", strings.TrimPrefix(base, "http://"), time.Second)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	panic("demo did not start")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
