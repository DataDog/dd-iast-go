package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var leaked string // cross-request global

func registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /sql/sprintf", sqlSprintf)
	mux.HandleFunc("GET /sql/sprintf-literal", sqlSprintfLiteral)
	mux.HandleFunc("GET /sql/concat", sqlConcat)
	mux.HandleFunc("GET /sql/concat-literal", sqlConcatLiteral)
	mux.HandleFunc("GET /sql/builder", sqlBuilder)
	mux.HandleFunc("POST /sql/json-decoder", sqlJSONDecoder)
	mux.HandleFunc("POST /sql/json-unmarshal", sqlJSONUnmarshal)
	mux.HandleFunc("GET /sql/safe-param", sqlSafeParam)
	mux.HandleFunc("GET /sql/atoi", sqlAtoi)
	mux.HandleFunc("GET /sql/clean-literal", sqlCleanLiteral)
	mux.HandleFunc("GET /sql/header", sqlHeader)
	mux.HandleFunc("GET /sql/cookie", sqlCookie)
	mux.HandleFunc("POST /sql/form", sqlForm)
	mux.HandleFunc("GET /sql/path/{col}", sqlPath)
	mux.HandleFunc("GET /sql/two-sources", sqlTwoSources)
	mux.HandleFunc("GET /sql/prepare", sqlPrepare)
	mux.HandleFunc("GET /sql/redact-name", sqlRedactName)
	mux.HandleFunc("GET /sql/comment", sqlComment)
	mux.HandleFunc("GET /sql/leak-set", leakSet)
	mux.HandleFunc("GET /sql/leak-use", leakUse)
	mux.HandleFunc("GET /sql/literal-func", func(w http.ResponseWriter, r *http.Request) {
		col := r.URL.Query().Get("col")
		q := "SELECT id FROM users ORDER BY " + col
		sinkLine(w)
		rows, err := db.QueryContext(r.Context(), q)
		closeRows(rows, err)
	})
	mux.HandleFunc("GET /sql/inline-concat", sqlInlineConcat)
	mux.HandleFunc("GET /sql/inline-sprintf", sqlInlineSprintf)
	mux.HandleFunc("GET /sql/plus-assign", sqlPlusAssign)
	mux.HandleFunc("GET /sql/noctx", sqlNoCtx)
	mux.HandleFunc("POST /sql/body-string", sqlBodyString)
	mux.HandleFunc("POST /sql/multipart", sqlMultipart)
	mux.Handle("GET /sql/method", &server{})
	mux.HandleFunc("GET /sql/transform", sqlTransform)
	mux.HandleFunc("GET /sql/query-index", sqlQueryIndex)
	mux.HandleFunc("POST /sql/json-map", sqlJSONMap)
	mux.HandleFunc("GET /sql/validated-string", sqlValidatedString)
	mux.HandleFunc("GET /sql/goroutine", sqlGoroutine)
	mux.HandleFunc("GET /sql/allowlist", sqlAllowlist)
	mux.HandleFunc("GET /sql/branch", sqlBranch)
	mux.HandleFunc("GET /cmd/inline-concat", cmdInlineConcat)
	mux.HandleFunc("GET /cmd/join", cmdJoin)
	mux.HandleFunc("GET /fp/builder-reset", fpBuilderReset)
	mux.HandleFunc("GET /fp/buffer-shared-a", fpBufferSharedA)
	mux.HandleFunc("GET /fp/buffer-shared-b", fpBufferSharedB)
	mux.HandleFunc("POST /fp/json-clean-doc", fpJSONCleanDoc)
	mux.HandleFunc("GET /fp/query-set", fpQuerySet)
	mux.HandleFunc("GET /fp/header-set", fpHeaderSet)
	mux.HandleFunc("GET /fp/replace-all", fpReplaceAll)
	mux.HandleFunc("GET /fp/sprintf-hex", fpSprintfHex)
	mux.HandleFunc("GET /fp/sprintf-type", fpSprintfType)
	mux.HandleFunc("GET /fp/sprintf-len", fpSprintfLen)
	mux.HandleFunc("POST /fp/body-overwrite", fpBodyOverwrite)
	mux.HandleFunc("GET /sql/urlpath/{rest...}", sqlURLPath)
	mux.HandleFunc("GET /sql/rawquery", sqlRawQuery)
	mux.HandleFunc("GET /sql/header-index", sqlHeaderIndex)
	mux.HandleFunc("GET /sql/auth-header", sqlAuthHeader)
	mux.HandleFunc("GET /conc", concHandler)
	mux.HandleFunc("GET /sql/login", sqlLogin)
	mux.HandleFunc("GET /cmd/shell", cmdShell)
	mux.HandleFunc("GET /cmd/arg", cmdArg)
	mux.HandleFunc("GET /cmd/safe", cmdSafe)
	mux.HandleFunc("GET /cmd/atoi", cmdAtoi)
}

type rowsCloser interface{ Close() error }

func closeRows(rows rowsCloser, err error) {
	if err == nil && rows != nil {
		_ = rows.Close()
	}
}

// --- SQL true positives -------------------------------------------------

func sqlSprintf(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := fmt.Sprintf("SELECT id FROM users ORDER BY %s", col)
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlSprintfLiteral(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	q := fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name)
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlConcat(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := "SELECT id FROM users ORDER BY " + col + " LIMIT 10"
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlConcatLiteral(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	q := "SELECT id FROM users WHERE name = '" + name + "' AND active = 1"
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlBuilder(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	var b strings.Builder
	b.WriteString("SELECT id FROM users ORDER BY ")
	b.WriteString(col)
	b.WriteString(" DESC")
	q := b.String()
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

type searchBody struct {
	Col string `json:"col"`
}

func sqlJSONDecoder(w http.ResponseWriter, r *http.Request) {
	var body searchBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	q := "SELECT id FROM users ORDER BY " + body.Col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlJSONUnmarshal(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	var body searchBody
	if err := json.Unmarshal(data, &body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	q := "SELECT id FROM users ORDER BY " + body.Col
	sinkLine(w)
	_, err = db.ExecContext(r.Context(), q)
	_ = err
}

func sqlHeader(w http.ResponseWriter, r *http.Request) {
	col := r.Header.Get("X-Sort")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlCookie(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sort")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	q := "SELECT id FROM users ORDER BY " + c.Value
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlForm(w http.ResponseWriter, r *http.Request) {
	col := r.FormValue("col")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlPath(w http.ResponseWriter, r *http.Request) {
	col := r.PathValue("col")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlTwoSources(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q := "SELECT " + v.Get("col") + " FROM " + v.Get("table")
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlPrepare(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	stmt, err := db.PrepareContext(r.Context(), q)
	if err != nil {
		return
	}
	defer stmt.Close()
	_, _ = stmt.ExecContext(r.Context())
}

func sqlRedactName(w http.ResponseWriter, r *http.Request) {
	pw := r.URL.Query().Get("password")
	q := "SELECT id FROM users ORDER BY " + pw
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlComment(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := "SELECT id FROM users /* api_key=sk_live_CLEANCOMMENT */ ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

// --- SQL negatives ---------------------------------------------------------

func sqlSafeParam(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.QueryContext(r.Context(), "SELECT id FROM users WHERE name = ?", name)
	closeRows(rows, err)
}

func sqlAtoi(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	q1 := "SELECT name FROM users WHERE id = " + strconv.Itoa(n)
	rows, err := db.QueryContext(r.Context(), q1)
	closeRows(rows, err)
	q2 := fmt.Sprintf("SELECT name FROM users WHERE id = %d", n)
	rows, err = db.QueryContext(r.Context(), q2)
	closeRows(rows, err)
}

func sqlCleanLiteral(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("col") // request carries col=name (byte-identical)
	q := "SELECT id FROM users ORDER BY " + "name"
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func leakSet(w http.ResponseWriter, r *http.Request) {
	leaked = "SELECT id FROM users ORDER BY " + r.URL.Query().Get("col")
}

func leakUse(w http.ResponseWriter, r *http.Request) {
	rows, err := db.QueryContext(r.Context(), leaked)
	closeRows(rows, err)
}

// --- Command injection -------------------------------------------------------

func cmdShell(w http.ResponseWriter, r *http.Request) {
	c := r.URL.Query().Get("cmd")
	sinkLine(w)
	out, err := exec.CommandContext(r.Context(), "sh", "-c", c).Output()
	w.Header().Set("X-Out", strings.TrimSpace(string(out)))
	_ = err
}

func cmdArg(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("file")
	cmd := exec.Command("ls", "-d", f)
	sinkLine(w)
	_ = cmd.Run()
}

func cmdSafe(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("cmd")
	out, _ := exec.CommandContext(r.Context(), "echo", "constant").Output()
	w.Header().Set("X-Out", strings.TrimSpace(string(out)))
}

func cmdAtoi(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.URL.Query().Get("n"))
	if err != nil {
		http.Error(w, "bad n", 400)
		return
	}
	_ = exec.CommandContext(r.Context(), "sh", "-c", "echo "+strconv.Itoa(n)).Run()
}

// --- batch 2 -------------------------------------------------------------------

func sqlInlineConcat(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), "SELECT id FROM users ORDER BY "+col)
	closeRows(rows, err)
}

func sqlInlineSprintf(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), fmt.Sprintf("SELECT id FROM users ORDER BY %s", col))
	closeRows(rows, err)
}

func sqlPlusAssign(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := "SELECT id FROM users ORDER BY "
	q += col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlNoCtx(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.Query(q)
	closeRows(rows, err)
}

func sqlBodyString(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	s := string(body)
	q := "SELECT id FROM users ORDER BY " + s
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlMultipart(w http.ResponseWriter, r *http.Request) {
	col := r.FormValue("col")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

type server struct{}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlTransform(w http.ResponseWriter, r *http.Request) {
	col := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("col")))
	q := strings.Join([]string{"SELECT id FROM users ORDER BY", col}, " ")
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlQueryIndex(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query()["col"][0]
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlJSONMap(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return
	}
	q := "SELECT id FROM users ORDER BY " + body["col"]
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

// Validation without conversion: the original string still flows (TRUE positive).
func sqlValidatedString(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if _, err := strconv.Atoi(id); err != nil {
		return
	}
	q := "SELECT name FROM users WHERE id = " + id
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlGoroutine(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	q := "SELECT id FROM users ORDER BY " + col
	done := make(chan struct{})
	ctx := r.Context()
	go func() {
		defer close(done)
		rows, err := db.QueryContext(ctx, q)
		closeRows(rows, err)
	}()
	<-done
}

var allowedColumns = map[string]string{"name": "name", "id": "id"}

func sqlAllowlist(w http.ResponseWriter, r *http.Request) {
	col, ok := allowedColumns[r.URL.Query().Get("col")]
	if !ok {
		col = "id"
	}
	q := "SELECT id FROM users ORDER BY " + col
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlBranch(w http.ResponseWriter, r *http.Request) {
	col := "id"
	if r.URL.Query().Get("col") == "name" {
		col = "name"
	}
	q := "SELECT id FROM users ORDER BY " + col
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func cmdInlineConcat(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	sinkLine(w)
	_ = exec.CommandContext(r.Context(), "sh", "-c", "ls -d "+dir).Run()
}

func cmdJoin(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	line := strings.Join([]string{"ls", "-d", dir}, " ")
	sinkLine(w)
	_ = exec.CommandContext(r.Context(), "sh", "-c", line).Run()
}

// --- batch 3: false-positive stress -------------------------------------------

func fpBuilderReset(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	var b strings.Builder
	b.WriteString(col)
	_ = b.String()
	b.Reset()
	b.WriteString("SELECT id FROM users ORDER BY name")
	q := b.String()
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

var (
	sharedMu  sync.Mutex
	sharedBuf bytes.Buffer
)

func fpBufferSharedA(w http.ResponseWriter, r *http.Request) {
	col := r.URL.Query().Get("col")
	sharedMu.Lock()
	defer sharedMu.Unlock()
	sharedBuf.Reset()
	sharedBuf.WriteString("SELECT id FROM users ORDER BY ")
	sharedBuf.WriteString(col)
	q := sharedBuf.String()
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpBufferSharedB(w http.ResponseWriter, r *http.Request) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	sharedBuf.Reset()
	sharedBuf.WriteString("SELECT id FROM users ORDER BY ")
	sharedBuf.WriteString("name; DROP TABLE users") // same bytes as request A, but clean
	q := sharedBuf.String()
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpJSONCleanDoc(w http.ResponseWriter, r *http.Request) {
	var tainted searchBody
	_ = json.NewDecoder(r.Body).Decode(&tainted)
	var clean searchBody
	_ = json.Unmarshal([]byte(`{"col":"name; DROP TABLE users"}`), &clean)
	var clean2 searchBody
	_ = json.NewDecoder(strings.NewReader(`{"col":"name; DROP TABLE users"}`)).Decode(&clean2)
	q := "SELECT id FROM users ORDER BY " + clean.Col + ", " + clean2.Col
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpQuerySet(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	v.Set("col", "name")
	q := "SELECT id FROM users ORDER BY " + v.Get("col")
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpHeaderSet(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("X-Sort", "name")
	q := "SELECT id FROM users ORDER BY " + r.Header.Get("X-Sort")
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpReplaceAll(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("col")
	col := strings.ReplaceAll(in, in, "name") // output bytes come only from the literal
	q := "SELECT id FROM users ORDER BY " + col
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpSprintfHex(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("name")
	q := fmt.Sprintf("SELECT id FROM users WHERE name = X'%x'", in)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpSprintfType(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("name")
	q := fmt.Sprintf("SELECT id FROM users /* %T */", in)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpSprintfLen(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("name")
	q := fmt.Sprintf("SELECT id FROM users LIMIT %d", len(in))
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func fpBodyOverwrite(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) != len("SELECT id FROM users ORDER BY name") {
		http.Error(w, "len", 400)
		return
	}
	copy(body, "SELECT id FROM users ORDER BY name") // clean overwrite, same length
	q := string(body)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

// --- batch 3: more true positives ---------------------------------------------

func sqlURLPath(w http.ResponseWriter, r *http.Request) {
	col := strings.TrimPrefix(r.URL.Path, "/sql/urlpath/")
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlRawQuery(w http.ResponseWriter, r *http.Request) {
	q := "SELECT id FROM users WHERE " + r.URL.RawQuery
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlHeaderIndex(w http.ResponseWriter, r *http.Request) {
	col := r.Header["X-Sort"][0]
	q := "SELECT id FROM users ORDER BY " + col
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

func sqlAuthHeader(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	q := "SELECT id FROM sessions WHERE token = " + tok
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

// --- concurrency: all requests overlap before the sink ------------------------

var (
	concArrived atomic.Int64
	concOnce    sync.Once
	concGate          = make(chan struct{})
	concTarget  int64 = 32
)

func concHandler(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	var q string
	if v.Get("kind") == "tainted" {
		q = "SELECT id FROM users ORDER BY " + v.Get("col")
	} else {
		q = "SELECT id FROM users ORDER BY " + "name"
	}
	if concArrived.Add(1) >= concTarget {
		concOnce.Do(func() { close(concGate) })
	}
	select {
	case <-concGate:
	case <-time.After(10 * time.Second):
	}
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}

// Login-style query: the application's own password literal must be redacted.
func sqlLogin(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	q := "SELECT id FROM users WHERE name = '" + user + "' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42"
	sinkLine(w)
	rows, err := db.QueryContext(r.Context(), q)
	closeRows(rows, err)
}
