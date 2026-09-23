package testapp

// crash-race-hunt: woven application code exercised concurrently by
// zz_racehunt_test.go. Every stdlib call here is subject to IAST weaving.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// RaceHuntLast holds a tainted value from an earlier (possibly finished)
// request; later requests read it concurrently (cross-request reuse).
var RaceHuntLast atomic.Pointer[string]

// RaceHuntDetached tracks fire-and-forget work that outlives its request.
var RaceHuntDetached sync.WaitGroup

// RaceHuntHandle performs a broad mix of woven operations, including from
// goroutines spawned by the handler that outlive nothing but share values.
func RaceHuntHandle(ctx context.Context, r *http.Request, db *sql.DB, runExec bool) (int, error) {
	q := r.URL.Query()
	name := q.Get("name")
	id := r.FormValue("id")
	hdr := r.Header.Get("X-Hunt")
	cookie := ""
	if c, err := r.Cookie("session"); err == nil {
		cookie = c.Value
	}
	var body struct {
		Value string   `json:"value"`
		List  []string `json:"list"`
	}
	if r.Header.Get("Content-Type") == "application/json" {
		data, err := io.ReadAll(r.Body)
		if err == nil {
			_ = json.Unmarshal(data, &body)
		}
	}
	prev := ""
	if p := RaceHuntLast.Load(); p != nil {
		prev = *p
	}
	joined := name + "-" + id + "-" + hdr + "-" + cookie + "-" + body.Value
	RaceHuntLast.Store(&joined)

	// Fire-and-forget background work that outlives the request: it uses the
	// request URL object and tainted values after the scope finished.
	detachedURL := r.URL
	RaceHuntDetached.Add(1)
	go func() {
		defer RaceHuntDetached.Done()
		v := detachedURL.Query().Get("name")
		q := "SELECT '" + strings.TrimSpace(v) + "' || '" + joined + "'"
		_, _ = db.ExecContext(context.Background(), q)
	}()

	var wg sync.WaitGroup
	var hits atomic.Int32
	errs := make(chan error, 8)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// Concurrent reads of already-parsed request data are legal in Go.
			local := r.URL.Query().Get("name")
			_ = r.Header.Get("X-Hunt")
			// Explicit re-parse is a documented no-op once parsed; concurrent
			// readers of the parsed maps are race-free in plain Go.
			if os.Getenv("RACEHUNT_NOREPARSE") != "1" {
				_ = r.ParseForm()
			}
			_ = r.Form["id"]
			_ = r.PostForm["id"]
			_ = r.FormValue("id")
			_ = r.PostFormValue("id")
			var sb strings.Builder
			sb.WriteString("SELECT * FROM t WHERE a = '")
			sb.WriteString(strings.TrimSpace(local))
			sb.WriteString("' AND b = '")
			sb.WriteString(strings.ToUpper(joined))
			sb.WriteString("' AND c = '")
			sb.WriteString(prev)
			sb.WriteString("'")
			var buf bytes.Buffer
			buf.WriteString(strings.Repeat(name, 2))
			buf.Write([]byte(id))
			buf.WriteString(url.QueryEscape(hdr))
			buf.WriteString(strconv.Quote(cookie))
			_, _ = buf.ReadString('-')
			s := buf.String()
			parts := strings.Split(joined, "-")
			fields := strings.Fields(strings.ReplaceAll(joined, "-", " "))
			cut, _, _ := strings.Cut(joined, "-")
			query := fmt.Sprintf("%s /* %s %s %d %s */", sb.String(), s, strings.Join(parts, ","), len(fields), cut)
			b := []byte(query)
			b = bytes.ToLower(b)
			query2 := string(b[:len(b)/2]) + string(b[len(b)/2:])
			for _, l := range body.List {
				query2 += l
			}
			if _, err := db.ExecContext(ctx, query2); err != nil {
				errs <- err
				return
			}
			rows, err := db.QueryContext(ctx, query)
			if err != nil {
				errs <- err
				return
			}
			_ = rows.Close()
			if runExec && g == 0 {
				_ = osexec.CommandContext(ctx, "/definitely-not-present-"+cut).Run()
			}
			hits.Add(1)
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		return int(hits.Load()), err
	}
	return int(hits.Load()), nil
}
