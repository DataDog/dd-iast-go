package testapp

// Customer-shaped handler code for the fx-hooks-io-bufio-F1 reproducer. It lives
// in the root package because the pinned injector's root filter excludes the
// external test package (see chains.go).

import (
	"bufio"
	"context"
	"database/sql"
	"io"
	"strings"
	"sync"
)

// FXResetOntoConstant reads the body through a bufio.Reader, then reuses the
// same reader for a clean constant query.
func FXResetOntoConstant(ctx context.Context, db *sql.DB, body io.Reader) (bodyData []byte, q []byte, query string, err error) {
	br := bufio.NewReader(body)
	bodyData, _ = io.ReadAll(br)
	br.Reset(strings.NewReader("SELECT 1 FROM clean_constant"))
	q, _ = io.ReadAll(br)
	query = string(q)
	_, err = db.ExecContext(ctx, query)
	return
}

// FXControl uses a fresh reader for the same constant.
func FXControl(ctx context.Context, db *sql.DB, body io.Reader) (q []byte, query string, err error) {
	_, _ = io.ReadAll(bufio.NewReader(body))
	q, _ = io.ReadAll(bufio.NewReader(strings.NewReader("SELECT 1 FROM clean_constant")))
	query = string(q)
	_, err = db.ExecContext(ctx, query)
	return
}

// FXReaderPool is a deterministic free list with the same Get/Reset shape as
// net/http's newBufioReader (sync.Pool's per-P private slot would make the
// cross-goroutine reuse nondeterministic in a test).
type FXReaderPool struct {
	mu    sync.Mutex
	items []*bufio.Reader
}

func (p *FXReaderPool) Get(r io.Reader) *bufio.Reader {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.items); n > 0 {
		br := p.items[n-1]
		p.items = p.items[:n-1]
		br.Reset(r)
		return br
	}
	return bufio.NewReader(r)
}

func (p *FXReaderPool) Put(br *bufio.Reader) {
	br.Reset(nil)
	p.mu.Lock()
	p.items = append(p.items, br)
	p.mu.Unlock()
}

// FXPooledA reads its body through a pooled reader and returns it to the pool.
func FXPooledA(pool *FXReaderPool, body io.Reader) []byte {
	br := pool.Get(body)
	data, _ := io.ReadAll(br)
	pool.Put(br)
	return data
}

// FXPooledBInternal reuses a pooled reader for clean, non-request data.
func FXPooledBInternal(ctx context.Context, db *sql.DB, pool *FXReaderPool) (q []byte, query string, err error) {
	br := pool.Get(strings.NewReader("SELECT 3 FROM b_internal_clean"))
	q, _ = io.ReadAll(br)
	pool.Put(br)
	query = string(q)
	_, err = db.ExecContext(ctx, query)
	return
}

// FXPooledBBody reuses a pooled reader for its own request body.
func FXPooledBBody(ctx context.Context, db *sql.DB, pool *FXReaderPool, body io.Reader) (q []byte, query string, err error) {
	br := pool.Get(body)
	q, _ = io.ReadAll(br)
	pool.Put(br)
	cond := string(q)
	query = "SELECT 4 FROM t WHERE " + cond
	_, err = db.ExecContext(ctx, query)
	return
}
