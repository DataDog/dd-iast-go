// Independent reproducer for fx-life-cross-request-F1. Not part of the product.
// This file is in the woven root package, so it models ordinary customer
// handler code: every call below is a direct, instrumented call site.

package testapp

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"strconv"
)

// FxBodyPool is an application free list of byte buffers. It is a deterministic
// stand-in for a sync.Pool of []byte (capacity one, so a Put is always the next Get).
type FxBodyPool struct{ ch chan []byte }

// NewFxBodyPool returns an empty pool.
func NewFxBodyPool() *FxBodyPool { return &FxBodyPool{ch: make(chan []byte, 1)} }

// Put recycles b.
func (p *FxBodyPool) Put(b []byte) {
	select {
	case p.ch <- b[:0]:
	default:
	}
}

// Get returns a recycled buffer, or a fresh one.
func (p *FxBodyPool) Get() []byte {
	select {
	case b := <-p.ch:
		return b
	default:
		return make([]byte, 0, 64)
	}
}

// FxIngest is request A's handler logic: read the whole body, use it, and
// recycle the buffer. The returned slice is for test inspection only.
func FxIngest(r *http.Request, pool *FxBodyPool) []byte {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	pool.Put(body)
	return body
}

// FxLookup is request B's handler logic: build a query with a server-side
// integer id into a pooled buffer, convert it, and execute it.
func FxLookup(ctx context.Context, db *sql.DB, pool *FxBodyPool, id int64) (string, []byte, error) {
	buf := pool.Get()
	buf = append(buf, "SELECT name FROM users WHERE id="...)
	buf = strconv.AppendInt(buf, id, 10)
	query := string(buf)
	_, err := db.ExecContext(ctx, query)
	pool.Put(buf)
	return query, buf, err
}
