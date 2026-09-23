// Review reproducer (life-async): application-root helpers so the woven
// propagation and handler advice applies (external test packages are excluded
// by the pinned injector's root filter).

package testapp

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
)

// ReviewDerive runs several supported propagation steps.
func ReviewDerive(v string) string {
	s := "SELECT '" + v + "'"
	s = strings.ToUpper(s)
	var b strings.Builder
	b.WriteString(s)
	b.WriteString(" -- x")
	return fmt.Sprintf("%s", b.String())
}

// ReviewDeriveIdent derives without introducing SQL literals, so SQL
// redaction leaves the source value readable in the event.
func ReviewDeriveIdent(v string) string {
	s := strings.ToLower(strings.TrimSpace(" " + v + " "))
	var b strings.Builder
	b.WriteString(s)
	b.WriteString(" WHERE a = b")
	return b.String()
}

// ReviewConcat is a supported 2-operand concatenation.
func ReviewConcat(a, b string) string { return a + b }

// ReviewDetach replaces the request context with a fresh, non-derived one.
type ReviewDetach struct{ Next http.Handler }

func (d ReviewDetach) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.Next.ServeHTTP(w, r.WithContext(context.Background()))
}

// ReviewPassthrough keeps the request context (control).
type ReviewPassthrough struct{ Next http.Handler }

func (d ReviewPassthrough) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.Next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reviewKey{}, 1)))
}

type reviewKey struct{}

// ReviewClone forwards a deep copy made by Request.Clone with the same context.
type ReviewClone struct{ Next http.Handler }

func (d ReviewClone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.Next.ServeHTTP(w, r.Clone(r.Context()))
}

// ReviewInner reads a query parameter and a header and sinks both.
type ReviewInner struct {
	DB      *sql.DB
	Observe func(r *http.Request, query, header string)
}

func (h ReviewInner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	hv := r.Header.Get("X-Review")
	if h.Observe != nil {
		h.Observe(r, q, hv)
	}
	_, _ = h.DB.ExecContext(r.Context(), q)
	_, _ = h.DB.ExecContext(r.Context(), hv)
}
