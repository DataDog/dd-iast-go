// Phase-3 reproducer (fx-life-async-F1): realistic application-root handlers.

package testapp

import (
	"database/sql"
	"net/http"

	"github.com/DataDog/dd-iast-go/taint"
)

// FxObservation records what the handler saw.
type FxObservation struct {
	Value, RawQuery, Query                      string
	ValueTainted, RawQueryTainted, QueryTainted bool
}

// FxItemsByQuery reads ?name= through URL.Query and builds SQL by concatenation.
func FxItemsByQuery(db *sql.DB, seen *FxObservation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		query := "SELECT id FROM items WHERE name = '" + name + "'"
		*seen = FxObservation{Value: name, RawQuery: r.URL.RawQuery, Query: query,
			ValueTainted: taint.IsTaintedString(name), RawQueryTainted: taint.IsTaintedString(r.URL.RawQuery),
			QueryTainted: taint.IsTaintedString(query)}
		rows, err := db.QueryContext(r.Context(), query)
		if err == nil {
			rows.Close()
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// FxItemsByForm reads ?name= through FormValue (context-scoped lazy source).
func FxItemsByForm(db *sql.DB, seen *FxObservation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")
		query := "SELECT id FROM items WHERE name = '" + name + "'"
		*seen = FxObservation{Value: name, RawQuery: r.URL.RawQuery, Query: query,
			ValueTainted: taint.IsTaintedString(name), RawQueryTainted: taint.IsTaintedString(r.URL.RawQuery),
			QueryTainted: taint.IsTaintedString(query)}
		rows, err := db.QueryContext(r.Context(), query)
		if err == nil {
			rows.Close()
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// FxCloneMiddleware forwards r.Clone(r.Context()), as request-mutating middleware does.
func FxCloneMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.Clone(r.Context()))
	})
}
