package testapp_test

import (
	"context"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
)

type builderLayout struct {
	addr *strings.Builder
	buf  []byte
}

func backing(b *strings.Builder) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData((*builderLayout)(unsafe.Pointer(b)).buf)))
}

// A request parameter is written into a reused strings.Builder holder; the
// holder is then reinitialised and refilled with a fully server-side, clean
// SQL query of the same length. If GC hands back the freed backing, the woven
// String() publishes the stale request taint and the SQL sink reports it.
func TestReviewBuilderABAFalseSQLi(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const param = "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	const clean = "SELECT name FROM users WHERE id = 42"
	if len(param) != len(clean) {
		t.Fatal("lengths differ")
	}
	for _, mode := range []string{"zero-value-reset/gc-each-row", "zero-value-reset/collect-rows", "control-woven-Reset/collect-rows"} {
		t.Run(mode, func(t *testing.T) {
			const attempts = 2000
			var reused, fp, fpNoReuse, execs int
			event := requestEvent(t, func(ctx context.Context, r *http.Request) {
				id := r.URL.Query().Get("id")
				if !taint.IsTaintedString(id) {
					t.Error("control: source not tainted")
				}
				w := &testapp.RowWriter{}
				w.WriteRow(id)
				old := backing(&w.SB)
				collect := strings.HasSuffix(mode, "collect-rows")
				var rows []string // handler accumulates formatted rows
				for i := 0; i < attempts; i++ {
					if strings.HasPrefix(mode, "zero-value-reset") {
						w.ZeroReset()
					} else {
						w.WovenReset()
					}
					if !collect || i == 0 {
						runtime.GC() // stands in for a concurrent GC cycle during the request
					}
					w.FormatRow(clean)
					same := backing(&w.SB) == old
					if same {
						reused++
					}
					q := w.Row()
					if q != clean {
						t.Fatalf("content %q", q)
					}
					if collect {
						rows = append(rows, q)
					}
					if taint.IsTaintedString(q) {
						fp++
						if !same {
							fpNoReuse++
						}
						if execs == 0 {
							taint.VisitString(q, func(rg taint.Range) bool {
								t.Logf("attempt %d: clean query %q carries range start=%d len=%d source=%s:%s value=%q",
									i, q, rg.Start, rg.Length, rg.Source.Origin, rg.Source.Name, rg.Source.Value)
								return true
							})
							execs++
							if _, err := db.ExecContext(ctx, q); err != nil {
								t.Error(err)
							}
						}
					}
				}
				runtime.KeepAlive(rows)
			}, url.Values{"id": {param}})
			sqli := countType(event, constants.VulnerabilityTypeSqlInjection)
			t.Logf("mode=%s attempts=%d backingAddressReused=%d staleTaintedClean=%d staleWithoutReuse=%d SQLiReports=%d", mode, attempts, reused, fp, fpNoReuse, sqli)
			for _, v := range event.Vulnerabilities {
				t.Logf("REPORTED %s evidence=%+v", v.Type, v.Evidence)
			}
			for _, s := range event.Sources {
				t.Logf("REPORTED source=%+v", s)
			}
			if fp > 0 || sqli > 0 {
				t.Errorf("BUG: clean server-side query reported as SQL injection from stale builder taint (fp=%d, reports=%d)", fp, sqli)
			}
		})
	}
}
