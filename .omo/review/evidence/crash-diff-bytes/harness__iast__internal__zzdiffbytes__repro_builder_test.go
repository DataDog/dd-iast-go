package zzdiffbytes

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

// TestReproBuilderStaleTaintRealistic uses only ordinary customer idioms: a
// direct WriteString of request data, a zero-value reinitialisation of the
// holder, fmt.Fprintf through io.Writer, and a direct String call.
func TestReproBuilderStaleTaintRealistic(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	for _, size := range []int{16, 48, 40000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			setupConfig(t)
			const iterations = 40
			reuse, fp := 0, 0
			for i := 0; i < iterations; i++ {
				// One request per iteration, as in a handler.
				ctx, scope, created := request.Begin(context.Background())
				if !created {
					t.Fatal("no scope")
				}
				body := make([]byte, size)
				for k := range body {
					body[k] = 'a' + byte(k%26)
				}
				param := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"}, string(body))
				cleanRow := strings.Repeat("c", size)

				type rowWriter struct{ sb strings.Builder }
				w := &rowWriter{}
				w.sb.WriteString(param) // woven direct write of tainted data
				old := uintptr(unsafe.Pointer(unsafe.SliceData((*bldInternal)(unsafe.Pointer(&w.sb)).buf)))
				// The handler keeps reusing the holder for clean rows; every
				// row reinitialises it and formats through io.Writer.
				var query string
				var cur uintptr
				for retry := 0; retry < 100; retry++ {
					*w = rowWriter{} // ordinary zero-value reinitialisation
					runtime.GC()
					fmt.Fprintf(&w.sb, "%s", cleanRow) // io.Writer path, not wrapped
					cur = uintptr(unsafe.Pointer(unsafe.SliceData((*bldInternal)(unsafe.Pointer(&w.sb)).buf)))
					if cur == old {
						break
					}
				}
				query = w.sb.String() // woven direct String
				if cur == old {
					reuse++
				}
				if taint.IsTaintedString(query) {
					fp++
					if fp == 1 {
						var got []taint.Range
						taint.VisitString(query, func(r taint.Range) bool { got = append(got, r); return true })
						src := got[0].Source.Value
						if len(src) > 24 {
							src = src[:24] + "..."
						}
						t.Logf("iteration %d: FALSE POSITIVE: clean value %q... (len %d, all 'c') tainted with range start=%d len=%d source=%s:%s value=%q",
							i, query[:8], len(query), got[0].Start, got[0].Length, got[0].Source.Source.Origin, got[0].Source.Source.Name, src)
					}
				}
				scope.Finish()
			}
			t.Logf("size=%d iterations=%d backingAddressReused=%d falsePositives=%d", size, iterations, reuse, fp)
			if fp > 0 {
				t.Errorf("clean strings.Builder content reported tainted %d/%d times", fp, iterations)
			}
		})
	}
}
