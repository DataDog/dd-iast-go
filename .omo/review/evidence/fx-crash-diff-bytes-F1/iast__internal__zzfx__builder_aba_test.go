package zzfx

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

type builderLayout struct {
	addr *strings.Builder
	buf  []byte
}

// Read the backing directly: b.String() is woven here and may return a clone.
func backing(b *strings.Builder) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData((*builderLayout)(unsafe.Pointer(b)).buf)))
}

// Each variant: tracked tainted write through a woven direct call, then one
// "reset" step, then a clean refill through io.Writer/io.StringWriter (inside
// the stdlib, never woven), then a woven direct String().
type variant struct {
	name  string
	reset func(sb *strings.Builder)
	fill  func(sb *strings.Builder, clean string)
}

var variants = []variant{
	{"zero-assign+io.WriteString", func(sb *strings.Builder) { *sb = strings.Builder{} }, func(sb *strings.Builder, c string) { io.WriteString(sb, c) }},
	{"methodvalue-Reset+fmt.Fprint", func(sb *strings.Builder) { r := sb.Reset; r() }, func(sb *strings.Builder, c string) { fmt.Fprint(sb, c) }},
	// Control: a woven direct Reset must invalidate the record, so reuse is harmless.
	{"CONTROL-direct-Reset+io.WriteString", func(sb *strings.Builder) { sb.Reset() }, func(sb *strings.Builder, c string) { io.WriteString(sb, c) }},
}

func TestFxBuilderABA(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	defer func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm }()

	for _, v := range variants {
		for _, size := range []int{24, 200} {
			t.Run(fmt.Sprintf("%s/%d", v.name, size), func(t *testing.T) {
				const requests = 20
				reused, fpReused, fpNotReused := 0, 0, 0
				for i := 0; i < requests; i++ {
					ctx, scope, ok := request.Begin(context.Background())
					if !ok {
						t.Fatal("no request scope")
					}
					q := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestQuery, Name: "q"}, strings.Repeat("x", size))
					var sb strings.Builder
					sb.WriteString(q) // woven BuilderWriteString
					if !taint.IsTaintedString(sb.String()) {
						t.Fatal("control: tracked builder String() should be tainted")
					}
					old, oldCap := backing(&sb), sb.Cap()
					clean := strings.Repeat("c", size)
					hit := false
					v.reset(&sb)
					runtime.GC()
					var pinned [][]byte // keep non-matching refills alive so the allocator walks to the freed slot
					for try := 0; try < 1<<14 && !hit; try++ {
						if try > 0 {
							pinned = append(pinned, (*builderLayout)(unsafe.Pointer(&sb)).buf)
							v.reset(&sb)
						}
						v.fill(&sb, clean)
						hit = backing(&sb) == old && sb.Cap() == oldCap
					}
					runtime.KeepAlive(pinned)
					got := sb.String() // woven BuilderString
					if got != clean {
						t.Fatalf("content mismatch %q", got)
					}
					tainted := taint.IsTaintedString(got)
					if hit {
						reused++
					}
					switch {
					case tainted && hit:
						fpReused++
						if fpReused == 1 {
							var src string
							taint.VisitString(got, func(r taint.Range) bool {
								src = fmt.Sprintf("start=%d len=%d origin=%s name=%s", r.Start, r.Length, r.Source.Source.Origin, r.Source.Source.Name)
								return false
							})
							t.Logf("request %d: FALSE POSITIVE clean %q tainted: %s (backing 0x%x reused)", i, got[:8], src, old)
						}
					case tainted:
						fpNotReused++
					}
					scope.Finish()
				}
				t.Logf("RESULT variant=%s size=%d requests=%d addressReused=%d falsePositiveWhenReused=%d falsePositiveWithoutReuse=%d",
					v.name, size, requests, reused, fpReused, fpNotReused)
			})
		}
	}
}
