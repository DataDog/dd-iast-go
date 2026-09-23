// Allocation fidelity for operator wrappers with IAST inactive (review node
// hooks-fidelity-strings). Native non-escaping string(b) / a+b of short
// results use a stack buffer; the wrappers force a heap allocation.

package propagation_test

import (
	"testing"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

var allocSink int

//go:noinline
func nativeConv(b []byte) int { s := string(b); return len(s) + int(s[0]) }

//go:noinline
func wrappedConv(b []byte) int { s := iastprop.BytesToString(b); return len(s) + int(s[0]) }

//go:noinline
func nativeConcat(a, b string) int { s := a + b; return len(s) + int(s[0]) }

//go:noinline
func wrappedConcat(a, b string) int { s := iastprop.Concat2(a, b); return len(s) + int(s[0]) }

func TestFidelityInactiveAllocations(t *testing.T) {
	if request.ActiveStore() != nil {
		t.Fatal("expected inactive IAST")
	}
	b := []byte("0123456789abcdef")
	a, c := "hello ", "world"
	results := map[string]float64{
		"native string(b)":   testing.AllocsPerRun(1000, func() { allocSink += nativeConv(b) }),
		"BytesToString(b)":   testing.AllocsPerRun(1000, func() { allocSink += wrappedConv(b) }),
		"native a+b":         testing.AllocsPerRun(1000, func() { allocSink += nativeConcat(a, c) }),
		"Concat2(a,b)":       testing.AllocsPerRun(1000, func() { allocSink += wrappedConcat(a, c) }),
	}
	for k, v := range results {
		t.Logf("ALLOCS %-20s %.1f", k, v)
	}
}
