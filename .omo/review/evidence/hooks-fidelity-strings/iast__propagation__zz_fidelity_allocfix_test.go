// Proposed-fix probe (review node hooks-fidelity-strings): evaluate the native
// operation inside the inactive fast path so that, once inlined, escape
// analysis can keep a non-escaping result on the stack.

package propagation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/operatorbridge"
	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

func fixedConcat2[T ~string](a, b T) T {
	if !operatorbridge.HasValues() {
		return a + b
	}
	return T(internal.Concat2(string(a), string(b), string(a+b)))
}

func fixedBytesToString[T ~[]byte](value T) string {
	if !operatorbridge.HasValues() {
		return string(value)
	}
	return internal.BytesToString([]byte(value), string(value))
}

//go:noinline
func fixedConv(b []byte) int { s := fixedBytesToString(b); return len(s) + int(s[0]) }

//go:noinline
func fixedConcat(a, b string) int { s := fixedConcat2(a, b); return len(s) + int(s[0]) }

func TestFidelityInactiveAllocationsProposedFix(t *testing.T) {
	if request.ActiveStore() != nil {
		t.Fatal("expected inactive IAST")
	}
	b := []byte("0123456789abcdef")
	a, c := "hello ", "world"
	t.Logf("ALLOCS %-20s %.1f", "fixed BytesToString", testing.AllocsPerRun(1000, func() { allocSink += fixedConv(b) }))
	t.Logf("ALLOCS %-20s %.1f", "fixed Concat2", testing.AllocsPerRun(1000, func() { allocSink += fixedConcat(a, c) }))
}
