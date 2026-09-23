package propagation_test

import (
	"fmt"
	"testing"

	iastpropagation "github.com/DataDog/dd-iast-go/iast/propagation"
)

var reviewSink int

// nativeConv is what the customer wrote: `s := string(b)` whose result does not escape.
//
//go:noinline
func nativeConv(b []byte) int {
	s := string(b)
	return len(s) + int(s[0])
}

// wovenConv is the exact shape produced by the "operator bytes to string conversion" aspect:
// '{{ .AST.Fun }}(iastprop.BytesToString({{ index .AST.Args 0 }}))'.
//
//go:noinline
func wovenConv(b []byte) int {
	s := string(iastpropagation.BytesToString(b))
	return len(s) + int(s[0])
}

//go:noinline
func nativeConcat(a, b string) int {
	s := a + b
	return len(s) + int(s[0])
}

//go:noinline
func wovenConcat(a, b string) int {
	s := iastpropagation.Concat2(a, b)
	return len(s) + int(s[0])
}

// nativeConcatConv: `"p" + string(b)`; the conversion is compiler-optimized (unwrapped
// by design) but the concat chain is woven to Concat2("p", string(b)).
//
//go:noinline
func nativeConcatConv(b []byte) int {
	s := "p" + string(b)
	return len(s) + int(s[0])
}

//go:noinline
func wovenConcatConv(b []byte) int {
	s := iastpropagation.Concat2("p", string(b))
	return len(s) + int(s[0])
}

// No request is active and IAST is not sampling: the woven code should cost
// the same allocations as the native code.
func TestReviewWovenAllocationsWithoutActiveRequest(t *testing.T) {
	b := []byte("SELECT * FROM users WHERE id=1")
	a, c := "SELECT * FROM t ", "WHERE id=1"
	res := map[string]float64{
		"native string(b)":           testing.AllocsPerRun(1000, func() { reviewSink += nativeConv(b) }),
		"woven BytesToString":        testing.AllocsPerRun(1000, func() { reviewSink += wovenConv(b) }),
		"native a+b":                 testing.AllocsPerRun(1000, func() { reviewSink += nativeConcat(a, c) }),
		"woven Concat2":              testing.AllocsPerRun(1000, func() { reviewSink += wovenConcat(a, c) }),
		"native \"p\"+string(b)":     testing.AllocsPerRun(1000, func() { reviewSink += nativeConcatConv(b[:16]) }),
		"woven Concat2(p,string(b))": testing.AllocsPerRun(1000, func() { reviewSink += wovenConcatConv(b[:16]) }),
	}
	for _, k := range []string{"native string(b)", "woven BytesToString", "native a+b", "woven Concat2", "native \"p\"+string(b)", "woven Concat2(p,string(b))"} {
		fmt.Printf("ALLOCS %-28s %.0f\n", k, res[k])
	}
}
