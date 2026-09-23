package zzreview

import (
	"fmt"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
)

var sink int

//go:noinline
func conv(b []byte) int {
	s := string(b) // woven: string(iastprop.BytesToString(b))
	return len(s) + int(s[0])
}

//go:noinline
func concatConv(b []byte) int {
	s := "p" + string(b) // woven: iastprop.Concat2("p", string(b))
	return len(s) + int(s[0])
}

//go:noinline
func concatPlain(a, b string) int {
	s := a + b // woven: iastprop.Concat2(a, b)
	return len(s) + int(s[0])
}

func TestReviewWovenAllocs(t *testing.T) {
	fmt.Printf("WOVEN built.WithOrchestrion=%v\n", built.WithOrchestrion)
	b := []byte("0123456789abcdef")
	x, y := "SELECT ", "1"
	fmt.Printf("WOVEN-ALLOCS s:=string(b)        %.0f\n", testing.AllocsPerRun(1000, func() { sink += conv(b) }))
	fmt.Printf("WOVEN-ALLOCS s:=\"p\"+string(b)  %.0f\n", testing.AllocsPerRun(1000, func() { sink += concatConv(b) }))
	fmt.Printf("WOVEN-ALLOCS s:=a+b              %.0f\n", testing.AllocsPerRun(1000, func() { sink += concatPlain(x, y) }))
}
