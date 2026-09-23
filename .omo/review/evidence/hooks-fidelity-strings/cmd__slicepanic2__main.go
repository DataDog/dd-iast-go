// Reproducer (review node hooks-fidelity-strings): with a compile-time-known
// sub-word unsigned index, gc's native out-of-range slice panic reports a
// wrong index ([:0]); the generic wrapper reports the real index ([:200]).
package main

import (
	"fmt"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
)

func pv(f func()) (msg string) {
	defer func() { msg = fmt.Sprint(recover()) }()
	f()
	return
}

//go:noinline
func nativeU8(s string) string { var i uint8 = 200; return s[:i] }

//go:noinline
func wrappedU8(s string) string { var i uint8 = 200; return iastprop.StringSliceHigh(s, i) }

//go:noinline
func nativeU8Low(s string) string { var i uint8 = 200; return s[i:] }

//go:noinline
func wrappedU8Low(s string) string { var i uint8 = 200; return iastprop.StringSliceLow(s, i) }

//go:noinline
func nativeU16(s string) string { var i uint16 = 60000; return s[:i] }

//go:noinline
func wrappedU16(s string) string { var i uint16 = 60000; return iastprop.StringSliceHigh(s, i) }

//go:noinline
func nativeB8(b []byte) []byte { var i uint8 = 200; return b[:i] }

//go:noinline
func wrappedB8(b []byte) []byte { var i uint8 = 200; return iastprop.BytesSliceHigh(b, i) }

//go:noinline
func nativeI8(s string) string { var i int8 = -3; return s[i:] }

//go:noinline
func wrappedI8(s string) string { var i int8 = -3; return iastprop.StringSliceLow(s, i) }

func main() {
	s, b := "abc", []byte("abc")
	for _, c := range []struct {
		name         string
		native, wrap func()
	}{
		{"string[:uint8 const]", func() { nativeU8(s) }, func() { wrappedU8(s) }},
		{"string[uint8 const:]", func() { nativeU8Low(s) }, func() { wrappedU8Low(s) }},
		{"string[:uint16 const]", func() { nativeU16(s) }, func() { wrappedU16(s) }},
		{"bytes[:uint8 const]", func() { nativeB8(b) }, func() { wrappedB8(b) }},
		{"string[int8 const:]", func() { nativeI8(s) }, func() { wrappedI8(s) }},
	} {
		n, w := pv(c.native), pv(c.wrap)
		mark := "SAME"
		if n != w {
			mark = "DIFF"
		}
		fmt.Printf("%s %-24s native=%q wrapper=%q\n", mark, c.name, n, w)
	}
}
