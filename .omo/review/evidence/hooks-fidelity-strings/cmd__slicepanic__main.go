// Reproducer (review node hooks-fidelity-strings): out-of-range slice panic
// messages differ between a native slice expression and the generic
// iast/propagation slice wrappers for sub-word index types.
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

func report(name string, native, wrapped func()) {
	n, w := pv(native), pv(wrapped)
	mark := "SAME"
	if n != w {
		mark = "DIFF"
	}
	fmt.Printf("%s %-22s native=%q wrapper=%q\n", mark, name, n, w)
}

func main() {
	s := "abc"
	b := []byte("abc")
	var u8 uint8 = 200
	var u16 uint16 = 60000
	var u32 uint32 = 4000000000
	var i8 int8 = -3
	var i16 int16 = 30000
	var u uint = 1 << 40
	var i int = 200
	report("string[:uint8]", func() { _ = s[:u8] }, func() { _ = iastprop.StringSliceHigh(s, u8) })
	report("string[uint8:]", func() { _ = s[u8:] }, func() { _ = iastprop.StringSliceLow(s, u8) })
	report("string[:uint16]", func() { _ = s[:u16] }, func() { _ = iastprop.StringSliceHigh(s, u16) })
	report("string[:uint32]", func() { _ = s[:u32] }, func() { _ = iastprop.StringSliceHigh(s, u32) })
	report("string[int8:]", func() { _ = s[i8:] }, func() { _ = iastprop.StringSliceLow(s, i8) })
	report("string[:int16]", func() { _ = s[:i16] }, func() { _ = iastprop.StringSliceHigh(s, i16) })
	report("string[:uint]", func() { _ = s[:u] }, func() { _ = iastprop.StringSliceHigh(s, u) })
	report("string[:int]", func() { _ = s[:i] }, func() { _ = iastprop.StringSliceHigh(s, i) })
	report("bytes[:uint8]", func() { _ = b[:u8] }, func() { _ = iastprop.BytesSliceHigh(b, u8) })
	report("bytes[u8:u8:u8]", func() { _ = b[1:2:u8] }, func() { _ = iastprop.BytesSliceFull(b, 1, 2, u8) })
	report("bytes[:uint16]", func() { _ = b[:u16] }, func() { _ = iastprop.BytesSliceHigh(b, u16) })
	report("bytes[int8:]", func() { _ = b[i8:] }, func() { _ = iastprop.BytesSliceLow(b, i8) })
}
