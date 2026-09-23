// Probe: Go runtime behaviours that break naive address-keyed taint identity.
// Each line prints whether two distinct logical values share a data address.
package main

import (
	"fmt"
	"strings"
	"unsafe"
)

//go:noinline
func oneByte(b []byte, i int) string { return string(b[i : i+1]) }

//go:noinline
func concat(a, b string) string { return a + b }

//go:noinline
func isolated(value string) string { // copy of research isolatedString (registry.go:185-193)
	if len(value) == 0 {
		return ""
	}
	buffer := make([]byte, len(value)+1)
	copy(buffer, value)
	withSentinel := string(buffer)
	return withSentinel[:len(value)]
}

var sink []string

func main() {
	secret := []byte("attacker")
	clean := []byte("a")
	// 1. single-byte []byte->string conversions are interned in runtime.staticuint64s.
	s1 := oneByte(secret, 0) // "a" derived from tainted input
	s2 := oneByte(clean, 0)  // "a" from clean input
	sink = append(sink, s1, s2)
	fmt.Println("1-byte conversion shares address:", unsafe.StringData(s1) == unsafe.StringData(s2))

	// 2. concatenation with an empty operand returns the other operand unchanged.
	t := string(secret)
	c := concat("", t)
	sink = append(sink, c, t) // t escapes: heap-resident operand
	fmt.Println("\"\"+s aliases s:", unsafe.StringData(c) == unsafe.StringData(t))

	// 3. strings.TrimSpace / Cut return views into the input backing array.
	v := strings.TrimPrefix(t, "att")
	fmt.Println("TrimPrefix result is interior view:", uintptr(unsafe.Pointer(unsafe.StringData(v)))-uintptr(unsafe.Pointer(unsafe.StringData(t))) == 3)

	// 4. research isolatedString defeats (1): the +1 sentinel forces a >=2 byte allocation.
	i1 := isolated(s1)
	i2 := isolated(s2)
	sink = append(sink, i1, i2)
	fmt.Println("isolatedString 1-byte results share address:", unsafe.StringData(i1) == unsafe.StringData(i2))

	// 5. tiny allocator: two small noscan allocations can be adjacent in one 16-byte block.
	a := isolated("ab")
	b := isolated("cd")
	sink = append(sink, a, b)
	d := int64(uintptr(unsafe.Pointer(unsafe.StringData(b)))) - int64(uintptr(unsafe.Pointer(unsafe.StringData(a))))
	fmt.Println("tiny allocs distance (bytes):", d, "same 16B block:", uintptr(unsafe.Pointer(unsafe.StringData(a)))>>4 == uintptr(unsafe.Pointer(unsafe.StringData(b)))>>4)
}
