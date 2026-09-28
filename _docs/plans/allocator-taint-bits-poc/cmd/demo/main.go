package main

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"example.com/allocbits/heapbits"
)

func main() {
	fmt.Println("available:", heapbits.Available())
	s := strings.Repeat("abcdefgh", 8) // 64 bytes, heap
	fmt.Println("taint heap:", heapbits.TaintString(s))
	fmt.Println("whole:", heapbits.IsTainted(s), "substr:", heapbits.IsTainted(s[10:20]))
	var arr [16]byte
	fmt.Println("taint stack:", heapbits.TaintBytes(arr[:]))
	fmt.Println("taint global:", heapbits.TaintString("literal"))
	b := []byte(s)
	fmt.Printf("s=%#x b=%#x arr=%#x\n", uintptr(unsafe.Pointer(unsafe.StringData(s))), uintptr(unsafe.Pointer(unsafe.SliceData(b))), uintptr(unsafe.Pointer(&arr)))
	fmt.Println("copy tainted (expected false):", heapbits.IsTaintedBytes(b))
	heapbits.TaintBytes(b[4:6])
	fmt.Println("b[0:4]", heapbits.IsTaintedBytes(b[0:4]), "b[3:5]", heapbits.IsTaintedBytes(b[3:5]), "b[6:]", heapbits.IsTaintedBytes(b[6:]))
	heapbits.ClearBytes(b)
	fmt.Println("after clear:", heapbits.IsTaintedBytes(b))
	runtime.GC()
	bm, sw := heapbits.Stats()
	fmt.Println("bitmaps:", bm, "sweeps:", sw)
}
