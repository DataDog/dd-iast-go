package unsafeonly

import "unsafe"

var _ = unsafe.Sizeof(0)

func Hello(name string) string { return "hello, " + name }
