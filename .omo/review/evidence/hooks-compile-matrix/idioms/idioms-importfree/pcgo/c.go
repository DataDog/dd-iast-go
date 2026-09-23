package pcgo

/*
#include <stdlib.h>
#include <string.h>
static char* hello(void) { return strdup("hello-cgo"); }
*/
import "C"

import "unsafe"

func Hello(suffix string) string {
	p := C.hello()
	defer C.free(unsafe.Pointer(p))
	s := C.GoString(p)
	b := C.GoBytes(unsafe.Pointer(p), 5)
	cs := C.CString(s + suffix)
	defer C.free(unsafe.Pointer(cs))
	return s + suffix + string(b) + C.GoString(cs)[1:]
}
