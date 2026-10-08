// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

// The operations of the tests. Each one is //go:noinline, so the compiler
// cannot fold it into the test or change its escape result.

// ---- heap operations: the result escapes, so the runtime gets buf == nil ----

//go:noinline
func heapConcat2(a, b string) string { return a + b }

//go:noinline
func heapConcat3(a, b, c string) string { return a + b + c }

//go:noinline
func heapConcat6(a, b, c, d, e, f string) string { return a + b + c + d + e + f }

//go:noinline
func heapConcatBytes(a, b string) []byte { return []byte(a + b) }

//go:noinline
func heapB2S(b []byte) string { return string(b) }

//go:noinline
func heapS2B(s string) []byte { return []byte(s) }

//go:noinline
func heapR2S(r []rune) string { return string(r) }

//go:noinline
func heapS2R(s string) []rune { return []rune(s) }

// heapGrow appends one byte to b (len(b) == cap(b)): growslice copies the
// old elements to a new heap array.
//
//go:noinline
func heapGrow(b []byte) []byte { return append(b[:len(b):len(b)], '!') }

// heapGrowUint32 appends one element to v (len(v) == cap(v)).
//
//go:noinline
func heapGrowUint32(v []uint32) []uint32 { return append(v[:len(v):len(v)], 0xffffffff) }

// heapGrowStrings appends one element to v: the element type has pointers,
// so growslice does not copy taint bits.
//
//go:noinline
func heapGrowStrings(v []string) []string { return append(v[:len(v):len(v)], "x") }

// markCap taints all of b[:cap(b)]. It does not leak b (the compiler can
// keep a stack backing store for the slice of the caller).
//
//go:noinline
func markCap(b []byte) bool { return taintBytesNoLeak(bytesData(b), cap(b)) }

// bufGrow appends n bytes to a slice that uses a stack backing store
// (growsliceBuf). After 40 bytes (more than the stack buffer: the backing
// store is now on the heap), markCap taints the backing store, and the slice
// becomes its last 2 bytes, with len == cap. The next append calls
// growsliceBuf with tainted old elements on the heap: without the hook, it
// copies them to the stack buffer (the taint is lost).
//
//go:noinline
func bufGrow(n int) []byte {
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, 'a'+byte(i%26))
		if len(out) == 40 {
			markCap(out)
			out = out[cap(out)-2 : cap(out)]
		}
	}
	return out
}

// ---- stack operations: the result stays in the function, so the runtime
// gets a stack buffer. Only a probe leaves the function. A tainted result
// proves that the hook forced it to the heap: stack memory has no taint bits.
// The tests check "stays on the stack" with testing.AllocsPerRun: an address
// test is not reliable, because the runtime allocates goroutine stacks from
// the same arena as the heap. ----

//go:noinline
func stackConcat(a, b string) probe {
	s := a + b
	return probe{anyTainted(stringData(s), len(s))}
}

//go:noinline
func stackConcatBytes(a, b string) probe {
	s := []byte(a + b)
	return probe{anyTainted(bytesData(s), len(s))}
}

//go:noinline
func stackB2S(b []byte) probe {
	s := string(b)
	return probe{anyTainted(stringData(s), len(s))}
}

//go:noinline
func stackS2B(s string) probe {
	b := []byte(s)
	b[0] ^= 0 // a write: the compiler must copy (no zero-copy alias)
	return probe{anyTainted(bytesData(b), len(b))}
}

//go:noinline
func stackR2S(r []rune) probe {
	s := string(r)
	return probe{anyTainted(stringData(s), len(s))}
}

//go:noinline
func stackS2R(s string) probe {
	r := []rune(s)
	return probe{anyTainted(runesData(r), 4*len(r))}
}

// split is the taint of the two parts of a result: [0, k) and [k, n), in bytes
// of the result.
type split struct {
	head, tail bool
}

func splitOf(p uintptr, k, n int) split {
	return split{anyTainted(p, k), anyTainted(p+uintptr(k), n-k)}
}

// Stack operations that return the taint of the two parts of the result. k
// is the split point, in bytes of the operand (in runes for the rune
// operand). The rune result uses 4 bytes for each rune.

//go:noinline
func stackConcatSplit(a, b string) split {
	s := a + b
	return splitOf(stringData(s), len(a), len(s))
}

//go:noinline
func stackConcatBytesSplit(a, b string) split {
	s := []byte(a + b)
	return splitOf(bytesData(s), len(a), len(s))
}

//go:noinline
func stackB2SSplit(b []byte, k int) split {
	s := string(b)
	return splitOf(stringData(s), k, len(s))
}

//go:noinline
func stackS2BSplit(s string, k int) split {
	b := []byte(s)
	b[0] ^= 0 // a write: the compiler must copy (no zero-copy alias)
	return splitOf(bytesData(b), k, len(b))
}

//go:noinline
func stackR2SSplit(r []rune, k int) split {
	s := string(r) // ASCII runes: one byte for each rune
	return splitOf(stringData(s), k, len(s))
}

//go:noinline
func stackS2RSplit(s string, k int) split {
	r := []rune(s) // ASCII: one rune for each byte
	return splitOf(runesData(r), 4*k, 4*len(r))
}

// Stack operations that return only a length, for testing.AllocsPerRun.

//go:noinline
func stackConcatLen(a, b string) int { s := a + b; return len(s) }

//go:noinline
func stackConcatBytesLen(a, b string) int { s := []byte(a + b); s[0] ^= 0; return len(s) }

//go:noinline
func stackB2SLen(b []byte) int { s := string(b); return len(s) }

//go:noinline
func stackS2BLen(s string) int { b := []byte(s); b[0] ^= 0; return len(b) }

//go:noinline
func stackR2SLen(r []rune) int { s := string(r); return len(s) }

//go:noinline
func stackS2RLen(s string) int { r := []rune(s); return len(r) }

// stackBufGrowLen appends n bytes to a slice with a stack backing store
// (growsliceBuf), and returns the length only.
//
//go:noinline
func stackBufGrowLen(n int) int {
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, byte(i))
		sinkInt += cap(out)
	}
	return len(out)
}
