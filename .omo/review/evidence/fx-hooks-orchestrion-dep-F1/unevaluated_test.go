package fxunevaluated

import (
	"testing"
	"unsafe"
)

func noPanic(t *testing.T, f func() int, want int) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC (native Go would not evaluate operand): %v", r)
		}
	}()
	if got := f(); got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

var short = "abc"
var shortBytes = []byte("ab")

// Spec: len/cap of an array with no calls/receives is constant; operand not evaluated.
func TestLenArrayLiteralStringSlice(t *testing.T) {
	noPanic(t, func() int { return len([1]string{short[99:]}) }, 1)
}

func TestCapArrayLiteralByteSlice(t *testing.T) {
	noPanic(t, func() int { return cap([2][]byte{shortBytes[5:], nil}) }, 2)
}

// Slice-to-array-pointer conversion is not a function call: len is constant 4.
func TestLenArrayPointerConversion(t *testing.T) {
	noPanic(t, func() int { return len((*[4]byte)(shortBytes[1:])) }, 4)
}

// Spec: range over constant-len array with <=1 iteration var does not evaluate x.
func TestRangeArrayNotEvaluated(t *testing.T) {
	noPanic(t, func() int {
		n := 0
		for i := range [2]string{short[99:], ""} {
			n += i + 1
		}
		return n
	}, 3)
}

// Control: unsafe.Sizeof stays constant even with a call inside; expected no change.
func TestSizeofControl(t *testing.T) {
	noPanic(t, func() int { return int(unsafe.Sizeof(short[99:])) }, int(unsafe.Sizeof("")))
}
