package fxconstctx

import "testing"

func TestConstCtx(t *testing.T) {
	if ConstLenSlice("xy") != 1 || ConstLenConcat("a", "b") != 1 || ArraySizeFromLen([]byte("xy")) != 1 {
		t.Fatal("unexpected")
	}
}
