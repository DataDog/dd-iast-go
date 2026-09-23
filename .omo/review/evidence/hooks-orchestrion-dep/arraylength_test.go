package review_operator_arraylength

import "testing"

func TestArrayLengthLeavesSliceUnevaluated(t *testing.T) {
	value := "abc"
	length := len([1]string{value[99:]})
	if length != 1 {
		t.Fatalf("unexpected array length %d", length)
	}
}
