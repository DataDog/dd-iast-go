package reviewfxoperators

import "testing"

func TestLenDoesNotEvaluateArrayElement(t *testing.T) {
	s := "abc"
	high := 99
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("len evaluated the array element: %v", recovered)
		}
	}()

	if got := len([1]string{s[:high]}); got != 1 {
		t.Fatalf("len([1]string{...}) = %d, want 1", got)
	}
}

func TestRangeDoesNotEvaluateArrayElement(t *testing.T) {
	s := "abc"
	high := 99
	iterations := 0
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("range evaluated the array element: %v", recovered)
		}
	}()

	for range [1]string{s[:high]} {
		iterations++
	}
	if iterations != 1 {
		t.Fatalf("array range iterations = %d, want 1", iterations)
	}
}
