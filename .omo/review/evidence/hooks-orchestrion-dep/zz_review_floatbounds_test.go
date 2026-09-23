package propagation_test

import "testing"

func TestReviewIntegralUntypedFloatBound(t *testing.T) {
	value := "abc"
	if got := value[1.0:]; got != "bc" {
		t.Fatalf("unexpected slice %q", got)
	}
}
