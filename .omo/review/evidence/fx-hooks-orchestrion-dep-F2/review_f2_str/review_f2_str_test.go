package review_f2_str

import "testing"

// Customer-shaped: slicing a request-derived string with integral
// untyped float constants. All three are legal Go (spec: an untyped
// constant slice bound is converted to int).
func TestFloatBoundsString(t *testing.T) {
	value := "hello, tainted world"
	if got := value[1.0:]; got != "ello, tainted world" {
		t.Fatalf("low bound: got %q", got)
	}
	if got := value[:9.0]; got != "hello, ta" {
		t.Fatalf("high bound: got %q", got)
	}
	if got := value[1.0:5.0]; got != "ello" {
		t.Fatalf("both bounds: got %q", got)
	}
}
