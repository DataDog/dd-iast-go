
package review_f2_complex

import "testing"

// An integral untyped complex constant is also a legal slice bound.
func TestComplexBoundString(t *testing.T) {
    value := "hello, tainted world"
    if got := value[1.0+0i:]; got != "ello, tainted world" {
        t.Fatalf("complex low bound: got %q", got)
    }
}
