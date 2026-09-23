
package review_f2_bytes

import "testing"

// Byte-slice forms of the same legal integral constant bounds.
func TestFloatBoundsBytes(t *testing.T) {
    value := []byte("hello, tainted world")
    if got := string(value[1.0:]); got != "ello, tainted world" {
        t.Fatalf("low bound: got %q", got)
    }
    if got := string(value[:9.0]); got != "hello, ta" {
        t.Fatalf("high bound: got %q", got)
    }
    if got := string(value[1.0:5.0:9.0]); got != "ello" {
        t.Fatalf("full bound: got %q", got)
    }
}
