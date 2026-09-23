package floatbounds

import "testing"

func TestIntegralUntypedBounds(t *testing.T) {
	s := "abcd"
	if s[1.0:3.0] != "bc" || s[complex(1, 0):3] != "bc" {
		t.Fatal("integral untyped bounds")
	}
	b := []byte("abcd")
	if string(b[1.0:3.0:4.0]) != "bc" {
		t.Fatal("integral untyped byte bounds")
	}
}
