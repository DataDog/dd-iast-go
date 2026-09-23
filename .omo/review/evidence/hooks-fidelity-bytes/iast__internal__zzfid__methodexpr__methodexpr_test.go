package methodexpr

import "testing"

func TestMethodExpr(t *testing.T) {
	if got := BufferViaMethodExpr("abc"); got != "abc" {
		t.Fatalf("buffer: %q", got)
	}
	if got := BuilderViaMethodExpr("abc"); got != "abc" {
		t.Fatalf("builder: %q", got)
	}
}
