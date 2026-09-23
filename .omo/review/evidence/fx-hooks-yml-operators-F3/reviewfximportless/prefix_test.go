package reviewfximportless_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/reviewfximportless"
)

func TestPrefixWithoutImports(t *testing.T) {
	if got := reviewfximportless.Prefix("hello"); got != "hello!" {
		t.Fatalf("Prefix returned %q, want %q", got, "hello!")
	}
}
