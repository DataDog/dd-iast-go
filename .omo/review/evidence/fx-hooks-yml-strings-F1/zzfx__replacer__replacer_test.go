package replacer

import "testing"

func TestReplace(t *testing.T) {
	if got := Replace("a,b"); got != "a;b" {
		t.Fatalf("Replace = %q", got)
	}
}
