package buffer

import "testing"

func TestBuild(t *testing.T) {
	if got := Build("abc"); got != "abc" {
		t.Fatalf("Build = %q", got)
	}
}
