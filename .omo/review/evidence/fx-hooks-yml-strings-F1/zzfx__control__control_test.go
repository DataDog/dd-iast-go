package control

import "testing"

func TestBuild(t *testing.T) {
	if got := Build("a,b"); got != "a;b!" {
		t.Fatalf("Build = %q", got)
	}
}
