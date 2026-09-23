package reviewf2

import "testing"

func TestLimits(t *testing.T) {
	if Truncate("abc") != "abc" || string(Header([]byte("abcd"))) != "ab" || Mid("abcd") != "bc" {
		t.Fatal("wrong")
	}
}
