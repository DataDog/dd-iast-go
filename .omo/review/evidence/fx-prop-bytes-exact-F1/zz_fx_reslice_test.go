package propagation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// TestFxResliceBeyondLen checks ByteWindow for windows that stay inside the
// input's capacity (and the managed root) but extend past len(input). Every
// case uses a fresh root so that no identical (pointer, length) key was
// derived earlier.
func TestFxResliceBeyondLen(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	type tc struct {
		name string
		make func(short []byte) []byte
	}
	cases := []tc{
		{"control short[1:3]", func(b []byte) []byte { return b[1:3] }},
		{"short[:5]", func(b []byte) []byte { return b[:5] }},
		{"short[1:6]", func(b []byte) []byte { return b[1:6] }},
		{"short[1:6:7]", func(b []byte) []byte { return b[1:6:7] }},
		{"short[:8]", func(b []byte) []byte { return b[:8] }},
	}
	failed := 0
	for _, c := range cases {
		root, _ := taintBytes(t, owner, []byte("SELECT-x"), []ranges.Range{{Start: 1, Length: 6, SourceID: 9, Marks: 4}})
		short := root[:3:8]
		propagation.ByteWindow(root, short)
		out := c.make(short)
		propagation.ByteWindow(short, out)
		got := lookupByteRanges(s, out)
		str := propagation.BytesToString(out, string(out))
		gotStr := lookupRanges(s, str)
		t.Logf("%-19s short=%v out=%q len=%d cap=%d byteRanges=%v stringRanges=%v",
			c.name, lookupByteRanges(s, short), out, len(out), cap(out), got, gotStr)
		if len(got) == 0 || len(gotStr) == 0 {
			failed++
		}
	}
	// Growing-token lexer pattern: tok = tok[:len(tok)+1].
	root, _ := taintBytes(t, owner, []byte("xxSELECT"), []ranges.Range{{Length: 8, SourceID: 10}})
	tok := root[2:4]
	propagation.ByteWindow(root, tok)
	t.Logf("token start %q ranges=%v", tok, lookupByteRanges(s, tok))
	for len(tok) < 6 {
		next := tok[:len(tok)+1]
		propagation.ByteWindow(tok, next)
		tok = next
	}
	t.Logf("grown token %q ranges=%v", tok, lookupByteRanges(s, tok))
	if len(lookupByteRanges(s, tok)) == 0 {
		failed++
	}
	if failed > 0 {
		t.Fatalf("FX-REPRO: %d reslice(s) within capacity lost all provenance", failed)
	}
}
