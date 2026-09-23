package taint

import (
	"strings"
	"testing"
)

// Review repro (res-runtime): bytes left beyond len() after a clean overwrite keep
// their old address ranges; ReadFrom from an arbitrary reader then re-reads them
// through postRanges (buffer.go:152) and republishes the stale taint.
func Test_ReviewStaleCapacityTaint(t *testing.T) {
	active = newRegistryLifecycle()
	t.Cleanup(func() { active = newRegistryLifecycle() })

	b := NewBuffer(make([]byte, 0, 4096)) // no reallocation on ReadFrom (MinRead=512)
	if _, err := BufferWriteString(b, SourceString("SECRETSECRET")); err != nil { // 12 tainted bytes
		t.Fatal(err)
	}
	t.Logf("after source write ranges = %#v", RangesBytes(b.Bytes()))
	_ = BufferNext(b, b.Len())                         // consume everything
	_, _ = BufferRead(b, make([]byte, 1))               // empty buffer: bytes.Buffer.Read calls b.Reset() internally (uninstrumented), off=0
	if _, err := BufferWriteString(b, "cleanclean"); err != nil { // 10 clean bytes, same backing
		t.Fatal(err)
	}
	if r := RangesBytes(b.Bytes()); len(r) != 0 {
		t.Fatalf("after clean write ranges = %#v", r)
	}
	t.Logf("vacated-capacity ranges (b.Bytes()[:12]) = %#v", RangesBytes(b.Bytes()[:12]))
	if _, err := BufferReadFrom(b, strings.NewReader("xy")); err != nil { // clean, arbitrary reader
		t.Fatal(err)
	}
	got := BufferString(b)
	ranges := RangesString(got)
	t.Logf("value=%q ranges=%#v", got, ranges)
	if len(ranges) != 0 {
		t.Fatalf("clean data reported tainted: %q ranges=%#v", got, ranges)
	}
}
