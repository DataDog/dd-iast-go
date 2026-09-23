package propagation_test

import (
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/taint"
)

// A strings.Builder written through the wrapper, then reset and refilled
// outside supported hooks (zero-value assignment + io.Writer-style direct
// writes), reuses the freed backing address after GC. Builder views keep no
// anchor, so the stale (pointer,len,cap) view matches and the clean result is
// reported tainted.
func TestReviewBuilderABAStaleTaint(t *testing.T) {
	input := activeString(t, strings.Repeat("A", 24))
	var b strings.Builder
	propagation.BuilderWriteString(&b, input)
	if !taint.IsTaintedString(propagation.BuilderString(&b)) {
		t.Fatal("control: tracked builder should be tainted")
	}
	p := uintptr(unsafe.Pointer(unsafe.StringData(b.String())))
	l, c := b.Len(), b.Cap()
	b = strings.Builder{} // unwrapped reset (not a supported hook)
	runtime.GC()
	runtime.GC()
	clean := strings.Repeat("c", 24)
	keep := make([]string, 0, 1<<16)
	found := -1
	for i := 0; i < 1<<16; i++ {
		b = strings.Builder{}
		b.WriteString(clean) // direct call: not woven, like fmt.Fprintf(&b, ...)
		if uintptr(unsafe.Pointer(unsafe.StringData(b.String()))) == p && b.Len() == l && b.Cap() == c {
			found = i
			break
		}
		keep = append(keep, b.String())
	}
	runtime.KeepAlive(keep)
	if found < 0 {
		t.Skip("allocator did not reuse the address")
	}
	result := propagation.BuilderString(&b)
	t.Logf("address reused after %d attempts; result=%q tainted=%v", found, result, taint.IsTaintedString(result))
	if result != clean {
		t.Fatalf("unexpected content %q", result)
	}
	if taint.IsTaintedString(result) {
		t.Errorf("BUG: clean builder content reported tainted from stale writer state (ABA on unanchored builder view)")
	}
}
