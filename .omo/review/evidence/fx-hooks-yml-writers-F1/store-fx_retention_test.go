package store

import (
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// TestFxInteriorViewAnchorRetainsBacking measures retained heap, not charged
// bytes: eight writers anchored into interior views of 16 MiB caller
// allocations must retain the whole allocations while charging only the
// visible capacity, and owner finish must release them.
func TestFxInteriorViewAnchorRetainsBacking(t *testing.T) {
	s := New()
	owner := s.Acquire()
	input := writerInput(t, 6, ranges.Range{Length: 6, SourceID: 1})
	runtime.GC()
	var before, mid, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for index := 0; index < MaxWriters; index++ {
		backing := make([]byte, 16<<20)
		view := anchoredWriterView(backing[:16:16], 0, 6)
		if !owner.UpdateWriter(&writerObject{id: index}, WriterBytesBuffer, WriterView{}, view, &input, 6, 6) {
			t.Fatalf("writer %d failed admission", index)
		}
	}
	t.Logf("store charged=%d bytes for %d writer records", owner.Charged(), owner.owner.writerCount)

	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&mid)
	retained := int64(mid.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("retained while owner active: %d MiB", retained>>20)
	if retained <= 24<<20 {
		t.Fatalf("advertised 24 MiB envelope not exceeded; retention not reproduced")
	}

	owner.Finish()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("released by owner finish: %d MiB", (int64(mid.HeapAlloc)-int64(after.HeapAlloc))>>20)
	if int64(mid.HeapAlloc)-int64(after.HeapAlloc) < retained-(8<<20) {
		t.Fatalf("retained memory not released by owner finish")
	}
}
