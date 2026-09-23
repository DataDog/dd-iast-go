package store

import (
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func TestReviewBufferAnchorsExceedAdvertisedMemoryCeiling(t *testing.T) {
	s := New()
	owner := s.Acquire()
	defer owner.Finish()
	input := writerInput(t, 6, ranges.Range{Length: 6, SourceID: 1})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for index := 0; index < MaxWriters; index++ {
		backing := make([]byte, 16<<20)
		view := anchoredWriterView(backing[:16:16], 0, 6)
		if !owner.UpdateWriter(&writerObject{id: index}, WriterBytesBuffer, WriterView{}, view, &input, 6, 6) {
			t.Fatalf("writer %d failed admission", index)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("live heap increase=%d MiB, store charged=%d bytes, writer records=%d", retained>>20, owner.Charged(), owner.owner.writerCount)
	if retained > 24<<20 {
		t.Fatalf("advertised 24 MiB footprint exceeded by retained buffer allocations")
	}
}
