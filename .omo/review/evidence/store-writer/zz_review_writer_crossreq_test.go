package propagation_test

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/taint"
)

// Request B builds a tainted string with a strings.Builder through the public
// wrappers. Concurrently, request A's goroutine writes CLEAN data into its own,
// unrelated bytes.Buffer through the public wrappers. A's receiver lookup
// poisons B's owner (writerDirty) whenever it races B's writer critical
// section, and B's builder result silently loses its taint.
func TestReviewCrossRequestWriterPoisoning(t *testing.T) {
	tainted := activeStringSource(t, "b", "attacker")
	_ = activeStringSource(t, "a", "unused") // second live request owner (A)
	var stop atomic.Bool
	var wg sync.WaitGroup
	var aWrites atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		if os.Getenv("REVIEW_NO_A") != "" {
			return
		}
		var buf bytes.Buffer
		for !stop.Load() {
			propagation.BufferWriteString(&buf, "clean-data")
			if buf.Len() > 4096 {
				propagation.BufferReset(&buf)
			}
			aWrites.Add(1)
		}
	}()
	// 400 checks keep request B below its 512-root / 2 MiB budget, since every
	// tainted BuilderString publishes one new root.
	const ops = 400
	lost := 0
	var b strings.Builder
	for i := 0; i < ops; i++ {
		propagation.BuilderReset(&b)
		propagation.BuilderWriteString(&b, tainted)
		for j := 0; j < 50; j++ {
			propagation.BuilderWriteByte(&b, 'x')
		}
		if !taint.IsTaintedString(propagation.BuilderString(&b)) {
			lost++
		}
	}
	stop.Store(true)
	wg.Wait()
	_ = strings.Repeat
	t.Logf("B builder checks=%d lost-taint=%d; A clean buffer writes=%d", ops, lost, aWrites.Load())
	if lost > 0 {
		t.Errorf("BUG: request B lost builder taint %d/%d times due to request A's unrelated buffer writes", lost, ops)
	}
}
