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

// FX-F1 public-surface reproducer: two live request owners. Request B rebuilds
// a tainted string through the public strings.Builder wrappers; concurrently
// request A writes CLEAN data into its own unrelated bytes.Buffer through the
// public wrappers. If A's receiver lookups can poison B's owner, B's builder
// results silently lose their taint. FX_F1_NO_A=1 runs the single-request
// control.
func TestFxF1CrossRequestBuilderTaintWipedByUnrelatedBuffer(t *testing.T) {
	taintedB := activeStringSource(t, "b", "attacker-input-value")
	if os.Getenv("FX_F1_NO_A") == "" {
		_ = activeStringSource(t, "a", "unused")
	}

	var stop atomic.Bool
	var aWrites atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if os.Getenv("FX_F1_NO_A") != "" {
			return
		}
		var buf bytes.Buffer
		for !stop.Load() {
			propagation.BufferWriteString(&buf, "clean-")
			if buf.Len() > 1024 {
				propagation.BufferReset(&buf)
			}
			aWrites.Add(1)
		}
	}()

	const ops = 300
	lost := 0
	var b strings.Builder
	for i := 0; i < ops; i++ {
		propagation.BuilderReset(&b)
		propagation.BuilderWriteString(&b, taintedB)
		for j := 0; j < 40; j++ {
			propagation.BuilderWriteByte(&b, 'y')
		}
		if !taint.IsTaintedString(propagation.BuilderString(&b)) {
			lost++
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("FX-F1: ops=%d lost-taint=%d A-unrelated-buffer-writes=%d", ops, lost, aWrites.Load())
	if lost > 0 {
		t.Errorf("BUG: request B lost builder taint on %d/%d checks while unrelated request A wrote clean data into its own buffer", lost, ops)
	}
}
