package spans

import (
	"runtime"
	"testing"
	"weak"
)

func TestPerfGCWeakMakeAndValueDoNotAllocate(t *testing.T) {
	target := new(int)

	allocations := testing.AllocsPerRun(1_000, func() {
		pointer := weak.Make(target)
		if pointer.Value() == nil {
			t.Fatal("weak pointer unexpectedly lost its live target")
		}
	})

	runtime.KeepAlive(target)
	if allocations != 0 {
		t.Fatalf("weak.Make plus Value allocations = %v, want 0", allocations)
	}
}
