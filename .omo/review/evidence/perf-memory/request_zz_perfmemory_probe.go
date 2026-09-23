package request

import (
	"context"
	"math/bits"

	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// PerfMemoryGauges is a review-only probe (perf-memory private copy).
type PerfMemoryGauges struct {
	Initialized   bool
	PermitsUsed   int
	ProcessValues int32
	Charged       int64
	Tombstones    uint32
	OverflowFree  uint16
}

// PerfMemoryProcess returns process manager gauges.
func PerfMemoryProcess() PerfMemoryGauges {
	m := processManager.Load()
	if m == nil {
		return PerfMemoryGauges{}
	}
	st := m.store.Stats()
	return PerfMemoryGauges{
		Initialized:   true,
		PermitsUsed:   bits.OnesCount64(m.used.Load()),
		ProcessValues: m.store.ProcessValues(),
		Charged:       m.store.ProcessCharged(),
		Tombstones:    st.Tombstones,
		OverflowFree:  st.OverflowFree,
	}
}

// PerfMemoryOwner returns the live owner counters of the request in ctx.
func PerfMemoryOwner(ctx context.Context) (store.Counters, int32, int64, int, bool) {
	scope := FromContext(ctx)
	analysis, ok := scope.Analysis()
	if !ok {
		return store.Counters{}, 0, 0, 0, false
	}
	owner := analysis.storeOwner()
	if owner == nil {
		return store.Counters{}, 0, 0, 0, false
	}
	analysis.slot.sourceMu.Lock()
	sources := analysis.slot.table.Len()
	analysis.slot.sourceMu.Unlock()
	return owner.Counters(), owner.Values(), owner.Charged(), sources, true
}
