package request

import "math/bits"

// SoakGauges is a review-only probe (life-soak private copy).
type SoakGauges struct {
	PermitsUsed   int
	ProcessValues int32
	Charged       int64
	AcquireDrops  uint64
	Tombstones    uint32
	OverflowFree  uint16
	LiveSlots     int
}

// SoakStats returns process manager gauges, or zero before first sampled request.
func SoakStats() SoakGauges {
	m := processManager.Load()
	if m == nil {
		return SoakGauges{}
	}
	st := m.store.Stats()
	live := 0
	for i := range m.slots {
		if m.slots[i].active.Load() {
			live++
		}
	}
	return SoakGauges{
		PermitsUsed:   bits.OnesCount64(m.used.Load()),
		ProcessValues: m.store.ProcessValues(),
		Charged:       m.store.ProcessCharged(),
		AcquireDrops:  m.store.AcquireDrops(),
		Tombstones:    st.Tombstones,
		OverflowFree:  st.OverflowFree,
		LiveSlots:     live,
	}
}
