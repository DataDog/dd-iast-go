package spans

// PerfMemoryStats is a review-only probe (perf-memory private copy).
func PerfMemoryStats() (annotations int, eventSourceBytes int64, ownerBindings int) {
	for i := range ownerSpans {
		if ownerSpans[i].Load() != nil {
			ownerBindings++
		}
	}
	return store.Size(), processEventSourceBytes.Load(), ownerBindings
}
