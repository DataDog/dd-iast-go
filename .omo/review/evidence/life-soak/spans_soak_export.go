package spans

// SoakStats is a review-only probe (life-soak private copy).
func SoakStats() (annotations int, eventSourceBytes int64, ownerBindings int) {
	for i := range ownerSpans {
		if ownerSpans[i].Load() != nil {
			ownerBindings++
		}
	}
	return store.Size(), processEventSourceBytes.Load(), ownerBindings
}
