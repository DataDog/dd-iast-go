package store

import "sync/atomic"

// ReviewFault is a SCRATCH fault-injection switch for the phase-3 review only.
// 1 = panic before any lock; 2 = panic while holding lifecycleMu.RLock + writersMu.
var ReviewFault atomic.Int32

// ReviewFaultValue is the injected panic value.
var ReviewFaultValue = &struct{ origin string }{"injected fault inside Store.InvalidateBuffer"}
