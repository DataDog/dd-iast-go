// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"testing"
	"time"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/puzpuzpuz/xsync/v4"
)

// ResetForTest empties the store and the counters, so a test does not depend on
// what the tests before it left behind. It restores the same state when the
// test ends.
func ResetForTest(t testing.TB) {
	t.Helper()
	reset := func() {
		store.Clear()
		orphans.Clear()
		refusedOrphans.Store(0)
		entries.Store(0)
		open.Store(0)
		refuseUntil.Store(0)
		nextTrim.Store(0)
	}
	reset()
	t.Cleanup(reset)
}

func SetClosedEntryBudgetForTest(t testing.TB, budget int64) {
	t.Helper()
	previous := closedEntryBudget
	closedEntryBudget = budget
	t.Cleanup(func() { closedEntryBudget = previous })
}

func SetRefuseWindowForTest(t testing.TB, window time.Duration) {
	t.Helper()
	previous := refuseWindow
	refuseWindow = window
	t.Cleanup(func() { refuseWindow = previous })
}

func StoreStateForTest() (entryCount, openCount int64) {
	return entries.Load(), open.Load()
}

func StoreSizeForTest() int { return store.Size() }

func OrphanCountForTest() int { return orphans.Size() }

func OrphanRegistryStatsForTest() xsync.MapStats { return orphans.Stats() }

func StoreLimitForTest() int64 { return storeLimit() }

func RefusedOrphansForTest() int64 { return refusedOrphans.Load() }

func RefusingForTest() bool { return refusing() }

func RefuseUntilForTest() int64 { return refuseUntil.Load() }

func SetOrphanIDSourceForTest(t testing.TB, source func() uint64) {
	t.Helper()
	previous := drawOrphanID
	drawOrphanID = source
	t.Cleanup(func() { drawOrphanID = previous })
}

func ReplaceOrphanEntryForTest(o *Orphan) {
	orphans.Store(o.key, &Orphan{key: o.key})
}

func AddOrphanKeyForTest(span *tracer.Span, id uint64) {
	key := orphanKey{span, id}
	orphans.Store(key, &Orphan{key: key})
}

func ReplaceOrphanSpanForTest(o *Orphan, span *tracer.Span) {
	orphans.Delete(o.key)
	o.key = orphanKey{span, span.Context().SpanID()}
	orphans.Store(o.key, o)
}

func SetOrphanSpanStarterForTest(t testing.TB, start func(string, ...tracer.StartSpanOption) *tracer.Span) {
	t.Helper()
	previous := startOrphanSpan
	startOrphanSpan = start
	t.Cleanup(func() { startOrphanSpan = previous })
}

func SetRefusedOrphanBudgetForTest(t testing.TB, budget int64) {
	t.Helper()
	previous := refusedOrphanBudget
	refusedOrphanBudget = budget
	t.Cleanup(func() { refusedOrphanBudget = previous })
}

// ConfigureForTest sets the capacity and the sampling rate, enables IAST, and
// resets the store. Everything is restored when the test ends.
func ConfigureForTest(t testing.TB, capacity, samplingPct int) {
	t.Helper()
	previousCapacity, previousPct := config.MaxConcurrentRequests, config.RequestSamplingPct
	previousVulns, previousDedup := config.VulnerabilitiesPerRequest, config.DeduplicationEnabled
	previousEnabled := config.Enabled
	config.MaxConcurrentRequests, config.RequestSamplingPct = capacity, samplingPct
	config.VulnerabilitiesPerRequest, config.DeduplicationEnabled = 100000, false
	config.Enabled = true
	ResetForTest(t)
	t.Cleanup(func() {
		config.MaxConcurrentRequests, config.RequestSamplingPct = previousCapacity, previousPct
		config.VulnerabilitiesPerRequest, config.DeduplicationEnabled = previousVulns, previousDedup
		config.Enabled = previousEnabled
	})
}

// InsertEntryOfUnreferencedSpanForTest adds an entry and returns the only strong reference to its span.
func InsertEntryOfUnreferencedSpanForTest(id uint64, isOpen bool) *tracer.Span {
	span := new(tracer.Span)
	entries.Add(1)
	if isOpen {
		open.Add(1)
		store.Store(weak.Make(span), &Annotation{Sampled: true, spanID: id})
	} else {
		store.Store(weak.Make(span), newTombstone(id))
	}
	return span
}

// InsertStaleEntryForTest adds, for span, the entry of an earlier span (one
// that had the same memory, and another identifier).
func InsertStaleEntryForTest(span *tracer.Span) *Annotation {
	stale := newTombstone(span.Context().SpanID() + 1)
	entries.Add(1)
	store.Store(weak.Make(span), stale)
	return stale
}

// TrimForTest scans the store for the entries of spans that no longer exist.
func TrimForTest() {
	nextTrim.Store(0)
	trimStore()
}
