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
)

// ResetForTest empties the store and the counters, so a test does not depend on
// what the tests before it left behind. It restores the same state when the
// test ends.
func ResetForTest(t testing.TB) {
	t.Helper()
	reset := func() {
		store.Clear()
		entries.Store(0)
		open.Store(0)
		refuseUntil.Store(0)
		nextTrim.Store(0)
	}
	reset()
	t.Cleanup(reset)
}

// SetClosedEntryBudgetForTest changes the budget of closed entries.
func SetClosedEntryBudgetForTest(t testing.TB, budget int64) {
	t.Helper()
	previous := closedEntryBudget
	closedEntryBudget = budget
	t.Cleanup(func() { closedEntryBudget = previous })
}

// SetRefuseWindowForTest changes how long annotations are refused.
func SetRefuseWindowForTest(t testing.TB, window time.Duration) {
	t.Helper()
	previous := refuseWindow
	refuseWindow = window
	t.Cleanup(func() { refuseWindow = previous })
}

// StoreStateForTest returns the number of entries and of open annotations.
func StoreStateForTest() (entryCount, openCount int64) {
	return entries.Load(), open.Load()
}

// StoreSizeForTest returns the number of entries that the map holds.
func StoreSizeForTest() int { return store.Size() }

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
