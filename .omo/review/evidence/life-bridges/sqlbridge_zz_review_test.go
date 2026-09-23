package sqlbridge

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func reviewSetup(t *testing.T, cb func(context.Context, string, Kind)) {
	oldCallback, oldOwners := registered.Load(), activeOwners.Load()
	t.Cleanup(func() { registered.Store(oldCallback); activeOwners.Store(oldOwners) })
	var owners atomic.Uint64
	owners.Store(1)
	BindActiveOwners(&owners)
	Register(cb)
}

// Mirrors the woven shape: `defer __dd__iast_ReportSQL__(...)` prepended to a
// database/sql method whose driver panics.
func hostWithDeferredReport() (recovered any) {
	defer func() { recovered = recover() }()
	func() {
		defer Report(context.Background(), "SELECT 1", KindExec, true)
		panic("driver panic")
	}()
	return nil
}

func TestReviewDeferredReportKeepsHostPanic(t *testing.T) {
	var calls atomic.Int32
	reviewSetup(t, func(context.Context, string, Kind) { calls.Add(1) })
	got := hostWithDeferredReport()
	t.Logf("host recovered=%v callback calls=%d", got, calls.Load())
	if got != "driver panic" {
		t.Fatalf("host panic swallowed or replaced: %v", got)
	}
}

func TestReviewPanickingCallbackDuringHostPanic(t *testing.T) {
	reviewSetup(t, func(context.Context, string, Kind) { panic("callback panic") })
	got := hostWithDeferredReport()
	t.Logf("host recovered=%v", got)
	if got != "driver panic" {
		t.Fatalf("host panic swallowed or replaced: %v", got)
	}
}

func TestReviewConcurrentRegisterAndReport(t *testing.T) {
	reviewSetup(t, func(context.Context, string, Kind) {})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				Register(func(context.Context, string, Kind) {})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				Report(context.Background(), "q", KindQuery, true)
			}
		}()
	}
	wg.Wait()
}
