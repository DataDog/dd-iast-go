package sqlbridge

import (
	"context"
	"sync/atomic"
	"testing"
)

// A deferred Report runs while the host database/sql method is panicking. Its
// internal recover must NOT swallow the host panic (callback runs and panics too).
func TestReviewDeferredReportDoesNotSwallowHostPanic(t *testing.T) {
	var owners atomic.Uint64
	owners.Store(1)
	BindActiveOwners(&owners)
	called := false
	Register(func(context.Context, string, Kind) { called = true; panic("callback panic") })
	host := func() {
		defer Report(context.Background(), "SELECT 1", KindQuery, true)
		panic("host panic")
	}
	var got any
	func() {
		defer func() { got = recover() }()
		host()
	}()
	t.Logf("callback called=%v, recovered by caller=%v", called, got)
	if got != "host panic" {
		t.Fatalf("host panic was altered or swallowed: %v", got)
	}
}
