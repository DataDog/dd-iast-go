package jsonbridge

import (
	"reflect"
	"sync/atomic"
	"testing"
)

// Literal runs from a deferred closure inside decodeState.literalStore. If
// literalStore panics, the deferred Literal runs during panicking; its shield
// must not swallow the host panic.
func TestReviewDeferredLiteralDoesNotSwallowHostPanic(t *testing.T) {
	var owners atomic.Uint64
	owners.Store(1)
	var values atomic.Int32
	values.Store(1)
	prevO := BindActiveOwners(&owners)
	prevV := BindActiveValues(&values)
	defer BindActiveOwners(prevO)
	defer BindActiveValues(prevV)
	called := false
	Register(func(any, []byte) []byte { return nil }, func([]byte, []byte, reflect.Value, error) { called = true; panic("callback panic") })
	state := new(int)
	host := func() {
		defer func() { Literal(state, []byte(`"ab"`), []byte(`"ab"`), reflect.Value{}, nil, false) }()
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
