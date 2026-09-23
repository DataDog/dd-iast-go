package jsonbridge

import (
	"reflect"
	"sync/atomic"
	"testing"
)

func reviewActive(t *testing.T) {
	var owners atomic.Uint64
	owners.Store(1)
	var values atomic.Int32
	values.Store(1)
	po, pv, pc := BindActiveOwners(&owners), BindActiveValues(&values), registered.Load()
	t.Cleanup(func() { BindActiveOwners(po); BindActiveValues(pv); registered.Store(pc) })
}

// Mirrors the woven literalStore shape: deferred closure calling Literal while
// literalStore itself panics.
func TestReviewDeferredLiteralKeepsHostPanic(t *testing.T) {
	reviewActive(t)
	Register(func(any, []byte) []byte { return nil }, func([]byte, []byte, reflect.Value, error) { panic("callback panic") })
	state := new(int)
	if !Bind(nil, state) { t.Fatal("bind") }
	defer Unbind(state)
	doc := []byte(`"abc"`)
	got := func() (r any) {
		defer func() { r = recover() }()
		func() {
			defer func() { Literal(state, doc, doc, reflect.Value{}, nil, false) }()
			panic("literalStore panic")
		}()
		return nil
	}()
	t.Logf("host recovered=%v", got)
	if got != "literalStore panic" { t.Fatalf("host panic swallowed or replaced: %v", got) }
}

func TestReviewNilRegisterIsShielded(t *testing.T) {
	reviewActive(t)
	Register(nil, nil)
	t.Logf("registered non-nil holder with nil funcs: %v", registered.Load() != nil)
	state := new(int)
	if !Bind(new(int), state) { t.Fatal("bind") }
	defer Unbind(state)
	doc := []byte(`{"a":"b"}`)
	Document(state, doc)
	Literal(state, doc, doc[5:8], reflect.Value{}, nil, false)
	t.Log("no panic escaped with nil callbacks")
}
