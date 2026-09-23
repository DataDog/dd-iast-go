package jsonbridge

import (
	"reflect"
	"sync/atomic"
	"testing"
)

// Mirrors encoding/json: Decoder.Decode binds (reader, &dec.d), d.init publishes
// the document, then decodeState.unmarshal binds (nil, &dec.d) again before literalStore.
func TestReviewNestedBindCreatesDuplicateSlotAndDropsDocument(t *testing.T) {
	owners, values := new(atomic.Uint64), new(atomic.Int32)
	owners.Store(1)
	values.Store(1)
	defer BindActiveOwners(BindActiveOwners(owners))
	defer BindActiveValues(BindActiveValues(values))
	clone := []byte(`{"value":"tainted"}`)
	var seen []byte
	Register(
		func(any, []byte) []byte { return clone },
		func(document, _ []byte, _ reflect.Value, _ error) { seen = document },
	)
	defer registered.Store(nil)

	states := new([129]uint64) // index 0, 64, 128 share one start bucket
	reader := states
	other, ours := &states[0], &states[64]
	data := []byte(`{"value":"tainted"}`)

	if !Bind(reader, other) { // another request's Decode occupies probe 0
		t.Fatal("bind other")
	}
	if !Bind(reader, ours) { // our Decode lands on probe 1
		t.Fatal("bind ours")
	}
	Document(ours, data)  // d.init: clone mapping stored on our slot
	Unbind(other)         // the other Decode returns while ours blocks in Read
	if !Bind(nil, ours) { // decodeState.unmarshal nested bind
		t.Fatal("nested bind")
	}
	count, pointers, depths := ReviewOccupied()
	t.Logf("occupied=%d pointers=%#x depths=%v (ours=%#x)", count, pointers, depths, pointerOf(ours))
	Literal(ours, data, data[9:18], reflect.Value{}, nil, false)
	Unbind(ours)
	Unbind(ours)
	after, _, _ := ReviewOccupied()
	t.Logf("literal callback document is clone: %v (document=%p clone=%p data=%p); occupied after both unbinds=%d", len(seen) > 0 && &seen[0] == &clone[0], seen, clone, data, after)
	if len(seen) == 0 || &seen[0] != &clone[0] {
		t.Errorf("BUG: nested Bind claimed a freed earlier probe instead of the existing slot; Literal lost the decoder document mapping")
	}
}
