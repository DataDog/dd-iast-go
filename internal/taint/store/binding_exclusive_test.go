// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"bytes"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// The tests of this file check the reader binding rules in the package doc.

func TestBindingSizes(t *testing.T) {
	// exclusive, viaGuard, inputs, and demoted use the padding after kind.
	// Rule (d) reads the type word from the object interface, thus it adds
	// no field. The entry index of rule (e) uses the padding of OwnerRef.
	// The creation baselines of rule (f) are in bindingTable.readerExpect
	// (8 bytes for each reader binding), not in binding or OwnerRef.
	require.Equal(t, uintptr(32), unsafe.Sizeof(binding{}))
	require.Equal(t, uintptr(24), unsafe.Sizeof(OwnerRef{}))
	require.Equal(t, uintptr(9), unsafe.Sizeof(readerInputs{}))
}

func lookupReader(t *testing.T, s *Store, object any, size int) ([]OwnerRef, bool) {
	t.Helper()
	out := make([]OwnerRef, size)
	count, complete := LookupReaderValue(s, object, out)
	return out[:count], complete
}

func TestReaderBindingExclusiveFlag(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	exclusive := strings.NewReader("exclusive")
	shared := strings.NewReader("shared")
	require.True(t, BindReaderValue(owner, exclusive, true, false))
	require.True(t, BindObjectValue(owner, shared, BindingReader))

	refs, complete := lookupReader(t, s, exclusive, 4)
	require.True(t, complete)
	require.Len(t, refs, 1)
	require.True(t, refs[0].Exclusive)
	require.False(t, refs[0].ViaGuard)
	require.Equal(t, BindingReader, refs[0].Kind)

	refs, complete = lookupReader(t, s, shared, 4)
	require.True(t, complete)
	require.Len(t, refs, 1)
	require.False(t, refs[0].Exclusive, "BindObjectValue makes a non-exclusive reader binding")

	// A rebind keeps exclusive only when the old and the new binding are
	// both exclusive.
	require.True(t, BindReaderValue(owner, exclusive, false, false))
	refs, _ = lookupReader(t, s, exclusive, 4)
	require.False(t, refs[0].Exclusive, "exclusive must be old && new")
	require.True(t, BindReaderValue(owner, exclusive, true, false))
	refs, _ = lookupReader(t, s, exclusive, 4)
	require.False(t, refs[0].Exclusive, "a non-exclusive binding cannot become exclusive again")

	// A rebind keeps viaGuard when one of the bindings has it.
	guarded := strings.NewReader("guarded")
	require.True(t, BindReaderValue(owner, guarded, true, true))
	require.True(t, BindReaderValue(owner, guarded, true, false))
	refs, _ = lookupReader(t, s, guarded, 4)
	require.True(t, refs[0].Exclusive)
	require.True(t, refs[0].ViaGuard)

	// A URL binding is never exclusive, and a kind change sets the new flag.
	url := strings.NewReader("url")
	require.True(t, BindObjectValue(owner, url, BindingURL))
	var urlRefs [1]OwnerRef
	require.Equal(t, 1, LookupObjectValue(s, url, BindingURL, urlRefs[:]))
	require.False(t, urlRefs[0].Exclusive)
	require.True(t, BindReaderValue(owner, url, true, false))
	refs, _ = lookupReader(t, s, url, 4)
	require.True(t, refs[0].Exclusive, "a kind change from URL to reader sets the new value")
}

func TestReaderLookupIsIncompleteOnContention(t *testing.T) {
	s := New()
	first, second := s.Acquire(), s.Acquire()
	t.Cleanup(first.Finish)
	t.Cleanup(second.Finish)
	reader := strings.NewReader("body")
	require.True(t, BindReaderValue(first, reader, true, false))

	for name, lock := range map[string]*sync.RWMutex{
		"lifecycle":     &second.owner.lifecycleMu,
		"binding table": &second.owner.bindings.mu,
	} {
		t.Run(name, func(t *testing.T) {
			lock.Lock()
			refs, complete := lookupReader(t, s, reader, 4)
			lock.Unlock()
			// The contended owner has no binding of reader, but the
			// lookup cannot know it.
			require.False(t, complete)
			require.Len(t, refs, 1)
			refs, complete = lookupReader(t, s, reader, 4)
			require.True(t, complete)
			require.Len(t, refs, 1)
		})
	}
}

func TestReaderLookupIsIncompleteOnFanoutOverflow(t *testing.T) {
	s := New()
	first, second := s.Acquire(), s.Acquire()
	t.Cleanup(first.Finish)
	t.Cleanup(second.Finish)
	reader := strings.NewReader("body")
	require.True(t, BindReaderValue(first, reader, true, false))
	require.True(t, BindReaderValue(second, reader, true, false))
	refs, complete := lookupReader(t, s, reader, 1)
	require.False(t, complete)
	require.Len(t, refs, 1)
	require.Equal(t, uint64(1), second.Counters().Fanout)
	refs, complete = lookupReader(t, s, reader, 2)
	require.True(t, complete)
	require.Len(t, refs, 2)
	_, complete = lookupReader(t, s, reader, 0)
	require.False(t, complete, "an empty output cannot hold a result")
}

func TestReaderLookupOfUnboundValues(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	for name, object := range map[string]any{
		"nil":           nil,
		"typed nil":     (*strings.Reader)(nil),
		"non-pointer":   strings.Reader{},
		"unbound":       strings.NewReader("clean"),
		"zero-size ptr": &struct{}{},
	} {
		refs, complete := lookupReader(t, s, object, 4)
		require.True(t, complete, name)
		require.Empty(t, refs, name)
	}
	count, complete := LookupReaderValue(nil, strings.NewReader("x"), make([]OwnerRef, 1))
	require.Zero(t, count)
	require.True(t, complete)
}

// body is a custom request body type. Its first field has the address of the
// body itself.
type body struct {
	Buffer bytes.Buffer
	extra  int
}

func (b *body) Read(p []byte) (int, error) { return b.Buffer.Read(p) }

func TestReaderIdentityIsTypeAndAddress(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	value := &body{}
	value.Buffer.WriteString("unrelated")
	require.Equal(t, unsafe.Pointer(value), unsafe.Pointer(&value.Buffer))
	require.True(t, BindReaderValue(a, value, true, false))

	refs, complete := lookupReader(t, s, &value.Buffer, 4)
	require.True(t, complete)
	require.Empty(t, refs, "a lookup of the first field must not find the binding of the struct")
	var typed [1]OwnerRef
	require.Zero(t, LookupObject(s, &value.Buffer, typed[:]))
	require.Equal(t, 1, LookupObject(s, value, typed[:]))

	// The two identities are two different bindings.
	require.True(t, BindReaderValue(b, &value.Buffer, false, false))
	refs, _ = lookupReader(t, s, value, 4)
	require.Len(t, refs, 1)
	require.True(t, refs[0].Exclusive)
	_, _, id, ok := refs[0].Identity()
	require.True(t, ok)
	require.Equal(t, a.ID(), id)
	refs, _ = lookupReader(t, s, &value.Buffer, 4)
	require.Len(t, refs, 1)
	require.False(t, refs[0].Exclusive)
	_, _, id, _ = refs[0].Identity()
	require.Equal(t, b.ID(), id)

	// One owner can bind both identities.
	require.True(t, BindReaderValue(a, &value.Buffer, true, false))
	refs, _ = lookupReader(t, s, value, 4)
	require.Len(t, refs, 1)
	func() {
		table := &a.owner.bindings
		table.mu.RLock()
		defer table.mu.RUnlock()
		require.Equal(t, uint8(2), table.readerCount)
	}()
}

func TestRetargetedBitRemovesGuardedExclusivity(t *testing.T) {
	s := New()
	owner := s.Acquire()
	guarded := strings.NewReader("guarded")
	plain := strings.NewReader("plain")
	require.True(t, BindReaderValue(owner, guarded, true, true))
	require.True(t, BindReaderValue(owner, plain, true, false))
	index, ok := owner.Index()
	require.True(t, ok)

	MarkRetargeted(s, index, owner.Generation()+1)
	refs, _ := lookupReader(t, s, guarded, 4)
	require.True(t, refs[0].Exclusive, "a stale generation must not set the bit")
	require.Zero(t, owner.Counters().Retargets)

	MarkRetargeted(s, index, owner.Generation())
	refs, _ = lookupReader(t, s, guarded, 4)
	require.False(t, refs[0].Exclusive)
	require.True(t, refs[0].ViaGuard)
	refs, _ = lookupReader(t, s, plain, 4)
	require.True(t, refs[0].Exclusive, "the bit does not change a binding without a guard")
	require.Equal(t, uint64(1), owner.Counters().Retargets)

	MarkRetargeted(nil, index, owner.Generation())
	MarkRetargeted(s, MaxOwners, owner.Generation())
	owner.Finish()

	// A new generation of the slot clears the bit.
	var reused *Owner
	for range MaxOwners {
		candidate := s.Acquire()
		if slot, _ := candidate.Index(); slot == index {
			reused = candidate
			break
		}
		t.Cleanup(candidate.Finish)
	}
	require.NotNil(t, reused)
	t.Cleanup(reused.Finish)
	next := strings.NewReader("next")
	require.True(t, BindReaderValue(reused, next, true, true))
	refs, _ = lookupReader(t, s, next, 4)
	require.True(t, refs[0].Exclusive)
	require.Zero(t, reused.Counters().Retargets)
}

func TestRecordGuardDrop(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	owner.RecordGuardDrop()
	require.Equal(t, uint64(1), owner.Counters().GuardFull)
	var disabled *Owner
	disabled.RecordGuardDrop()
}

// bindDerived binds output exclusively to owner, with inputs as its inputs,
// as the request package does after a complete lookup of each input.
func bindDerived(t *testing.T, s *Store, owner *Owner, output any, inputs ...any) bool {
	t.Helper()
	refs := make([]OwnerRef, len(inputs))
	for i, input := range inputs {
		found, complete := lookupReader(t, s, input, 2)
		require.True(t, complete)
		require.Len(t, found, 1)
		refs[i] = found[0]
	}
	return BindDerivedReaderValue(owner, output, false, inputs, refs)
}

func requireExclusive(t *testing.T, s *Store, object any, want bool) {
	t.Helper()
	refs, complete := lookupReader(t, s, object, 4)
	require.True(t, complete)
	require.NotEmpty(t, refs)
	require.Equal(t, want, len(refs) == 1 && refs[0].Exclusive)
}

// TestDerivedReaderBindingRevalidatesInputs checks reader binding rule (e).
func TestDerivedReaderBindingRevalidatesInputs(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	body, other := strings.NewReader("body"), strings.NewReader("other")
	require.True(t, BindReaderValue(a, body, true, false))
	require.True(t, BindReaderValue(a, other, true, false))
	tee, multi, outer := new(strings.Reader), new(strings.Reader), new(strings.Reader)
	require.True(t, bindDerived(t, s, a, tee, body))
	require.True(t, bindDerived(t, s, a, multi, other, tee, other))
	require.True(t, bindDerived(t, s, a, outer, multi))
	requireExclusive(t, s, tee, true)
	requireExclusive(t, s, multi, true)
	requireExclusive(t, s, outer, true)
	set := func(object any) readerInputs {
		table := &a.owner.bindings
		table.mu.RLock()
		defer table.mu.RUnlock()
		position, found := table.find(uintptr(unsafe.Pointer(object.(*strings.Reader))), typeWord(object))
		require.True(t, found)
		require.NotZero(t, table.entries[position].inputs)
		return table.inputs[table.entries[position].inputs-1]
	}
	require.Equal(t, uint8(2), set(multi).count, "a repeated input is recorded once")

	// A second owner of the root input removes the exclusivity of each
	// binding over it, and of no other binding.
	require.True(t, BindReaderValue(b, body, true, false))
	requireExclusive(t, s, body, false)
	requireExclusive(t, s, tee, false)
	requireExclusive(t, s, multi, false)
	requireExclusive(t, s, outer, false)
	requireExclusive(t, s, other, true)
}

func TestBindDerivedReaderValueRejectsBadProofs(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	body, shared, bodyB := strings.NewReader("body"), strings.NewReader("shared"), strings.NewReader("body B")
	require.True(t, BindReaderValue(a, body, true, false))
	require.True(t, BindObjectValue(a, shared, BindingReader))
	require.True(t, BindReaderValue(b, bodyB, true, false))
	refs, _ := lookupReader(t, s, body, 2)
	sharedRefs, _ := lookupReader(t, s, shared, 2)
	bRefs, _ := lookupReader(t, s, bodyB, 2)
	output := new(strings.Reader)
	for name, test := range map[string]struct {
		inputs []any
		refs   []OwnerRef
	}{
		"no input":             {},
		"length mismatch":      {inputs: []any{body, body}, refs: refs},
		"too many inputs":      {inputs: []any{body, body, body, body, body, body, body, body, body}, refs: slices.Repeat(refs, 9)},
		"ref of another owner": {inputs: []any{bodyB}, refs: bRefs},
		"non-exclusive ref":    {inputs: []any{shared}, refs: sharedRefs},
		"ref of another input": {inputs: []any{shared}, refs: refs},
		"non-pointer input":    {inputs: []any{strings.Reader{}}, refs: refs},
	} {
		require.False(t, BindDerivedReaderValue(a, output, false, test.inputs, test.refs), name)
	}
	found, _ := lookupReader(t, s, output, 2)
	require.Empty(t, found, "a rejected proof makes no binding")

	// A ref of a finished generation of the slot is rejected.
	stale := refs
	a.Finish()
	reused := s.Acquire()
	t.Cleanup(reused.Finish)
	require.True(t, BindReaderValue(reused, body, true, false))
	require.False(t, BindDerivedReaderValue(reused, output, false, []any{body}, stale))
}

// TestDerivedReaderBindingCheckLimit checks the limit of maxInputChecks input
// lookups for each lookup: a binding whose revalidation needs more lookups is
// not exclusive (a safe miss).
func TestDerivedReaderBindingCheckLimit(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	// readers[n] has the inputs readers[0] to readers[n-1]. Its
	// revalidation needs 2^n - 1 input lookups.
	readers := []any{strings.NewReader("root")}
	require.True(t, BindReaderValue(owner, readers[0], true, false))
	for n := 1; n <= 5; n++ {
		reader := new(strings.Reader)
		require.True(t, bindDerivedUnchecked(t, s, owner, reader, readers...))
		readers = append(readers, reader)
	}
	requireExclusive(t, s, readers[4], true)  // 15 lookups
	requireExclusive(t, s, readers[5], false) // 31 lookups
}

// bindDerivedUnchecked is bindDerived, with the refs of the inputs that a lookup
// with no limit finds.
func bindDerivedUnchecked(t *testing.T, s *Store, owner *Owner, output any, inputs ...any) bool {
	t.Helper()
	refs := make([]OwnerRef, len(inputs))
	for i, input := range inputs {
		pointer, ok := dynamicPointer(input)
		require.True(t, ok)
		budget := 1 << 20
		var found [2]OwnerRef
		count, complete := lookupObject(s, pointer, typeWord(input), BindingReader, found[:], &budget)
		require.True(t, complete)
		require.Equal(t, 1, count)
		require.True(t, found[0].Exclusive)
		refs[i] = found[0]
	}
	return BindDerivedReaderValue(owner, output, false, inputs, refs)
}

// TestDerivedReaderBindingInputSetsAreBounded checks that the input sets of
// rule (e) have a fixed number: a derived binding that gets no set is not
// exclusive, and the owner counts a drop.
func TestDerivedReaderBindingInputSetsAreBounded(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	root := strings.NewReader("root")
	require.True(t, BindReaderValue(owner, root, true, false))
	// Each derived binding uses one set. A kind change to URL frees the
	// reader count, but not the set.
	for range MaxReaderBindings {
		derived := new(strings.Reader)
		require.True(t, bindDerived(t, s, owner, derived, root))
		requireExclusive(t, s, derived, true)
		require.True(t, BindObjectValue(owner, derived, BindingURL))
	}
	drops := owner.Counters().Full
	last := new(strings.Reader)
	require.True(t, bindDerived(t, s, owner, last, root))
	requireExclusive(t, s, last, false)
	require.Equal(t, drops+1, owner.Counters().Full)
}

// TestDerivedReaderRebindKeepsBothProofs checks that a rebind of a derived
// binding keeps the inputs of the old and of the new proof.
func TestDerivedReaderRebindKeepsBothProofs(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	first, second := strings.NewReader("first"), strings.NewReader("second")
	require.True(t, BindReaderValue(a, first, true, false))
	require.True(t, BindReaderValue(a, second, true, false))
	output := new(strings.Reader)
	require.True(t, bindDerived(t, s, a, output, first))
	require.True(t, bindDerived(t, s, a, output, second))
	// A root rebind keeps the inputs too.
	require.True(t, BindReaderValue(a, output, true, false))
	requireExclusive(t, s, output, true)
	require.True(t, BindReaderValue(b, first, true, false))
	requireExclusive(t, s, output, false)

	// A kind change to URL and back to reader demotes the entry: it is
	// never exclusive again (rule (f)), thus a token or an input set that
	// refers to the entry cannot see a new reader binding in its place.
	changed := new(strings.Reader)
	require.True(t, bindDerived(t, s, a, changed, second))
	require.True(t, BindObjectValue(a, changed, BindingURL))
	require.True(t, BindReaderValue(a, changed, true, false))
	requireExclusive(t, s, changed, false)
}

// TestDerivedReaderBindingStaysNotExclusiveAfterSecondOwnerEnds checks that the
// loss of rule (e) is sticky: a wrapper of A over an input that a second owner
// B bound stays not exclusive after B ends. The wrapper could have read bytes
// of B while B was live.
func TestDerivedReaderBindingStaysNotExclusiveAfterSecondOwnerEnds(t *testing.T) {
	for name, bindSecond := range map[string]func(t *testing.T, b *Owner, input any){
		"bind": func(t *testing.T, b *Owner, input any) {
			require.True(t, BindReaderValue(b, input, true, false))
		},
		"non-exclusive bind": func(t *testing.T, b *Owner, input any) {
			require.True(t, BindObjectValue(b, input, BindingReader))
		},
		// A bind that fails because the table of B is locked still counts:
		// no lookup can see that B has the bytes of the input.
		"contended bind": func(t *testing.T, b *Owner, input any) {
			b.owner.bindings.mu.Lock()
			defer b.owner.bindings.mu.Unlock()
			require.False(t, BindReaderValue(b, input, true, false))
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := New()
			a, b := s.Acquire(), s.Acquire()
			t.Cleanup(a.Finish)
			t.Cleanup(b.Finish)
			body := strings.NewReader("body")
			require.True(t, BindReaderValue(a, body, true, false))
			tee, outer := new(strings.Reader), new(strings.Reader)
			require.True(t, bindDerived(t, s, a, tee, body))
			require.True(t, bindDerived(t, s, a, outer, tee))
			requireExclusive(t, s, tee, true)
			requireExclusive(t, s, outer, true)

			bindSecond(t, b, body)
			b.Finish()
			refs, complete := lookupReader(t, s, body, 4)
			require.True(t, complete)
			require.Len(t, refs, 1, "only A is bound to the input after B ended")
			requireExclusive(t, s, tee, false)
			requireExclusive(t, s, outer, false)
		})
	}
}

// TestDerivedReaderBindingProofUsesTheCounterOfTheLookup checks that the
// proof of a derived binding uses the counter value that its input lookup
// read. A bind of B after that lookup and before the derived bind removes the
// exclusivity, also after B ends.
func TestDerivedReaderBindingProofUsesTheCounterOfTheLookup(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	body := strings.NewReader("body")
	require.True(t, BindReaderValue(a, body, true, false))
	refs, complete := lookupReader(t, s, body, 2)
	require.True(t, complete)
	require.Len(t, refs, 1)
	require.True(t, BindReaderValue(b, body, true, false))
	b.Finish()
	tee := new(strings.Reader)
	require.True(t, BindDerivedReaderValue(a, tee, false, []any{body}, refs))
	requireExclusive(t, s, tee, false)
}

// TestWrapperLookupSeesBindThatStartedBeforeTheCounterRead checks the ordering
// invariant of rule (e): a reader bind adds 1 to the counter BEFORE it changes
// the table. The test stops the bind of B between these two steps. Then a
// lookup of the wrapper W of A reads the counter of the input, and stops. B
// then completes its bind and ends, and the lookup continues: its input lookup
// finds only A. The lookup read the counter while B was bound to the input,
// thus W must not be exclusive.
func TestWrapperLookupSeesBindThatStartedBeforeTheCounterRead(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	body := strings.NewReader("body")
	require.True(t, BindReaderValue(a, body, true, false))
	tee := new(strings.Reader)
	require.True(t, bindDerived(t, s, a, tee, body))
	requireExclusive(t, s, tee, true)

	bindStopped, counterRead, bEnded := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var bindOnce, lookupOnce sync.Once
	setHook(t, func(stage hookStage, _ int) bool {
		switch stage {
		case hookReaderBind:
			bindOnce.Do(func() {
				close(bindStopped)
				<-counterRead
			})
		case hookInputCounters:
			lookupOnce.Do(func() {
				close(counterRead)
				<-bEnded
			})
		}
		return false
	})

	go func() {
		defer close(bEnded)
		BindReaderValue(b, body, true, false)
		b.Finish()
	}()
	<-bindStopped
	out := make([]OwnerRef, 4)
	count, complete := LookupReaderValue(s, tee, out)
	<-bEnded
	require.True(t, complete)
	require.Equal(t, 1, count)
	require.False(t, out[0].Exclusive, "the lookup read the counter while B was bound to the input")
	requireExclusive(t, s, tee, false)
}

// collidingReader returns a new reader with the reader bind counter slot of
// object, and a different identity.
func collidingReader(t *testing.T, object any) *strings.Reader {
	t.Helper()
	pointer, ok := dynamicPointer(object)
	require.True(t, ok)
	slot := readerBindSlot(pointer, typeWord(object))
	var kept []*strings.Reader // keep the misses live, so that no address is reused
	for range 1 << 20 {
		reader := new(strings.Reader)
		if readerBindSlot(uintptr(unsafe.Pointer(reader)), typeWord(reader)) == slot {
			return reader
		}
		kept = append(kept, reader)
	}
	t.Fatalf("no reader with slot %d in %d tries", slot, len(kept))
	return nil
}

// TestReaderBindCounterSlots checks the counters of rule (e): a reader bind of
// the owner itself does not remove the exclusivity of its wrappers, also for
// the same input or for another object with the same counter. A reader bind
// of another owner of an object with the same counter as an input removes it
// (a safe miss). A URL bind does not count.
func TestReaderBindCounterSlots(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	body := strings.NewReader("body")
	require.True(t, BindReaderValue(a, body, true, false))
	tee := new(strings.Reader)
	require.True(t, bindDerived(t, s, a, tee, body))
	requireExclusive(t, s, tee, true)

	require.True(t, BindReaderValue(a, body, true, false))
	require.True(t, BindReaderValue(a, collidingReader(t, body), true, false))
	require.True(t, BindObjectValue(b, collidingReader(t, body), BindingURL))
	requireExclusive(t, s, tee, true)

	// A reader bind of B with the counter of body removes the exclusivity
	// of body too (the creation baseline of rule (f)): a safe miss.
	require.True(t, BindReaderValue(b, collidingReader(t, body), true, false))
	requireExclusive(t, s, tee, false)
	requireExclusive(t, s, body, false)
}
