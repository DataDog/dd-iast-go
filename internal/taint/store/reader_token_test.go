// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// The tests of this file check rule (f) of plan encoding-json-v2, section 6.5:
// a reader token takes the reader bind counter of a ROOT reader too, thus a
// consumer finds a bind of another owner that started and ended after the
// token was taken.

// takeToken returns the token of a complete lookup of object that finds
// exactly one owner.
func takeToken(t *testing.T, s *Store, object any) ReaderToken {
	t.Helper()
	refs, complete := lookupReader(t, s, object, 4)
	require.True(t, complete)
	require.Len(t, refs, 1)
	token := refs[0].ReaderToken()
	require.True(t, token.OK, "the reader has no exclusive owner")
	return token
}

// revalidate reports whether a complete lookup of object finds exactly one
// owner, and token accepts its ref.
func revalidate(t *testing.T, s *Store, token ReaderToken, object any) bool {
	t.Helper()
	refs, complete := lookupReader(t, s, object, 4)
	return complete && len(refs) == 1 && token.Revalidate(refs[0])
}

// TestReaderTokenOfRootMissesBindOfOtherOwnerThatEnded is the gap of rule
// (f): B binds the root reader X of A, the bytes of X flow while B is bound,
// and B ends. A lookup of X then finds only A, with an exclusive binding. The
// token that A took before the bytes flowed must be a miss.
func TestReaderTokenOfRootMissesBindOfOtherOwnerThatEnded(t *testing.T) {
	for name, bindSecond := range map[string]func(t *testing.T, b *Owner, input any){
		"exclusive bind": func(t *testing.T, b *Owner, input any) {
			require.True(t, BindReaderValue(b, input, true, false))
		},
		"non-exclusive bind": func(t *testing.T, b *Owner, input any) {
			require.True(t, BindObjectValue(b, input, BindingReader))
		},
		// A bind that fails because the table of B is locked still counts:
		// no lookup can see that B has the bytes of the reader.
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
			token := takeToken(t, s, body)
			require.True(t, revalidate(t, s, token, body), "no bind since the token")

			bindSecond(t, b, body)
			b.Finish()
			refs, complete := lookupReader(t, s, body, 4)
			require.True(t, complete)
			require.Len(t, refs, 1, "only A is bound to the reader after B ended")
			require.False(t, refs[0].Exclusive, "the loss of A is sticky (rule (f))")
			require.False(t, revalidate(t, s, token, body),
				"the token of A is valid after B bound the root reader and ended")
			// A new token, taken after B ended, is not OK (review 2 of
			// batch 1, finding 2): the bind of B is in the counter.
			require.False(t, refs[0].ReaderToken().OK)
		})
	}
}

// TestReaderTokenOfDerivedReaderMissesDirectBind checks rule (f) for a derived
// binding: a direct bind of the wrapper by another owner that ended is a miss
// for the token, also though the inputs of the wrapper did not change.
func TestReaderTokenOfDerivedReaderMissesDirectBind(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	body := strings.NewReader("body")
	require.True(t, BindReaderValue(a, body, true, false))
	tee := new(strings.Reader)
	require.True(t, bindDerived(t, s, a, tee, body))
	token := takeToken(t, s, tee)
	require.True(t, BindReaderValue(b, tee, true, false))
	b.Finish()
	requireExclusive(t, s, tee, false)
	require.False(t, revalidate(t, s, token, tee))
}

// TestReaderTokenKeepsOwnBinds checks that the reader binds of the owner of
// the token itself do not remove its exclusivity: a rebind of its own root, a
// derived bind over it, and a bind of another reader of the owner with the
// same counter. A bind of the owner that cannot lock its table is a safe miss.
func TestReaderTokenKeepsOwnBinds(t *testing.T) {
	s := New()
	a := s.Acquire()
	t.Cleanup(a.Finish)
	body := strings.NewReader("body")
	require.True(t, BindReaderValue(a, body, true, false))
	token := takeToken(t, s, body)

	require.True(t, BindReaderValue(a, body, true, false), "rebind of the own root")
	require.True(t, revalidate(t, s, token, body), "a rebind of the own root removed the exclusivity")
	require.True(t, bindDerived(t, s, a, new(strings.Reader), body))
	require.True(t, revalidate(t, s, token, body))
	colliding := collidingReader(t, body)
	require.True(t, BindReaderValue(a, colliding, true, false))
	require.True(t, revalidate(t, s, token, body), "a bind of the owner with the same counter removed the exclusivity")

	// A non-exclusive rebind of the own root removes the exclusive flag of
	// the binding (old && new).
	other := strings.NewReader("other")
	require.True(t, BindReaderValue(a, other, true, false))
	otherToken := takeToken(t, s, other)
	require.True(t, BindObjectValue(a, other, BindingReader))
	require.False(t, revalidate(t, s, otherToken, other))

	// A bind of the owner that cannot lock its table counts only in the
	// counter: a safe miss.
	a.owner.bindings.mu.Lock()
	require.False(t, BindReaderValue(a, body, true, false))
	a.owner.bindings.mu.Unlock()
	require.False(t, revalidate(t, s, token, body))
}

// TestReaderTokenRejectsOtherRefs checks the identity checks of
// ReaderToken.Revalidate.
func TestReaderTokenRejectsOtherRefs(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(b.Finish)
	body, bodyB, second := strings.NewReader("body"), strings.NewReader("body B"), strings.NewReader("second")
	require.True(t, BindReaderValue(a, body, true, false))
	require.True(t, BindReaderValue(a, second, true, false))
	require.True(t, BindReaderValue(b, bodyB, true, false))
	token := takeToken(t, s, body)

	require.False(t, ReaderToken{}.Revalidate(OwnerRef{}), "the zero token")
	require.False(t, revalidate(t, s, token, bodyB), "a ref of another owner")
	require.False(t, revalidate(t, s, token, second), "a ref of another binding of the owner")
	other := New()
	otherOwner := other.Acquire()
	t.Cleanup(otherOwner.Finish)
	require.True(t, BindReaderValue(otherOwner, body, true, false))
	require.Equal(t, token.Index, takeToken(t, other, body).Index)
	require.False(t, revalidate(t, other, token, body), "a ref of another store")

	// The owner ends, and its slot gets a new generation that binds the same
	// reader.
	a.Finish()
	reused := s.Acquire()
	t.Cleanup(reused.Finish)
	require.True(t, BindReaderValue(reused, body, true, false))
	require.False(t, revalidate(t, s, token, body), "a ref of a new generation of the owner slot")

	// A shared or unbound reader has no token.
	shared := strings.NewReader("shared")
	require.True(t, BindObjectValue(reused, shared, BindingReader))
	refs, _ := lookupReader(t, s, shared, 4)
	require.Len(t, refs, 1)
	require.False(t, refs[0].ReaderToken().OK)
}

// TestReaderTokenSeesBindInProgressAtCapture checks the ordering of rule (f)
// at the capture: B adds 1 to the counter and stops before it changes its
// table. The lookup of the capture then cannot read the table of B (it is
// locked), thus the lookup is incomplete and gives no token.
func TestReaderTokenSeesBindInProgressAtCapture(t *testing.T) {
	s := New()
	a, b := s.Acquire(), s.Acquire()
	t.Cleanup(a.Finish)
	t.Cleanup(b.Finish)
	body := strings.NewReader("body")
	require.True(t, BindReaderValue(a, body, true, false))
	token := takeToken(t, s, body)

	stopped, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	setHook(t, func(stage hookStage, _ int) bool {
		if stage == hookReaderBind {
			once.Do(func() {
				close(stopped)
				<-release
			})
		}
		return false
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		BindReaderValue(b, body, true, false)
		b.Finish()
	}()
	<-stopped
	refs, complete := lookupReader(t, s, body, 4)
	require.False(t, complete, "the lookup read the table of B while B was in its bind")
	require.False(t, complete && len(refs) == 1 && refs[0].ReaderToken().OK)
	close(release)
	<-done
	require.False(t, revalidate(t, s, token, body), "the bind of B started after the token")
}

// TestReaderEntryListFollowsKindChanges checks bindingTable.readers, the list
// that stampReaderBind uses: a kind change from reader to URL removes the
// entry, and a change back adds it. An own rebind of a reader that is in the
// list keeps its token valid.
func TestReaderEntryListFollowsKindChanges(t *testing.T) {
	s := New()
	a := s.Acquire()
	t.Cleanup(a.Finish)
	readers := make([]*strings.Reader, MaxReaderBindings)
	for i := range readers {
		readers[i] = strings.NewReader("reader")
		require.True(t, BindReaderValue(a, readers[i], true, false))
	}
	list := func() []uint8 {
		table := &a.owner.bindings
		table.mu.RLock()
		defer table.mu.RUnlock()
		return append([]uint8(nil), table.readers[:table.readerCount]...)
	}
	require.ElementsMatch(t, []uint8{0, 1, 2, 3, 4, 5, 6, 7}, list())
	require.False(t, BindReaderValue(a, strings.NewReader("ninth"), true, false), "the reader limit")

	require.True(t, BindObjectValue(a, readers[3], BindingURL))
	require.ElementsMatch(t, []uint8{0, 1, 2, 4, 5, 6, 7}, list())
	last := strings.NewReader("last")
	require.True(t, BindReaderValue(a, last, true, false))
	require.ElementsMatch(t, []uint8{0, 1, 2, 4, 5, 6, 7, 8}, list())
	token := takeToken(t, s, last)
	require.True(t, BindReaderValue(a, last, true, false))
	require.True(t, revalidate(t, s, token, last))

	require.True(t, BindObjectValue(a, last, BindingURL))
	require.True(t, BindReaderValue(a, readers[3], true, false))
	require.ElementsMatch(t, []uint8{0, 1, 2, 3, 4, 5, 6, 7}, list())
	require.False(t, revalidate(t, s, token, last), "a reader that is a URL binding now")
}

// readerTargets returns the root reader body of a, and a derived reader over
// body, as the targets of a check of rule (f).
func readerTargets(t *testing.T, s *Store, a *Owner) map[string]func() any {
	t.Helper()
	return map[string]func() any{
		"root": func() any {
			body := strings.NewReader("body")
			require.True(t, BindReaderValue(a, body, true, false))
			return body
		},
		"derived": func() any {
			body := strings.NewReader("body")
			require.True(t, BindReaderValue(a, body, true, false))
			tee := new(strings.Reader)
			require.True(t, bindDerived(t, s, a, tee, body))
			return tee
		},
	}
}

// TestReaderLookupReadsCounterUnderTableLock checks the order of review 2 of
// batch 1, finding 1. A takes a token of X. B binds X and ends. The lookup of
// the revalidation then stops before it locks the table of A, and A rebinds X
// at that point. If the lookup read the counter before the owner scan, the
// counter would not include the rebind of A, but the baseline would: the two
// changes would cancel and hide the bind of B. The counter is read under the
// table lock of A, thus the result must be a miss. Control: with no bind of
// B, the own rebind at the same point keeps the token valid.
func TestReaderLookupReadsCounterUnderTableLock(t *testing.T) {
	for _, foreign := range []bool{true, false} {
		s := New()
		a := s.Acquire()
		t.Cleanup(a.Finish)
		for name, target := range readerTargets(t, s, a) {
			t.Run(fmt.Sprintf("%s/foreign=%v", name, foreign), func(t *testing.T) {
				b := s.Acquire()
				t.Cleanup(b.Finish)
				reader := target()
				token := takeToken(t, s, reader)
				if foreign {
					require.True(t, BindReaderValue(b, reader, true, false))
				}
				b.Finish()
				index, ok := a.Index()
				require.True(t, ok)
				var once sync.Once
				setHook(t, func(stage hookStage, arg int) bool {
					if stage == hookLookupOwner && arg == int(index) {
						once.Do(func() { require.True(t, BindReaderValue(a, reader, true, false)) })
					}
					return false
				})
				got := revalidate(t, s, token, reader)
				testHook.Store(nil)
				require.Equal(t, !foreign, got, "an own rebind during the lookup hid the bind of B")
			})
		}
	}
}

// TestForeignBindBeforeCaptureIsSticky checks review 2 of batch 1, finding 2:
// A binds X, B binds X and ends, and only then A takes a token. The token must
// not be OK, and a wrapper of A built after B ended must not be exclusive. A
// rebind of A cannot restore the exclusivity. Control: the own rebinds of A
// before B keep the exclusivity.
func TestForeignBindBeforeCaptureIsSticky(t *testing.T) {
	s := New()
	a := s.Acquire()
	t.Cleanup(a.Finish)
	for name, target := range readerTargets(t, s, a) {
		t.Run(name, func(t *testing.T) {
			b := s.Acquire()
			t.Cleanup(b.Finish)
			reader := target()
			require.True(t, BindReaderValue(a, reader, true, false))
			require.True(t, BindReaderValue(a, collidingReader(t, reader), true, false))
			require.True(t, revalidate(t, s, takeToken(t, s, reader), reader), "own rebinds removed the exclusivity")

			require.True(t, BindReaderValue(b, reader, true, false))
			b.Finish()
			refs, complete := lookupReader(t, s, reader, 4)
			require.True(t, complete)
			require.Len(t, refs, 1, "only A is bound after B ended")
			require.False(t, refs[0].Exclusive)
			require.False(t, refs[0].ReaderToken().OK, "a token taken after B ended is OK")
			wrapper := new(strings.Reader)
			require.False(t, BindDerivedReaderValue(a, wrapper, false, []any{reader}, refs[:1]),
				"a wrapper built after B ended got an exclusive proof")

			require.True(t, BindReaderValue(a, reader, true, false))
			requireExclusive(t, s, reader, false)
		})
	}
}

// TestConcurrentOwnAndForeignRebindIsSticky checks review 2 of batch 1,
// finding 2, with barriers: A rebinds X and stops after its counter add,
// under its table lock. B binds X and ends in this window. Then A completes
// its rebind. A lookup after that must not find X exclusive, for a root and a
// derived reader.
func TestConcurrentOwnAndForeignRebindIsSticky(t *testing.T) {
	s := New()
	a := s.Acquire()
	t.Cleanup(a.Finish)
	for name, target := range readerTargets(t, s, a) {
		t.Run(name, func(t *testing.T) {
			b := s.Acquire()
			t.Cleanup(b.Finish)
			reader := target()
			token := takeToken(t, s, reader)
			stopped, release := make(chan struct{}), make(chan struct{})
			// Only the first bind stops. sync.Once would block the bind of
			// B until the bind of A returns.
			var first atomic.Bool
			setHook(t, func(stage hookStage, _ int) bool {
				if stage == hookReaderBind && first.CompareAndSwap(false, true) {
					close(stopped)
					<-release
				}
				return false
			})
			done := make(chan bool)
			go func() { done <- BindReaderValue(a, reader, true, false) }()
			<-stopped
			require.True(t, BindReaderValue(b, reader, true, false))
			b.Finish()
			close(release)
			require.True(t, <-done)
			testHook.Store(nil)

			refs, complete := lookupReader(t, s, reader, 4)
			require.True(t, complete)
			require.Len(t, refs, 1)
			require.False(t, refs[0].Exclusive, "the bind of B in the window of the rebind of A was lost")
			require.False(t, token.Revalidate(refs[0]))
		})
	}
}
