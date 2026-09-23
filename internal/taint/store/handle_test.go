// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntryHandleRevalidatesOwner(t *testing.T) {
	s := New()
	owner := s.Acquire()
	require.False(t, owner.Disabled())
	managed, _, ok := owner.TaintString("attacker-value", 0)
	require.True(t, ok)
	key, _ := StringKey(managed)
	var snapshot Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	entry, ok := snapshot.At(0)
	require.True(t, ok)

	handle, valid := entry.Handle(s)
	require.True(t, valid)
	require.Equal(t, owner.ID(), handle.ID())
	require.Equal(t, owner.Generation(), handle.Generation())

	// A nil store and a zero-value entry never produce a handle.
	_, valid = entry.Handle(nil)
	require.False(t, valid)
	_, valid = (&Entry{}).Handle(s)
	require.False(t, valid, "zero owner ID and generation must not handle")

	// After finish, the stale entry must not produce a handle.
	oldOwnerID := owner.ID()
	owner.Finish()
	_, valid = entry.Handle(s)
	require.False(t, valid, "finished owner must not handle")

	// Reuse the slot with a new generation and owner ID. The stale entry, which
	// still carries the old generation and owner ID, must not handle the reused
	// slot. This is the ABA guard: a stale snapshot cannot publish into reuse.
	ownerIdx, _ := owner.Index()
	reused := s.Acquire()
	require.False(t, reused.Disabled())
	reusedIdx, _ := reused.Index()
	require.Equal(t, ownerIdx, reusedIdx, "the reused slot has the same index")
	require.NotEqual(t, owner.Generation(), reused.Generation())
	require.NotEqual(t, oldOwnerID, reused.ID())
	_, valid = entry.Handle(s)
	require.False(t, valid, "stale entry must not handle a reused slot")
	reused.Finish()
}

func TestEntryHandlePublishesIntoLiveOwnerOnly(t *testing.T) {
	s := New()
	owner := s.Acquire()
	managed, root, ok := owner.TaintString("attacker-value", 0)
	require.True(t, ok)
	key, _ := StringKey(managed)
	var snapshot Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	entry, _ := snapshot.At(0)

	// A live handle can derive a new window into the same root.
	subKey, _ := StringKey(managed[2:9])
	handle, valid := entry.Handle(s)
	require.True(t, valid)
	require.True(t, handle.Derive(subKey, root))
	var sub Snapshot
	require.True(t, s.Lookup(subKey, &sub))
	require.Equal(t, 1, sub.Len())

	// A mismatched owner ID on the same slot is rejected even when active.
	oldOwnerID := owner.ID()
	owner.Finish()
	reused := s.Acquire()
	require.NotEqual(t, oldOwnerID, reused.ID())
	// Fabricate an entry that points at the reused slot but carries the old owner ID.
	staleID := *entry
	staleID.OwnerGen = reused.Generation()
	_, valid = staleID.Handle(s)
	require.False(t, valid, "owner ID mismatch must reject even if generation matches")
	reused.Finish()
}

func TestEntryHandleConcurrentFinishIsSafe(t *testing.T) {
	s := New()
	owner := s.Acquire()
	managed, root, ok := owner.TaintString(strings.Repeat("a", 32), 0)
	require.True(t, ok)
	key, _ := StringKey(managed)

	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(offset int) {
			defer wait.Done()
			<-start
			for i := 0; i < 500; i++ {
				var snapshot Snapshot
				if !s.Lookup(key, &snapshot) {
					continue
				}
				for j := 0; j < snapshot.Len(); j++ {
					entry, _ := snapshot.At(j)
					if handle, valid := entry.Handle(s); valid {
						begin := (offset + i) % (len(managed) - 2)
						subKey, subOK := StringKey(managed[begin : begin+2])
						if subOK {
							handle.Derive(subKey, root)
						}
					}
				}
			}
		}(worker)
	}
	close(start)
	finished := make(chan struct{})
	go func() {
		owner.Finish()
		close(finished)
	}()
	wait.Wait()
	<-finished
	require.Zero(t, s.ProcessValues())
}
