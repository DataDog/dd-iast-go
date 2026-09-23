// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReaderBindingContentionDoesNotPublishOrLoseExistingBinding(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	existing := strings.NewReader("existing")
	require.True(t, BindObjectValue(owner, existing, BindingReader))
	newReader := strings.NewReader("new reader")
	table := &owner.owner.bindings
	table.mu.Lock()
	typed := BindObject(owner, newReader, BindingReader)
	dynamic := BindObjectValue(owner, newReader, BindingReader)
	var refs [1]OwnerRef
	count := LookupObjectValue(s, existing, BindingReader, refs[:])
	table.mu.Unlock()
	require.False(t, typed)
	require.False(t, dynamic)
	require.Zero(t, count)
	require.Equal(t, uint64(3), owner.Counters().Contention)
	require.Zero(t, LookupObjectValue(s, newReader, BindingReader, refs[:]))
	require.Equal(t, 1, LookupObjectValue(s, existing, BindingReader, refs[:]))
}

func TestReaderBindingFanoutAndStaleReferences(t *testing.T) {
	s := New()
	first, second := s.Acquire(), s.Acquire()
	t.Cleanup(first.Finish)
	t.Cleanup(second.Finish)
	reader := strings.NewReader("shared input")
	require.True(t, BindObjectValue(first, reader, BindingReader))
	require.True(t, BindObjectValue(second, reader, BindingReader))
	var refs [1]OwnerRef
	require.Equal(t, 1, LookupObjectValue(s, reader, BindingReader, refs[:]))
	require.Equal(t, uint64(1), second.Counters().Fanout)
	stale := refs[0]
	_, _, id, ok := stale.Identity()
	require.True(t, ok)
	require.Equal(t, first.ID(), id)
	first.Finish()
	_, ok = stale.Handle()
	require.False(t, ok)
	_, _, _, ok = stale.Identity()
	require.False(t, ok)
	require.Equal(t, 1, LookupObjectValue(s, reader, BindingReader, refs[:]))
	_, _, id, ok = refs[0].Identity()
	require.True(t, ok)
	require.Equal(t, second.ID(), id)
}
