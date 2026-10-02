// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFinishReleasesReaderBindingObjects(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	readers := make([]*bytes.Reader, MaxReaderBindings)
	for index := range readers {
		readers[index] = bytes.NewReader([]byte("bound-reader"))
		require.True(t, BindObject(owner, readers[index], BindingReader))
	}
	bindings := &owner.owner.bindings
	func() {
		bindings.mu.RLock()
		defer bindings.mu.RUnlock()
		require.Equal(t, uint16(MaxReaderBindings), bindings.count)
		require.Equal(t, uint8(MaxReaderBindings), bindings.readerCount)
		for index, reader := range readers {
			require.Same(t, reader, bindings.entries[index].object)
		}
	}()

	owner.Finish()

	bindings.mu.RLock()
	defer bindings.mu.RUnlock()
	require.Zero(t, bindings.count)
	require.Zero(t, bindings.readerCount)
	for index := range bindings.entries {
		require.Nil(t, bindings.entries[index].object, "binding %d retains its reader after Finish", index)
	}
}
