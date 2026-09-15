// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFinishDrainsActiveWriterAndReleasesRoots(t *testing.T) {
	store := New()
	owner := store.Acquire()
	_, _, ok := owner.TaintString("retained-until-finish", 0)
	require.True(t, ok)

	owner.owner.lifecycleMu.RLock()
	done := make(chan struct{})
	go func() {
		owner.Finish()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Finish returned while a writer lifecycle lock was held")
	default:
	}
	owner.owner.lifecycleMu.RUnlock()
	<-done
	require.Zero(t, store.ProcessCharged())
	require.Zero(t, store.ProcessValues())
}

func BenchmarkFinishWithActiveWriter(b *testing.B) {
	store := New()
	for b.Loop() {
		owner := store.Acquire()
		owner.TaintString("retained-until-finish", 0)
		owner.owner.lifecycleMu.RLock()
		done := make(chan struct{})
		go func() {
			owner.Finish()
			close(done)
		}()
		owner.owner.lifecycleMu.RUnlock()
		<-done
	}
}
