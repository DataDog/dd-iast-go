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

func TestRequestRootByteLimit(t *testing.T) {
	store := New()
	owner := store.Acquire()
	for i := 0; i < RequestRootBytes/MaxRootBytes; i++ {
		_, _, ok := owner.TaintString(strings.Repeat(string(rune('a'+i%20)), MaxRootBytes), 0)
		require.Truef(t, ok, "root %d", i)
	}
	_, _, ok := owner.TaintString(strings.Repeat("z", MaxRootBytes), 0)
	require.False(t, ok)
	require.Equal(t, int64(RequestRootBytes), owner.Charged())
	require.Greater(t, owner.Counters().Bytes, uint64(0))
	owner.Finish()
}

func TestProcessRootByteLimit(t *testing.T) {
	store := New()
	owners := make([]*Owner, ProcessRootBytes/RequestRootBytes)
	for i := range owners {
		owners[i] = store.Acquire()
		for root := 0; root < RequestRootBytes/MaxRootBytes; root++ {
			_, _, ok := owners[i].TaintString(strings.Repeat(string(rune('a'+root%20)), MaxRootBytes), 0)
			require.True(t, ok)
		}
	}
	extra := store.Acquire()
	_, _, ok := extra.TaintString(strings.Repeat("z", MaxRootBytes), 0)
	require.False(t, ok)
	require.Equal(t, int64(ProcessRootBytes), store.ProcessCharged())
	for _, owner := range owners {
		owner.Finish()
	}
	extra.Finish()
	require.Zero(t, store.ProcessCharged())
}

func TestRootCountLimit(t *testing.T) {
	store := New()
	owner := store.Acquire()
	for i := 0; i < MaxRootsPerOwner; i++ {
		value := strings.Clone(string([]byte{byte(i), byte(i >> 8), 'x'}))
		_, _, ok := owner.TaintString(value, 0)
		require.Truef(t, ok, "root %d", i)
	}
	_, _, ok := owner.TaintString("one-root-too-many", 0)
	require.False(t, ok)
	require.Greater(t, owner.Counters().Full, uint64(0))
	owner.Finish()
}

func TestRequestAndProcessValueLimits(t *testing.T) {
	store := New()
	owners := make([]*Owner, ProcessValueLimit/RequestValueLimit)
	for i := range owners {
		owners[i] = store.Acquire()
		fillOwnerValues(t, owners[i])
		require.Equal(t, int32(RequestValueLimit), owners[i].Values())
	}
	require.Equal(t, int32(ProcessValueLimit), store.ProcessValues())

	extra := store.Acquire()
	_, _, ok := extra.TaintString("process-value-limit", 0)
	require.False(t, ok)
	require.Greater(t, extra.Counters().Full, uint64(0))
	for _, owner := range owners {
		owner.Finish()
	}
	extra.Finish()
	require.Zero(t, store.ProcessValues())
}

func fillOwnerValues(t *testing.T, owner *Owner) {
	t.Helper()
	const roots = RequestValueLimit / MaxValuesPerRoot
	for rootIndex := 0; rootIndex < roots; rootIndex++ {
		managed, root, ok := owner.TaintBytes(make([]byte, 512), 0)
		require.Truef(t, ok, "root %d", rootIndex)
		for offset := 0; offset < MaxValuesPerRoot-1; offset++ {
			key, valid := BytesKey(managed[offset : offset+2])
			require.True(t, valid)
			require.Truef(t, owner.Derive(key, root), "root %d offset %d", rootIndex, offset)
		}
	}
}

func TestBindingLimit(t *testing.T) {
	type object struct{ index int }
	store := New()
	owner := store.Acquire()
	objects := make([]*object, MaxBindings+1)
	for i := 0; i < MaxBindings; i++ {
		objects[i] = &object{index: i}
		require.True(t, BindObject(owner, objects[i], BindingURL))
	}
	objects[MaxBindings] = &object{index: MaxBindings}
	require.False(t, BindObject(owner, objects[MaxBindings], BindingURL))
	require.Greater(t, owner.Counters().Full, uint64(0))
	owner.Finish()
}

func TestReaderBindingLimit(t *testing.T) {
	type reader struct{ index int }
	store := New()
	owner := store.Acquire()
	readers := make([]*reader, MaxReaderBindings+1)
	for i := 0; i < MaxReaderBindings; i++ {
		readers[i] = &reader{index: i}
		require.True(t, BindObject(owner, readers[i], BindingReader))
	}
	readers[MaxReaderBindings] = &reader{index: MaxReaderBindings}
	require.False(t, BindObject(owner, readers[MaxReaderBindings], BindingReader))
	require.Greater(t, owner.Counters().Full, uint64(0))
	owner.Finish()
}
