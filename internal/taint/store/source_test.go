// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store_test

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestTaintSourceStringChargesValueAndName(t *testing.T) {
	taintStore := store.New()
	owner := taintStore.Acquire()
	value := "attacker"
	name := "header"
	managed, managedName, _, ok := owner.TaintSourceString(value, name, ranges.SourceID(0))
	require.True(t, ok)
	require.Equal(t, value, managed)
	require.Equal(t, name, managedName)
	require.False(t, unsafe.StringData(value) == unsafe.StringData(managed))
	require.False(t, unsafe.StringData(name) == unsafe.StringData(managedName))
	require.Equal(t, int64(16), owner.Charged())

	owner.Finish()
	require.Zero(t, taintStore.ProcessCharged())
}

func TestTaintSourceBytesChargesImmutableMetadata(t *testing.T) {
	taintStore := store.New()
	owner := taintStore.Acquire()
	value := make([]byte, 6, 12)
	copy(value, "attack")
	managed, managedName, managedValue, _, ok := owner.TaintSourceBytes(value, "body", ranges.SourceID(0))
	require.True(t, ok)
	require.Equal(t, cap(value), cap(managed))
	require.Equal(t, "body", managedName)
	require.Equal(t, "attack", managedValue)
	require.False(t, unsafe.SliceData(value) == unsafe.SliceData(managed))
	require.Equal(t, int64(32), owner.Charged())

	managed[0] = 'A'
	require.Equal(t, "attack", managedValue)
	owner.Finish()
	require.Zero(t, taintStore.ProcessCharged())
}

func TestAdoptSourceBytesKeepsOriginalAllocation(t *testing.T) {
	taintStore := store.New()
	owner := taintStore.Acquire()
	value := make([]byte, 6, 12)
	copy(value, "attack")
	before := unsafe.SliceData(value)
	managedName, managedValue, _, ok := owner.AdoptSourceBytes(value, "", ranges.SourceID(0))
	require.True(t, ok)
	require.Empty(t, managedName)
	require.Equal(t, "attack", managedValue)
	require.True(t, before == unsafe.SliceData(value))
	require.Equal(t, int64(24), owner.Charged())
	owner.Finish()
	require.Zero(t, taintStore.ProcessCharged())
}

func TestTaintSourceBytesAcceptsMaximumCombinedCharge(t *testing.T) {
	require.Equal(t, 3*store.MaxRootBytes, store.MaxRootChargeBytes)
	taintStore := store.New()
	owner := taintStore.Acquire()
	value := make([]byte, store.MaxRootBytes)
	name := string(make([]byte, store.MaxRootBytes))
	_, _, _, _, ok := owner.TaintSourceBytes(value, name, ranges.SourceID(0))
	require.True(t, ok)
	require.Equal(t, int64(store.MaxRootChargeBytes), owner.Charged())
	owner.Finish()
	require.Zero(t, taintStore.ProcessCharged())
}

func TestTaintSourceRejectsOversizedMetadataWithoutCharge(t *testing.T) {
	taintStore := store.New()
	owner := taintStore.Acquire()
	name := make([]byte, store.MaxRootBytes+1)
	_, _, _, ok := owner.TaintSourceString("value", string(name), ranges.SourceID(0))
	require.False(t, ok)
	require.Zero(t, owner.Charged())
	owner.Finish()
}
