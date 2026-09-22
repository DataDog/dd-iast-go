// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package jsonbridge_test

import (
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/stretchr/testify/require"
)

func TestDecoderSlotCapacityAndRelease(t *testing.T) {
	activateDecoderOwners(t)
	// Consecutive uint64 elements occupy all 64 pointer-hash buckets.
	// Binding the array as the reader also keeps every state address anchored.
	states := new([65]uint64)
	t.Cleanup(func() {
		for index := range states {
			jsonbridge.Unbind(&states[index])
		}
	})
	for index := range 64 {
		require.True(t, jsonbridge.Bind(states, &states[index]), "slot %d", index)
	}
	require.False(t, jsonbridge.Bind(states, &states[64]))
	for index := range 64 {
		jsonbridge.Unbind(&states[index])
	}
	require.True(t, jsonbridge.Bind(states, &states[64]), "released capacity must be reusable")
}

func TestDecoderCollisionStopsAfterFourProbes(t *testing.T) {
	activateDecoderOwners(t)
	// The pointer hash uses (address >> 3) modulo 64. These valid state
	// pointers are 64 uint64 elements apart, so all five start in one bucket.
	states := new([257]uint64)
	indexes := [...]int{0, 64, 128, 192, 256}
	t.Cleanup(func() {
		for _, index := range indexes {
			jsonbridge.Unbind(&states[index])
		}
	})
	for _, index := range indexes[:4] {
		require.True(t, jsonbridge.Bind(states, &states[index]))
	}
	require.False(t, jsonbridge.Bind(states, &states[indexes[4]]), "unrelated free buckets must not extend the probe budget")
	jsonbridge.Unbind(&states[indexes[1]])
	require.True(t, jsonbridge.Bind(states, &states[indexes[4]]), "a released collision slot must be reusable")
}

func activateDecoderOwners(t *testing.T) {
	t.Helper()
	owners := new(atomic.Uint64)
	owners.Store(1)
	previous := jsonbridge.BindActiveOwners(owners)
	t.Cleanup(func() { jsonbridge.BindActiveOwners(previous) })
}
