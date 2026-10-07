// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bridgetests_test

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/stretchr/testify/require"
)

// TestFastPathGatesAreInlinable checks that the gates of the v1 aspects are
// inlinable (plan encoding-json-v2, step 8 appendix, Table 6). The aspects
// call the bridge only when a gate is true. Thus, when IAST is inactive, the
// v1 decode path makes no call to the bridge. If a gate is not inlinable, the
// gate itself is a call.
func TestFastPathGatesAreInlinable(t *testing.T) {
	gotool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not available")
	}
	const bridgePackage = "github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	output, err := exec.CommandContext(t.Context(), gotool, "build", "-gcflags="+bridgePackage+"=-m", bridgePackage).CombinedOutput()
	require.NoError(t, err, "go build -gcflags=-m failed:\n%s", output)
	for _, gate := range []string{"RequestActive", "HasDecoderStates", "Active", "(*ReaderBinding).Exclusive"} {
		require.True(t, strings.Contains(string(output), ": can inline "+gate+"\n"), "the gate %s is not inlinable:\n%s", gate, output)
	}
}

// TestInactiveFastPath checks the gates when no request is active and no
// decoder slot is in use: all gates are false, and the bridge functions that
// the gates protect do nothing, call no callback, and do not allocate.
func TestInactiveFastPath(t *testing.T) {
	previousOwners := jsonbridge.BindActiveOwners(nil)
	previousValues := jsonbridge.BindActiveValues(nil)
	t.Cleanup(func() {
		jsonbridge.BindActiveOwners(previousOwners)
		jsonbridge.BindActiveValues(previousValues)
	})
	t.Cleanup(jsonbridge.SetV1ForTest(true))
	fake := &fakeCallbacks{token: okToken()}
	register(t, fake)

	require.False(t, jsonbridge.RequestActive())
	require.False(t, jsonbridge.Active())
	require.False(t, jsonbridge.HasDecoderStates())
	require.False(t, (*jsonbridge.ReaderBinding)(nil).Exclusive())
	binding := new(jsonbridge.ReaderBinding)
	binding.Capture(new(int))
	require.False(t, binding.Exclusive(), "Capture with no active request must not make the binding exclusive")

	state := any(new(int))
	original := []byte(`{"value":"inactive"}`)
	item := original[9:19]
	value := reflect.ValueOf(new(string)).Elem()
	require.Zero(t, testing.AllocsPerRun(100, func() {
		if jsonbridge.Bind(state) || jsonbridge.BindDecoder(binding, state) {
			panic("bound with no active request")
		}
		jsonbridge.Document(state, original)
		jsonbridge.Quoted(state, original, 9, 19, `"inactive"`)
		jsonbridge.Literal(state, original, item, value, nil, true)
	}))
	require.False(t, jsonbridge.HasDecoderStates(), "a Bind with no active request must not take a slot")
	require.Zero(t, fake.ownerCalls)
	require.Zero(t, fake.cloneCalls)
	require.Zero(t, fake.literalCalls)
}

// TestHasDecoderStatesCountsBoundSlots checks that HasDecoderStates is true
// exactly while a decoder slot is in use: from the Bind that takes a free
// slot to the final Unbind of that slot, also for nested binds and with all
// the slots in use.
func TestHasDecoderStatesCountsBoundSlots(t *testing.T) {
	activateDecoderOwners(t)
	require.False(t, jsonbridge.HasDecoderStates())

	state := new(int)
	require.True(t, jsonbridge.Bind(state))
	require.True(t, jsonbridge.HasDecoderStates())
	require.True(t, jsonbridge.Bind(state), "nested bind")
	jsonbridge.Unbind(state)
	require.True(t, jsonbridge.HasDecoderStates(), "the outer bind still uses the slot")
	jsonbridge.Unbind(state)
	require.False(t, jsonbridge.HasDecoderStates(), "the final Unbind must release the slot")
	jsonbridge.Unbind(state)
	require.False(t, jsonbridge.HasDecoderStates(), "an extra Unbind must not change the count")

	// Consecutive uint64 elements occupy all 64 pointer-hash buckets.
	states := new([65]uint64)
	t.Cleanup(func() {
		for index := range states {
			jsonbridge.Unbind(&states[index])
		}
	})
	for index := range 64 {
		require.True(t, jsonbridge.Bind(&states[index]), "slot %d", index)
	}
	require.False(t, jsonbridge.Bind(&states[64]))
	for index := range 64 {
		require.True(t, jsonbridge.HasDecoderStates(), "slot %d", index)
		jsonbridge.Unbind(&states[index])
	}
	require.False(t, jsonbridge.HasDecoderStates())
}

// TestLiteralWithNoSlotPublishes checks that Literal publishes the original
// token when no decoder slot is in use, but a request is active and the
// process has an indexed root. This occurs when all the slots that Bind
// probed were in use. Thus the gate of the literalStore aspect is
// "HasDecoderStates() || Active()", not HasDecoderStates alone.
func TestLiteralWithNoSlotPublishes(t *testing.T) {
	activate(t)
	fake := &fakeCallbacks{}
	register(t, fake)
	require.False(t, jsonbridge.HasDecoderStates())
	require.True(t, jsonbridge.Active())

	original := []byte(`{"value":"attack"}`)
	jsonbridge.Quoted(new(int), original, 9, 17, `"attack"`)
	jsonbridge.Literal(new(int), original, original[9:17], reflect.Value{}, nil, false)
	require.Equal(t, 1, fake.literalCalls)
	require.Equal(t, original, fake.literalDocument)
	require.Equal(t, original[9:17], fake.literalItem)
}
