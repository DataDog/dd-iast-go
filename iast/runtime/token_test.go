// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/stretchr/testify/require"
)

// tokenOps are the 6 hooked operations with a stack buffer and a tainted
// input. Each one enters the bridge 3 times: the filter check before the
// wrapper has a hit, the pre-check forces the result to the heap, and the
// result hook adopts it.
func tokenOps(t *testing.T) map[string]func() probe {
	t.Helper()
	ctx := begin(t)
	s := taintString(t, ctx, "s", "short-value")
	b := taintBytes(t, ctx, "b", []byte("short-bytes"))
	r := heapRunes("short runes")
	adoptRunes(t, s, r, 0, len(r))
	return map[string]func() probe{
		"concatstrings":     func() probe { return stackConcat("x", s) },
		"concatbytes":       func() probe { return stackConcatBytes("x", s) },
		"slicebytetostring": func() probe { return stackB2S(b) },
		"stringtoslicebyte": func() probe { return stackS2B(s) },
		"slicerunetostring": func() probe { return stackR2S(r) },
		"stringtoslicerune": func() probe { return stackS2R(s) },
	}
}

// TestBypassTokenGateChange checks token rule 3 (see "Bypass token" in the
// internal/taint/runtimebridge package doc): the gate
// changes to 0 between the outer entry and the inner entry. The inner entry
// then does not read the token, so the wrapper must clear it after the inner
// call. The next operation on the same goroutine enters the bridge.
func TestBypassTokenGateChange(t *testing.T) {
	requireWoven(t)
	ops := tokenOps(t)
	withTestBinding(t)
	for name, op := range ops {
		saved := runtimebridge.GateValue()
		require.NotZero(t, saved)
		testConfirmMode.Store(int32(confirmGateOff))
		p := op()
		testConfirmMode.Store(int32(confirmNormal))
		require.Zero(t, runtimebridge.GateValue(), "%s: the test binding stored 0 in the gate", name)
		runtimebridge.SwapGateForTest(saved)
		require.Equal(t, probe{}, p, "%s: confirm returned clean, so the result stays on the stack", name)

		before := entries()
		p = op()
		require.Equal(t, uint64(3), entries()-before, "%s: the next operation must enter the bridge (a stale token skips it)", name)
		require.Equal(t, probe{tainted: true}, p, name)
	}
}

// nilString returns a string of n bytes with a nil data pointer. A copy from
// it faults, and the runtime converts the fault into a recoverable panic.
func nilString(n int) string {
	header := struct {
		data unsafe.Pointer
		n    int
	}{nil, n}
	return *(*string)(unsafe.Pointer(&header))
}

//go:noinline
func faultingConcat(a, b string) (recovered bool) {
	defer func() { recovered = recover() != nil }()
	sinkInt = stackConcatLen(a, b)
	return false
}

// TestBypassTokenStaleBound checks token rule 4: the gate
// changes to 0 before the inner entry, and then the original body panics. The
// token stays 1 for one more entry: at most 1 of the next 2 operations on the
// goroutine does not enter the bridge.
func TestBypassTokenStaleBound(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	s := taintString(t, ctx, "s", "short-value")
	withTestBinding(t)
	saved := runtimebridge.GateValue()
	testConfirmMode.Store(int32(confirmGateOff))
	recovered := faultingConcat(s, nilString(8))
	testConfirmMode.Store(int32(confirmNormal))
	runtimebridge.SwapGateForTest(saved)
	require.True(t, recovered, "the copy from a nil pointer must panic")

	before := entries()
	first := stackConcat("x", s)
	second := stackConcat("x", s)
	got := entries() - before
	require.GreaterOrEqual(t, got, uint64(3), "at most one operation can skip the bridge")
	require.True(t, first.tainted || second.tainted)
	require.True(t, second.tainted, "the stale token is gone after one entry")
}

// TestBypassTokenSequence checks that 1 000 mixed operations on one goroutine
// all enter the bridge: no operation loses the token.
func TestBypassTokenSequence(t *testing.T) {
	requireWoven(t)
	ops := tokenOps(t)
	list := make([]func() probe, 0, len(ops))
	for _, op := range ops {
		list = append(list, op)
	}
	// The store quotas of the owner can refuse the later results, so the
	// test checks the bridge entries only.
	before := entries()
	for i := range 1000 {
		list[i%len(list)]()
	}
	require.Equal(t, uint64(3000), entries()-before)
}
