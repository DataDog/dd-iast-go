// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtimebridge_test

import (
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge/bridgetest"
	"github.com/stretchr/testify/require"
)

const bridgePackage = "github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"

// TestDependencies checks plan section 3.2 rule 1 (and section 9.1 item 9):
// the woven runtime links the bridge, so the bridge must not import a package
// that the runtime hooks weave. Only sync/atomic, unsafe and the runtime and
// its dependencies are permitted.
func TestDependencies(t *testing.T) {
	gotool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not available")
	}
	list := func(pkg string) map[string]bool {
		t.Helper()
		output, err := exec.Command(gotool, "list", "-deps", pkg).Output()
		require.NoError(t, err)
		packages := map[string]bool{}
		for _, line := range strings.Fields(string(output)) {
			packages[line] = true
		}
		return packages
	}
	runtimeDeps := list("runtime")
	allowed := map[string]bool{bridgePackage: true, "sync/atomic": true, "unsafe": true}
	var extra []string
	for pkg := range list(bridgePackage) {
		if !allowed[pkg] && !runtimeDeps[pkg] {
			extra = append(extra, pkg)
		}
	}
	require.Empty(t, extra, "the runtime bridge must import only sync/atomic and unsafe")
}

// TestLinkerSymbols calls every bridge function through the linker symbols
// that the woven runtime uses (plan section 2.2).
func TestLinkerSymbols(t *testing.T) {
	var filter runtimebridge.Filter
	tainted := heapString("linker-symbol-input")
	runes := heapRunes("linker-symbol-runes")
	for _, p := range []uintptr{uintptr(unsafe.Pointer(unsafe.StringData(tainted))), uintptr(unsafe.Pointer(&runes[0]))} {
		runtimebridge.MarkForTest(&filter, p)
	}
	confirm := func(uintptr, uint32) runtimebridge.ConfirmResult { return runtimebridge.ConfirmTainted }
	var calls []string
	record := func(name string) { calls = append(calls, name) }
	restore := runtimebridge.ReplaceForTest(&runtimebridge.Binding{Filter: &filter, Confirm: confirm}, true, &runtimebridge.Callbacks{
		Concat:      func(string, []string) { record("concat") },
		ConcatBytes: func([]byte, []string) { record("concat_bytes") },
		FromBytes:   func(string, []byte) { record("from_bytes") },
		ToBytes:     func([]byte, string) { record("to_bytes") },
		FromRunes:   func(string, []rune) { record("from_runes") },
		ToRunes:     func([]rune, string) { record("to_runes") },
	})
	t.Cleanup(restore)
	require.Equal(t, uint32(1), bridgetest.S2SGate())

	operands := []string{"x", tainted}
	require.True(t, bridgetest.ConcatPre(operands))
	require.True(t, bridgetest.BytesPre(unsafe.StringData(tainted), len(tainted)))
	require.True(t, bridgetest.StrPre(tainted))
	require.True(t, bridgetest.RunesPre(runes))
	result := strings.Clone("result")
	bridgetest.ConcatHook(result, operands)
	bridgetest.ConcatBytesHook([]byte("result"), operands)
	bridgetest.FromBytes(result, unsafe.StringData(tainted), len(tainted))
	bridgetest.ToBytes([]byte("result"), tainted)
	bridgetest.FromRunes(result, runes)
	bridgetest.ToRunes([]rune("result"), tainted)
	require.Equal(t, []string{"concat", "concat_bytes", "from_bytes", "to_bytes", "from_runes", "to_runes"}, calls)

	previous := bridgetest.SetS2SGate(0)
	require.Equal(t, uint32(1), previous)
	require.False(t, runtimebridge.StringToSliceEnabled())
	require.False(t, bridgetest.StrPre(tainted))
	bridgetest.SetS2SGate(previous)
}

// heapString returns a heap copy of s. The bridgetest declarations are
// //go:noescape, as in the runtime, so a value that only goes to them can be
// on the stack, and a stack value can move when the stack grows.
//
//go:noinline
func heapString(s string) string { return strings.Clone(s) }

//go:noinline
func heapRunes(s string) []rune { return []rune(s) }
