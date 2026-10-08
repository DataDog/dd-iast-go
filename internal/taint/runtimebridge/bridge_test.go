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

// TestDependencies checks rule 1 of the runtime hook rules in the package doc:
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
// that the woven runtime uses (the body-less //go:linkname declarations of
// iast/runtime/orchestrion.yml).
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
	clean := heapString("linker-symbol-clean")
	var buffer [32]byte
	buf := unsafe.Pointer(&buffer)
	hit := func(gotBuf unsafe.Pointer, ok bool) bool {
		t.Helper()
		require.Equal(t, buf, gotBuf, "the filter check returns buf unchanged")
		return ok
	}
	gotBuf, gotOperands, ok := bridgetest.ConcatHit(buf, operands)
	require.True(t, hit(gotBuf, ok))
	require.Equal(t, operands, gotOperands)
	gotBuf, gotPtr, gotN, ok := bridgetest.BytesHit(buf, unsafe.StringData(tainted), len(tainted))
	require.True(t, hit(gotBuf, ok))
	require.Equal(t, unsafe.StringData(tainted), gotPtr)
	require.Equal(t, len(tainted), gotN)
	gotBuf, gotString, ok := bridgetest.StrHit(buf, tainted)
	require.True(t, hit(gotBuf, ok))
	require.Equal(t, tainted, gotString)
	gotBuf, gotString, ok = bridgetest.StrHitRunes(buf, tainted)
	require.True(t, hit(gotBuf, ok))
	require.Equal(t, tainted, gotString)
	gotBuf, gotRunes, ok := bridgetest.RunesHit(buf, runes)
	require.True(t, hit(gotBuf, ok))
	require.Equal(t, runes, gotRunes)
	if !runtimebridge.FilterHit(&filter, uintptr(unsafe.Pointer(unsafe.StringData(clean)))) {
		_, _, ok = bridgetest.ConcatHit(buf, []string{"x", clean})
		require.False(t, ok)
		_, _, ok = bridgetest.StrHit(buf, clean)
		require.False(t, ok)
	}
	_, _, ok = bridgetest.ConcatHit(nil, []string{"", ""})
	require.False(t, ok, "empty operands")
	_, _, _, ok = bridgetest.BytesHit(nil, unsafe.StringData(tainted), 0)
	require.False(t, ok, "empty input")
	_, _, ok = bridgetest.StrHit(nil, "")
	require.False(t, ok, "empty input")
	_, _, ok = bridgetest.StrHitRunes(nil, "")
	require.False(t, ok, "empty input")
	_, _, ok = bridgetest.RunesHit(nil, nil)
	require.False(t, ok, "empty input")
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

// TestFilterChecks checks the filter checks ("hit" functions) with filters
// that give a known result: they return their arguments unchanged, and true
// only when the filter has a bucket of one input.
func TestFilterChecks(t *testing.T) {
	value := heapString("filter-check-input")
	other := heapString("filter-check-other")
	runes := heapRunes("filter-check-runes")
	one := heapString("1")
	valueP := uintptr(unsafe.Pointer(unsafe.StringData(value)))
	var buffer [32]byte
	buf := unsafe.Pointer(&buffer)

	// check calls the 5 filter checks with non-empty inputs. Each one must
	// return its arguments unchanged.
	check := func(t *testing.T, operands []string) (concat, bytes, str, strRunes, runeSlice bool) {
		t.Helper()
		gotBuf, gotOperands, concat := bridgetest.ConcatHit(buf, operands)
		require.Equal(t, buf, gotBuf)
		require.Equal(t, operands, gotOperands)
		gotBuf, gotPtr, gotN, bytes := bridgetest.BytesHit(buf, unsafe.StringData(value), len(value))
		require.Equal(t, buf, gotBuf)
		require.Equal(t, unsafe.StringData(value), gotPtr)
		require.Equal(t, len(value), gotN)
		gotBuf, gotString, str := bridgetest.StrHit(buf, value)
		require.Equal(t, buf, gotBuf)
		require.Equal(t, value, gotString)
		gotBuf, gotString, strRunes = bridgetest.StrHitRunes(buf, value)
		require.Equal(t, buf, gotBuf)
		require.Equal(t, value, gotString)
		gotBuf, gotRunes, runeSlice := bridgetest.RunesHit(buf, runes)
		require.Equal(t, buf, gotBuf)
		require.Equal(t, runes, gotRunes)
		return concat, bytes, str, strRunes, runeSlice
	}
	confirm := func(uintptr, uint32) runtimebridge.ConfirmResult { return runtimebridge.ConfirmTainted }

	t.Run("no binding", func(t *testing.T) {
		t.Cleanup(runtimebridge.ReplaceForTest(nil, true, nil))
		concat, bytes, str, strRunes, runeSlice := check(t, []string{other, value})
		require.False(t, concat || bytes || str || strRunes || runeSlice)
	})
	t.Run("no filter", func(t *testing.T) {
		t.Cleanup(runtimebridge.ReplaceForTest(&runtimebridge.Binding{Confirm: confirm}, true, nil))
		concat, bytes, str, strRunes, runeSlice := check(t, []string{other, value})
		require.False(t, concat || bytes || str || strRunes || runeSlice)
	})
	t.Run("empty filter", func(t *testing.T) {
		var filter runtimebridge.Filter
		t.Cleanup(runtimebridge.ReplaceForTest(&runtimebridge.Binding{Filter: &filter, Confirm: confirm}, true, nil))
		concat, bytes, str, strRunes, runeSlice := check(t, []string{other, value})
		require.False(t, concat || bytes || str || strRunes || runeSlice, "a filter miss")
	})
	t.Run("one input in the filter", func(t *testing.T) {
		var filter runtimebridge.Filter
		for _, p := range []uintptr{valueP, uintptr(unsafe.Pointer(&runes[0])), uintptr(unsafe.Pointer(unsafe.StringData(one)))} {
			runtimebridge.MarkForTest(&filter, p)
		}
		t.Cleanup(runtimebridge.ReplaceForTest(&runtimebridge.Binding{Filter: &filter, Confirm: confirm}, true, nil))
		concat, bytes, str, strRunes, runeSlice := check(t, []string{other, value})
		require.True(t, concat && bytes && str && strRunes && runeSlice)
		_, _, concat = bridgetest.ConcatHit(buf, []string{value, other})
		require.True(t, concat, "the first operand hits")
		// The filter check does not skip a one-byte input: the wrapper and
		// the result function decide for it.
		_, _, str = bridgetest.StrHit(buf, one)
		require.True(t, str, "a one-byte input")
		_, _, _, bytes = bridgetest.BytesHit(buf, unsafe.StringData(one), 1)
		require.True(t, bytes, "a one-byte input")
		// Inputs that the filter does not contain: each check returns false,
		// also when the filter contains other values.
		var clean string
		var cleanRunes []rune
		for range 100 {
			if s := heapString("filter-check-clean"); !runtimebridge.FilterHit(&filter, uintptr(unsafe.Pointer(unsafe.StringData(s)))) {
				clean = s
			}
			if r := heapRunes("filter-check-clean"); !runtimebridge.FilterHit(&filter, uintptr(unsafe.Pointer(&r[0]))) {
				cleanRunes = r
			}
			if clean != "" && cleanRunes != nil {
				break
			}
		}
		require.NotEmpty(t, clean, "no clean string is a filter miss")
		require.NotNil(t, cleanRunes, "no clean rune slice is a filter miss")
		_, _, concat = bridgetest.ConcatHit(buf, []string{clean, clean})
		require.False(t, concat, "no operand hits")
		_, _, _, bytes = bridgetest.BytesHit(buf, unsafe.StringData(clean), len(clean))
		require.False(t, bytes, "a filter miss")
		_, _, str = bridgetest.StrHit(buf, clean)
		require.False(t, str, "a filter miss")
		_, _, strRunes = bridgetest.StrHitRunes(buf, clean)
		require.False(t, strRunes, "a filter miss")
		_, _, runeSlice = bridgetest.RunesHit(buf, cleanRunes)
		require.False(t, runeSlice, "a filter miss")
		_, _, concat = bridgetest.ConcatHit(buf, []string{"", value[:0]})
		require.False(t, concat, "empty operands")
		_, _, _, bytes = bridgetest.BytesHit(buf, unsafe.StringData(value), 0)
		require.False(t, bytes, "empty input")
		_, _, _, bytes = bridgetest.BytesHit(buf, nil, 4)
		require.False(t, bytes, "nil pointer")
		_, _, str = bridgetest.StrHit(buf, value[:0])
		require.False(t, str, "empty input")
		_, _, strRunes = bridgetest.StrHitRunes(buf, value[:0])
		require.False(t, strRunes, "empty input")
		_, _, runeSlice = bridgetest.RunesHit(buf, runes[:0])
		require.False(t, runeSlice, "empty input")
	})
}

// heapString returns a heap copy of s. The bridgetest declarations are
// //go:noescape, as in the runtime, so a value that only goes to them can be
// on the stack, and a stack value can move when the stack grows.
//
//go:noinline
func heapString(s string) string { return strings.Clone(s) }

//go:noinline
func heapRunes(s string) []rune { return []rune(s) }
