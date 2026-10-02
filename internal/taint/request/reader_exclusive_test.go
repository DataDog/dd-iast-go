// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// The tests of this file check plan encoding-json-v2, sections 6.5 and 6.6,
// without woven io and bufio packages. The woven tests are in iast/io,
// iast/bufio and iast/net/http.

func enableForTest(t *testing.T) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
}

func beginForTest(t *testing.T) (context.Context, *Scope) {
	t.Helper()
	ctx, scope, created := Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	return ctx, scope
}

func requireOwner(t *testing.T, scope *Scope, reader any) {
	t.Helper()
	index, generation, ok := ReaderOwner(reader).Identity()
	require.True(t, ok, "the reader has no exclusive owner")
	analysis, active := scope.Analysis()
	require.True(t, active)
	ownerIndex, _, ownerGeneration, _ := analysis.Identity()
	require.Equal(t, ownerIndex, index)
	require.Equal(t, ownerGeneration, generation)
}

func requireNoOwner(t *testing.T, reader any) {
	t.Helper()
	_, _, ok := ReaderOwner(reader).Identity()
	require.False(t, ok, "the reader has an exclusive owner")
}

func TestEntryBindingIsExclusive(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	type object struct{ value int }
	body := &object{value: 1}
	EagerHTTP(ctx, nil, nil, nil, nil, &object{value: 2}, body)
	requireOwner(t, scope, body)

	manual := strings.NewReader("manual")
	require.True(t, BindReader(ctx, manual))
	requireOwner(t, scope, manual)

	scope.Finish()
	requireNoOwner(t, body)
}

func TestPropagateReaderExclusivity(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	otherCtx, _ := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))

	// A wrapper that user code cannot retarget (io.TeeReader,
	// http.MaxBytesReader) of an exclusive input is exclusive.
	wrapper := new(strings.Reader)
	PropagateReader(input, wrapper)
	requireOwner(t, scope, wrapper)

	shared := new(strings.Reader)
	PropagateSharedReader(input, shared)
	requireNoOwner(t, shared)
	count, complete := lookupReader(shared, make([]store.OwnerRef, 4))
	require.True(t, complete)
	require.Equal(t, 1, count, "a shared propagation keeps a non-exclusive binding")

	// A reader of two owners is not exclusive, and its wrappers are not.
	twoOwners := strings.NewReader("two owners")
	require.True(t, BindReader(ctx, twoOwners))
	require.True(t, BindReader(otherCtx, twoOwners))
	requireNoOwner(t, twoOwners)
	fromTwo := new(strings.Reader)
	PropagateReader(twoOwners, fromTwo)
	requireNoOwner(t, fromTwo)

	// A wrapper of a non-exclusive input is not exclusive.
	fromShared := new(strings.Reader)
	PropagateReader(shared, fromShared)
	requireNoOwner(t, fromShared)

	// Unbound and non-pointer inputs give no binding.
	unbound := new(strings.Reader)
	PropagateReader(strings.NewReader("clean"), unbound)
	requireNoOwner(t, unbound)
	PropagateReader(strings.Reader{}, new(strings.Reader))
	requireNoOwner(t, nil)
}

func TestIncompleteLookupIsNotExclusive(t *testing.T) {
	enableForTest(t)
	ctx, _ := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))
	before := iobridge.GuardCountForTest()
	restore := SetIncompleteReaderLookupsForTest()
	t.Cleanup(restore)

	requireNoOwner(t, input)
	wrapper := new(strings.Reader)
	PropagateReader(input, wrapper)
	guarded := new(strings.Reader)
	PropagateGuardedReader(input, guarded)
	require.Equal(t, before, iobridge.GuardCountForTest(), "an incomplete lookup must not add a guard")
	restore()
	requireNoOwner(t, wrapper)
	requireNoOwner(t, guarded)
}

func TestPropagateGuardedReaderAddsGuard(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))
	before := iobridge.GuardCountForTest()

	wrapper := new(strings.Reader)
	PropagateGuardedReader(input, wrapper)
	requireOwner(t, scope, wrapper)
	require.Equal(t, before+1, iobridge.GuardCountForTest())
	var refs [4]store.OwnerRef
	count, complete := lookupReader(wrapper, refs[:])
	require.True(t, complete)
	require.Equal(t, 1, count)
	require.True(t, refs[0].ViaGuard)

	// A wrapper of the guarded wrapper depends on the guard too.
	tee := new(strings.Reader)
	PropagateReader(wrapper, tee)
	requireOwner(t, scope, tee)

	// Normal reads keep the exclusivity.
	for range 100 {
		iobridge.CheckRead(wrapper, input)
	}
	requireOwner(t, scope, wrapper)
	requireOwner(t, scope, tee)

	// A read from another target sets the retargeted bit of the owner.
	iobridge.CheckRead(wrapper, strings.NewReader("clean"))
	requireNoOwner(t, wrapper)
	requireNoOwner(t, tee)
	requireOwner(t, scope, input)
	require.Equal(t, before, iobridge.GuardCountForTest())
	analysis, _ := scope.Analysis()
	require.Equal(t, uint64(1), analysis.storeOwner().Counters().Retargets)
}

func TestPropagateGuardedReaderNonExclusiveInput(t *testing.T) {
	enableForTest(t)
	ctx, _ := beginForTest(t)
	otherCtx, _ := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))
	require.True(t, BindReader(otherCtx, input))
	before := iobridge.GuardCountForTest()
	wrapper := new(strings.Reader)
	PropagateGuardedReader(input, wrapper)
	require.Equal(t, before, iobridge.GuardCountForTest())
	requireNoOwner(t, wrapper)
	count, _ := lookupReader(wrapper, make([]store.OwnerRef, 4))
	require.Equal(t, 2, count, "the non-exclusive fanout stays")
}

func TestPropagateGuardedReaderFailedBindRemovesGuard(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))
	// Fill the reader bindings of the owner.
	for range store.MaxReaderBindings - 1 {
		require.True(t, BindReader(ctx, new(strings.Reader)))
	}
	before := iobridge.GuardCountForTest()
	wrapper := new(strings.Reader)
	PropagateGuardedReader(input, wrapper)
	require.Equal(t, before, iobridge.GuardCountForTest(), "a failed bind must remove its guard")
	requireNoOwner(t, wrapper)
	requireOwner(t, scope, input)
}

func TestFinishReleasesGuards(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))
	require.Zero(t, iobridge.GuardCountForTest())
	require.Zero(t, iobridge.GuardEntriesForTest())
	for range 4 {
		PropagateGuardedReader(input, new(strings.Reader))
	}
	require.Equal(t, 4, iobridge.GuardCountForTest())
	require.Equal(t, 4, iobridge.GuardEntriesForTest())
	scope.Finish()
	// The counter and each slot of the table are empty.
	require.Zero(t, iobridge.GuardCountForTest())
	require.Zero(t, iobridge.GuardEntriesForTest())
}

func TestNoActiveRequestReaderCallbacksDoNotAllocate(t *testing.T) {
	input, output := strings.NewReader("body"), new(strings.Reader)
	data := []byte("body")
	manager := processManager.Load()
	if manager != nil && manager.used.Load() != 0 {
		t.Skip("another request is active")
	}
	allocations := testing.AllocsPerRun(100, func() {
		PropagateReader(input, output)
		PropagateGuardedReader(input, output)
		PropagateJoinedReader(joined(input, input), 2, output)
		ReaderOwner(input)
		RevalidateReader(ReaderOwner(input), input)
		readAllEnd(input, data, readAllOwner(input))
	})
	require.Zero(t, allocations)
}

// TestActiveRequestReaderPropagationDoesNotAllocate checks that the input
// revalidation of rule (e) does not allocate.
func TestActiveRequestReaderPropagationDoesNotAllocate(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))
	tee, multi := new(strings.Reader), new(strings.Reader)
	allocations := testing.AllocsPerRun(100, func() {
		PropagateReader(input, tee)
		PropagateJoinedReader(joined(tee, input), 2, multi)
		ReaderOwner(multi)
		// The token of rule (f) and its revalidation.
		if !RevalidateReader(ReaderOwner(multi), multi) || !readAllOwner(input).OK {
			t.Fatal("the token is not valid")
		}
	})
	require.Zero(t, allocations)
	requireOwner(t, scope, multi)
}

func TestPropagateGuardedReaderFullGuardTableIsNotExclusive(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	input := strings.NewReader("body")
	require.True(t, BindReader(ctx, input))

	// Find a wrapper and 4 other objects with the same first probe slot of
	// the guard table (iobridge uses (address >> 4) % 128).
	objects := make([][16]byte, 4096)
	slot := func(object *[16]byte) uintptr { return (uintptr(unsafe.Pointer(object)) >> 4) % 128 }
	wrapper := &objects[0]
	var fillers []*[16]byte
	for index := 1; index < len(objects) && len(fillers) < 4; index++ {
		if slot(&objects[index]) == slot(wrapper) {
			fillers = append(fillers, &objects[index])
		}
	}
	require.Len(t, fillers, 4)
	for _, filler := range fillers {
		// The index is not an owner slot, thus these guards have no owner.
		require.True(t, iobridge.Guard(filler, filler, store.MaxOwners, 1))
		t.Cleanup(func() { iobridge.Unguard(filler) })
	}

	PropagateGuardedReader(input, wrapper)
	requireNoOwner(t, wrapper)
	count, _ := lookupReader(wrapper, make([]store.OwnerRef, 4))
	require.Equal(t, 1, count, "a wrapper with no guard gets a non-exclusive binding")
	analysis, _ := scope.Analysis()
	require.Equal(t, uint64(1), analysis.storeOwner().Counters().GuardFull)
	runtime.KeepAlive(objects)
}

func joined(inputs ...any) [iobridge.MaxJoinInputs]any {
	var result [iobridge.MaxJoinInputs]any
	copy(result[:], inputs)
	return result
}

func TestPropagateJoinedReader(t *testing.T) {
	enableForTest(t)
	for name, test := range map[string]struct {
		inputs    func(first, second, other any) ([iobridge.MaxJoinInputs]any, int)
		exclusive bool
		owners    int
	}{
		"one input": {inputs: func(first, _, _ any) ([iobridge.MaxJoinInputs]any, int) {
			return joined(first), 1
		}, exclusive: true, owners: 1},
		"two inputs, one owner": {inputs: func(first, second, _ any) ([iobridge.MaxJoinInputs]any, int) {
			return joined(first, second), 2
		}, exclusive: true, owners: 1},
		"eight inputs": {inputs: func(first, second, _ any) ([iobridge.MaxJoinInputs]any, int) {
			return joined(first, second, first, second, first, second, first, second), 8
		}, exclusive: true, owners: 1},
		"nine inputs": {inputs: func(first, second, _ any) ([iobridge.MaxJoinInputs]any, int) {
			return joined(first, second, first, second, first, second, first, second), 9
		}, owners: 1},
		"two owners": {inputs: func(first, _, other any) ([iobridge.MaxJoinInputs]any, int) {
			return joined(first, other), 2
		}, owners: 2},
		"clean input": {inputs: func(first, _, _ any) ([iobridge.MaxJoinInputs]any, int) {
			return joined(strings.NewReader("clean"), first), 2
		}, owners: 1},
		"no input": {inputs: func(_, _, _ any) ([iobridge.MaxJoinInputs]any, int) {
			return joined(), 0
		}},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			otherCtx, _ := beginForTest(t)
			first, second, other := strings.NewReader("first"), strings.NewReader("second"), strings.NewReader("other")
			require.True(t, BindReader(ctx, first))
			require.True(t, BindReader(ctx, second))
			require.True(t, BindReader(otherCtx, other))
			output := new(strings.Reader)
			inputs, count := test.inputs(first, second, other)
			PropagateJoinedReader(inputs, count, output)
			if test.exclusive {
				requireOwner(t, scope, output)
			} else {
				requireNoOwner(t, output)
			}
			found, complete := lookupReader(output, make([]store.OwnerRef, 4))
			require.True(t, complete)
			require.Equal(t, test.owners, found)
		})
	}
}

// TestPropagateJoinedReaderOwnerChangeAfterLookup checks review finding 1 of
// batch 1: the owner of the inputs ends after the input lookups, and one
// input then gets a new owner B, while the other input still has the bytes of
// A. The output must not be exclusive to B.
func TestPropagateJoinedReaderOwnerChangeAfterLookup(t *testing.T) {
	enableForTest(t)
	ctxA, scopeA := beginForTest(t)
	ctxB, _ := beginForTest(t)
	x, y := strings.NewReader("bytes of A"), strings.NewReader("bytes of A, then B")
	require.True(t, BindReader(ctxA, x))
	require.True(t, BindReader(ctxA, y))
	hook := func() {
		scopeA.Finish()
		require.True(t, BindReader(ctxB, y))
	}
	joinHookForTest.Store(&hook)
	t.Cleanup(func() { joinHookForTest.Store(nil) })

	output := new(strings.Reader)
	PropagateJoinedReader(joined(x, y), 2, output)
	requireNoOwner(t, output)
}

// TestDerivedBindingLosesExclusivityWhenInputGetsSecondOwner checks rule (e)
// of plan encoding-json-v2, section 6.5 (review finding 2 of batch 1): a
// wrapper binding that is exclusive to A stops being exclusive when its input
// (or an input of its input) gets a binding of a second live owner B.
func TestDerivedBindingLosesExclusivityWhenInputGetsSecondOwner(t *testing.T) {
	enableForTest(t)
	for name, build := range derivedBuilders() {
		t.Run(name, func(t *testing.T) {
			ctxA, scopeA := beginForTest(t)
			ctxB, _ := beginForTest(t)
			body := strings.NewReader("body")
			require.True(t, BindReader(ctxA, body))
			wrapper := build(body)
			requireOwner(t, scopeA, wrapper)
			require.True(t, BindReader(ctxB, body))
			requireNoOwner(t, body)
			requireNoOwner(t, wrapper)
		})
	}
	t.Run("second owner of an intermediate wrapper", func(t *testing.T) {
		ctxA, scopeA := beginForTest(t)
		ctxB, _ := beginForTest(t)
		body := strings.NewReader("body")
		require.True(t, BindReader(ctxA, body))
		inner, outer := new(strings.Reader), new(strings.Reader)
		PropagateReader(body, inner)
		PropagateReader(inner, outer)
		requireOwner(t, scopeA, outer)
		require.True(t, BindReader(ctxB, inner))
		requireOwner(t, scopeA, body)
		requireNoOwner(t, outer)
	})
}

// TestDerivedBindingStaysNotExclusiveAfterSecondOwnerEnds checks that the
// loss of rule (e) is sticky (follow-up review 1 of batch 1, finding 1): the
// input of a wrapper of A gets a binding of B, B ends, and the wrapper stays
// not exclusive. While B was live, the wrapper could read or buffer bytes of
// B.
func TestDerivedBindingStaysNotExclusiveAfterSecondOwnerEnds(t *testing.T) {
	enableForTest(t)
	for name, build := range derivedBuilders() {
		t.Run(name, func(t *testing.T) {
			ctxA, scopeA := beginForTest(t)
			ctxB, scopeB := beginForTest(t)
			body := strings.NewReader("body")
			require.True(t, BindReader(ctxA, body))
			wrapper := build(body)
			requireOwner(t, scopeA, wrapper)
			require.True(t, BindReader(ctxB, body))
			requireNoOwner(t, wrapper)
			scopeB.Finish()
			// Only A is bound to the input now, but the bind of B is in
			// the counter of the input: the loss is sticky for the input
			// too (rule (f)).
			require.Equal(t, 1, LookupObject(body, store.BindingReader, make([]store.OwnerRef, 4)))
			requireNoOwner(t, body)
			requireNoOwner(t, wrapper)
		})
	}
}

// derivedBuilders returns functions that make a derived exclusive binding of
// a new reader over input, with the propagation functions of this package.
func derivedBuilders() map[string]func(input any) any {
	return map[string]func(input any) any{
		"PropagateReader": func(input any) any {
			output := new(strings.Reader)
			PropagateReader(input, output)
			return output
		},
		"PropagateGuardedReader": func(input any) any {
			output := new(strings.Reader)
			PropagateGuardedReader(input, output)
			return output
		},
		"PropagateJoinedReader": func(input any) any {
			output := new(strings.Reader)
			PropagateJoinedReader(joined(input, input), 2, output)
			return output
		},
		"chain of three wrappers": func(input any) any {
			guarded := new(strings.Reader)
			PropagateGuardedReader(input, guarded)
			joinedOutput := new(strings.Reader)
			PropagateJoinedReader(joined(guarded), 1, joinedOutput)
			output := new(strings.Reader)
			PropagateReader(joinedOutput, output)
			return output
		},
	}
}
