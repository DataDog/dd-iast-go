// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// The tests of this file check the JSON bridge helpers ReaderOwnerToken and
// CloneForOwner, through jsonbridge.ReaderBinding, with the real store. The
// woven decoder tests are in iast/encoding/json.

// registerJSONForTest registers the request helpers as the JSON bridge
// callbacks, and turns the v2 flag on, so that jsonbridge.ReaderDocument
// calls CloneForOwner.
func registerJSONForTest(t *testing.T) {
	t.Helper()
	jsonbridge.Register(jsonbridge.Callbacks{
		Literal: func([]byte, []byte, reflect.Value, error) {},
		Owner:   ReaderOwnerToken,
		Clone:   CloneForOwner,
		// The string cache guard is not used by these tests.
		MayBeTainted: func([]byte) bool { return true },
	})
	t.Cleanup(jsonbridge.SetV2ForTest(true))
}

// decodeValue gives one value to the binding, as one Decode does, and reports
// whether the value was cloned for an owner.
func decodeValue(binding *jsonbridge.ReaderBinding, value []byte) bool {
	got := jsonbridge.ReaderDocument(binding, value)
	return unsafe.SliceData(got) != unsafe.SliceData(value)
}

// requireClosed checks that binding never propagates again.
func requireClosed(t *testing.T, binding *jsonbridge.ReaderBinding) {
	t.Helper()
	state := new(int)
	if jsonbridge.BindDecoder(binding, state) {
		jsonbridge.Unbind(state)
		t.Fatal("the binding is not closed")
	}
}

// requireOpen checks that binding can propagate.
func requireOpen(t *testing.T, binding *jsonbridge.ReaderBinding) {
	t.Helper()
	state := new(int)
	require.True(t, jsonbridge.BindDecoder(binding, state), "the binding is closed")
	jsonbridge.Unbind(state)
}

func TestReaderOwnerTokenCaptureStates(t *testing.T) {
	enableForTest(t)
	registerJSONForTest(t)
	value := []byte(`{"a":"value"}`)
	for name, test := range map[string]struct {
		reader    func(t *testing.T, ctx, otherCtx context.Context) any
		exclusive bool
	}{
		"zero owners": {reader: func(*testing.T, context.Context, context.Context) any { return strings.NewReader("x") }},
		"one exclusive owner": {reader: func(t *testing.T, ctx, _ context.Context) any {
			reader := strings.NewReader("x")
			require.True(t, BindReader(ctx, reader))
			return reader
		}, exclusive: true},
		"one owner, not exclusive": {reader: func(t *testing.T, ctx, _ context.Context) any {
			input := strings.NewReader("x")
			require.True(t, BindReader(ctx, input))
			output := new(strings.Reader)
			PropagateSharedReader(input, output)
			return output
		}},
		"two owners": {reader: func(t *testing.T, ctx, otherCtx context.Context) any {
			reader := strings.NewReader("x")
			require.True(t, BindReader(ctx, reader))
			require.True(t, BindReader(otherCtx, reader))
			return reader
		}},
		"incomplete lookup": {reader: func(t *testing.T, ctx, _ context.Context) any {
			reader := strings.NewReader("x")
			require.True(t, BindReader(ctx, reader))
			t.Cleanup(SetIncompleteReaderLookupsForTest())
			return reader
		}},
		"nil reader": {reader: func(*testing.T, context.Context, context.Context) any { return nil }},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			otherCtx, other := beginOther(t)
			reader := test.reader(t, ctx, otherCtx)
			binding := new(jsonbridge.ReaderBinding)
			binding.Capture(reader)
			analysis, _ := scope.Analysis()
			otherAnalysis, _ := other.Analysis()
			require.Equal(t, test.exclusive, decodeValue(binding, value))
			if test.exclusive {
				requireOpen(t, binding)
				require.Equal(t, 1, analysis.SourceCount())
			} else {
				requireClosed(t, binding)
				require.Zero(t, analysis.SourceCount())
			}
			require.Zero(t, otherAnalysis.SourceCount())
		})
	}
}

func TestReaderOwnerTokenNoActiveRequest(t *testing.T) {
	enableForTest(t)
	registerJSONForTest(t)
	reader := strings.NewReader("x")
	binding := new(jsonbridge.ReaderBinding)
	if ActiveStore() == nil {
		// No request is active: Capture does nothing (state "none").
		binding.Capture(reader)
	}
	ctx, scope := beginForTest(t)
	require.True(t, BindReader(ctx, reader))
	require.False(t, decodeValue(binding, []byte(`{"a":"b"}`)), "a decoder made with no active request propagated")
	analysis, _ := scope.Analysis()
	require.Zero(t, analysis.SourceCount())
}

// TestCloneForOwnerClosesOnFailedRevalidation checks the cases where the
// token of NewDecoder fails at Decode: then the decoder is closed for good.
func TestCloneForOwnerClosesOnFailedRevalidation(t *testing.T) {
	enableForTest(t)
	registerJSONForTest(t)
	value := []byte(`{"a":"value"}`)
	for name, change := range map[string]func(t *testing.T, scope *Scope, reader *strings.Reader){
		"finished owner": func(_ *testing.T, scope *Scope, _ *strings.Reader) { scope.Finish() },
		"new owner at Decode": func(t *testing.T, _ *Scope, reader *strings.Reader) {
			otherCtx, _ := beginOther(t)
			require.True(t, BindReader(otherCtx, reader))
		},
		"second owner that ended before Decode": func(t *testing.T, _ *Scope, reader *strings.Reader) {
			otherCtx, other := beginOther(t)
			require.True(t, BindReader(otherCtx, reader))
			other.Finish()
		},
		"incomplete lookup at Decode": func(t *testing.T, _ *Scope, _ *strings.Reader) {
			t.Cleanup(SetIncompleteReaderLookupsForTest())
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			reader := strings.NewReader("x")
			require.True(t, BindReader(ctx, reader))
			binding := new(jsonbridge.ReaderBinding)
			binding.Capture(reader)
			require.True(t, decodeValue(binding, value), "control: the first value propagates")
			change(t, scope, reader)
			require.False(t, decodeValue(binding, value))
			requireClosed(t, binding)
		})
	}
	t.Run("incomplete lookup is sticky", func(t *testing.T) {
		ctx, scope := beginForTest(t)
		reader := strings.NewReader("x")
		require.True(t, BindReader(ctx, reader))
		binding := new(jsonbridge.ReaderBinding)
		binding.Capture(reader)
		restore := SetIncompleteReaderLookupsForTest()
		require.False(t, decodeValue(binding, value))
		restore()
		require.False(t, decodeValue(binding, value), "a closed decoder propagated again")
		analysis, _ := scope.Analysis()
		require.Zero(t, analysis.SourceCount())
	})
}

// TestCloneForOwnerReusedOwnerSlot checks that a token of a finished owner
// fails also when a new owner gets the same store slot (a new generation) and
// binds the same reader.
func TestCloneForOwnerReusedOwnerSlot(t *testing.T) {
	enableForTest(t)
	registerJSONForTest(t)
	ctx, scope := beginForTest(t)
	reader := strings.NewReader("x")
	require.True(t, BindReader(ctx, reader))
	binding := new(jsonbridge.ReaderBinding)
	binding.Capture(reader)
	token := ReaderOwnerToken(reader)
	require.True(t, token.OK)
	scope.Finish()

	var reused *Scope
	var reusedCtx context.Context
	for range MaxAnalyses {
		candidateCtx, candidate := beginOther(t)
		analysis, ok := candidate.Analysis()
		require.True(t, ok)
		index, _, generation, _ := analysis.Identity()
		if index == token.Index {
			require.NotEqual(t, token.Generation, generation)
			reused, reusedCtx = candidate, candidateCtx
			break
		}
	}
	require.NotNil(t, reused, "no new request got the store slot of the finished owner")
	require.True(t, BindReader(reusedCtx, reader))
	require.False(t, decodeValue(binding, []byte(`{"a":"value"}`)))
	requireClosed(t, binding)
	analysis, _ := reused.Analysis()
	require.Zero(t, analysis.SourceCount(), "the value was attributed to the new owner of the slot")
}

func TestCloneForOwnerValues(t *testing.T) {
	enableForTest(t)
	registerJSONForTest(t)
	ctx, scope := beginForTest(t)
	analysis, _ := scope.Analysis()
	reader := strings.NewReader("x")
	require.True(t, BindReader(ctx, reader))
	token := ReaderOwnerToken(reader)
	require.True(t, token.OK)

	// Bad tokens.
	for name, bad := range map[string]jsonbridge.OwnerToken{
		"zero":           {},
		"no store":       {Generation: token.Generation, Index: token.Index, Entry: token.Entry, OK: true},
		"other store":    {Store: new(int), Generation: token.Generation, Index: token.Index, Entry: token.Entry, OK: true},
		"not OK":         {Store: token.Store, Generation: token.Generation, Index: token.Index, Entry: token.Entry},
		"old generation": {Store: token.Store, Generation: token.Generation - 1, Index: token.Index, Entry: token.Entry, OK: true},
		"other slot":     {Store: token.Store, Generation: token.Generation, Index: token.Index + 1, Entry: token.Entry, OK: true},
		"other entry":    {Store: token.Store, Generation: token.Generation, Index: token.Index, Entry: token.Entry + 1, OK: true},
	} {
		clone, proven := CloneForOwner(reader, bad, []byte("body"))
		require.Nil(t, clone, name)
		require.False(t, proven, name)
	}
	clone, proven := CloneForOwner(nil, token, []byte("body"))
	require.Nil(t, clone)
	require.False(t, proven, "a nil reader is not the reader of the token")
	require.Zero(t, analysis.SourceCount())

	// A short or oversized value is a miss for this value only.
	clone, proven = CloneForOwner(reader, token, []byte("x"))
	require.Nil(t, clone)
	require.True(t, proven)
	drops := analysis.storeOwner().Counters().Bytes
	clone, proven = CloneForOwner(reader, token, make([]byte, store.MaxRootBytes+1))
	require.Nil(t, clone)
	require.True(t, proven)
	require.Equal(t, drops+1, analysis.storeOwner().Counters().Bytes)
	require.Zero(t, analysis.SourceCount())

	// A valid value: an exact-capacity clone, adopted into the owner only.
	data := make([]byte, 4, 16)
	copy(data, "body")
	clone, proven = CloneForOwner(reader, token, data)
	require.True(t, proven)
	require.Equal(t, data, clone)
	require.Equal(t, len(clone), cap(clone))
	data[0] = 'x'
	require.Equal(t, []byte("body"), clone)
	require.Equal(t, 1, analysis.SourceCount())
	require.True(t, IsTaintedBytes(clone))
	require.False(t, IsTaintedBytes(data))
}

// TestReaderDocumentWithNoIndexedRoot checks that the first source of a
// request can be its JSON body: the binding needs an active owner, not an
// indexed root.
func TestReaderDocumentWithNoIndexedRoot(t *testing.T) {
	enableForTest(t)
	registerJSONForTest(t)
	ctx, scope := beginForTest(t)
	// Each other test finished its requests, thus the process has no indexed
	// root. The test must not skip: it checks the zero-root case.
	require.Zero(t, ActiveStore().IndexedRoots().Load(), "the process has an indexed root before the clone")
	reader := strings.NewReader("x")
	require.True(t, BindReader(ctx, reader))
	binding := new(jsonbridge.ReaderBinding)
	binding.Capture(reader)
	require.False(t, jsonbridge.Active())
	require.True(t, decodeValue(binding, []byte(`{"a":"value"}`)))
	analysis, _ := scope.Analysis()
	require.Equal(t, 1, analysis.SourceCount())
	require.True(t, jsonbridge.Active(), "the clone is an indexed root")
}

func TestCloneReaderBytesNeedsOneExclusiveOwner(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	otherCtx, other := beginOther(t)
	reader := strings.NewReader("x")
	require.True(t, BindReader(ctx, reader))
	require.NotNil(t, CloneReaderBytes(reader, []byte("body")))
	require.True(t, BindReader(otherCtx, reader))
	require.Nil(t, CloneReaderBytes(reader, []byte("body")))
	analysis, _ := scope.Analysis()
	otherAnalysis, _ := other.Analysis()
	require.Equal(t, 1, analysis.SourceCount())
	require.Zero(t, otherAnalysis.SourceCount())
}

func TestCloneForOwnerActiveDoesNotAllocateOnMiss(t *testing.T) {
	enableForTest(t)
	ctx, _ := beginForTest(t)
	reader := strings.NewReader("x")
	require.True(t, BindReader(ctx, reader))
	token := ReaderOwnerToken(reader)
	short := []byte("x")
	require.Zero(t, testing.AllocsPerRun(100, func() {
		if !ReaderOwnerToken(reader).OK {
			panic("no token")
		}
		if _, proven := CloneForOwner(reader, token, short); !proven {
			panic("not proven")
		}
	}))
}

// TestCloneForOwnerFailedAdoptionKeepsBindingOpen checks a real failure of
// adoptBodyBytes with a valid token: CloneForOwner returns (nil, true), the
// value is a miss, and the binding stays open (the failure is not a proof
// failure). When the cause goes away, a later value propagates.
func TestCloneForOwnerFailedAdoptionKeepsBindingOpen(t *testing.T) {
	enableForTest(t)
	registerJSONForTest(t)
	value := []byte(`{"a":"value"}`)
	for name, test := range map[string]struct {
		// during runs attempt while the adoption of analysis fails.
		during    func(t *testing.T, analysis Analysis, attempt func())
		recovered bool
	}{
		"source table full": {during: func(t *testing.T, analysis Analysis, attempt func()) {
			for i := 0; i < MaxSources; i++ {
				_, ok := analysis.TaintString(constants.OriginHttpRequestHeader, "name", fmt.Sprintf("value-%03d", i))
				require.True(t, ok, "source %d", i)
			}
			require.Equal(t, MaxSources, analysis.SourceCount())
			attempt()
		}},
		"source lock contended": {during: func(_ *testing.T, analysis Analysis, attempt func()) {
			analysis.slot.sourceMu.Lock()
			defer analysis.slot.sourceMu.Unlock()
			attempt()
		}, recovered: true},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			analysis, ok := scope.Analysis()
			require.True(t, ok)
			reader := strings.NewReader("x")
			require.True(t, BindReader(ctx, reader))
			token := ReaderOwnerToken(reader)
			require.True(t, token.OK)
			binding := new(jsonbridge.ReaderBinding)
			binding.Capture(reader)

			test.during(t, analysis, func() {
				clone, proven := CloneForOwner(reader, token, value)
				require.Nil(t, clone, "a failed adoption returned a clone")
				require.True(t, proven, "a failed adoption is not a proof failure")
				require.False(t, decodeValue(binding, value), "a failed adoption propagated")
			})
			requireOpen(t, binding)
			if !test.recovered {
				require.Equal(t, MaxSources, analysis.SourceCount())
				return
			}
			require.Zero(t, analysis.SourceCount())
			require.True(t, decodeValue(binding, value), "the open binding must propagate a later value")
			require.Equal(t, 1, analysis.SourceCount())
		})
	}
}
