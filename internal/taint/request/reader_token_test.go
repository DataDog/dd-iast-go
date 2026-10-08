// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// The tests of this file check reader binding rule (f) (see the
// internal/taint/store package doc) at the consumers of the request package:
// ReaderOwner + RevalidateReader, ReadAllBytesForToken (io.ReadAll), and
// CloneReaderBytesForToken.

// consumers are the attribution paths of a reader token. Each returns true
// when it attributed data to an owner.
func tokenConsumers() map[string]func(token ReaderToken, input any, analysis Analysis) bool {
	return map[string]func(token ReaderToken, input any, analysis Analysis) bool{
		"RevalidateReader": func(token ReaderToken, input any, _ Analysis) bool {
			return RevalidateReader(token, input)
		},
		"ReadAllBytesForToken": func(token ReaderToken, input any, analysis Analysis) bool {
			before := analysis.SourceCount()
			ReadAllBytesForToken(token, input, []byte("body bytes"))
			return analysis.SourceCount() > before
		},
		"CloneReaderBytesForToken": func(token ReaderToken, input any, analysis Analysis) bool {
			before := analysis.SourceCount()
			clone := CloneReaderBytesForToken(token, input, []byte("body bytes"))
			if (clone != nil) != (analysis.SourceCount() > before) {
				panic("the clone and the source do not agree")
			}
			return clone != nil
		},
	}
}

// beginOther starts a second request scope. The test must call Finish.
func beginOther(t *testing.T) (context.Context, *Scope) {
	t.Helper()
	ctx, scope, created := Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	return ctx, scope
}

// TestReaderTokenMissesSecondOwnerThatEnded is the gap of rule (f): B binds
// the root reader of A while A is bound, the data is read or buffered, and B
// ends. A lookup of the reader then finds only A again. The token that A took
// before the data flowed must be a miss for each consumer.
func TestReaderTokenMissesSecondOwnerThatEnded(t *testing.T) {
	enableForTest(t)
	for name, consume := range tokenConsumers() {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			analysis, ok := scope.Analysis()
			require.True(t, ok)
			reader := strings.NewReader("body")
			require.True(t, BindReader(ctx, reader))
			token := ReaderOwner(reader)
			require.True(t, token.OK())

			// The data is read while B is bound, then B ends.
			otherCtx, other := beginOther(t)
			require.True(t, BindReader(otherCtx, reader))
			other.Finish()
			require.Equal(t, 1, LookupObject(reader, store.BindingReader, make([]store.OwnerRef, 4)),
				"only A is bound to the reader after B ended")

			require.False(t, consume(token, reader, analysis),
				"the data was attributed to A after B bound the reader and ended")
			// A token taken after B ended is not OK either.
			require.False(t, ReaderOwner(reader).OK())
			require.False(t, consume(ReaderOwner(reader), reader, analysis))
		})
	}
}

// TestReaderTokenMissesBindBetweenCaptureAndRevalidation checks rule (f) with
// the test hook of revalidateReader: B binds the reader and ends after the
// capture and before the lookup of the revalidation.
func TestReaderTokenMissesBindBetweenCaptureAndRevalidation(t *testing.T) {
	enableForTest(t)
	for name, consume := range tokenConsumers() {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			analysis, ok := scope.Analysis()
			require.True(t, ok)
			reader := strings.NewReader("body")
			require.True(t, BindReader(ctx, reader))
			token := ReaderOwner(reader)
			require.True(t, token.OK())

			otherCtx, other := beginOther(t)
			hook := func() {
				require.True(t, BindReader(otherCtx, reader))
				other.Finish()
			}
			revalidateHookForTest.Store(&hook)
			t.Cleanup(func() { revalidateHookForTest.Store(nil) })
			require.False(t, consume(token, reader, analysis),
				"a bind of B between the capture and the revalidation was not found")
			revalidateHookForTest.Store(nil)
			require.False(t, ReaderOwner(reader).OK(), "the loss is sticky (rule (f))")
			// Control: a reader that B did not bind keeps a valid token.
			clean := strings.NewReader("clean")
			require.True(t, BindReader(ctx, clean))
			require.True(t, consume(ReaderOwner(clean), clean, analysis))
		})
	}
}

// TestReaderTokenKeepsOwnRebind checks that a rebind of its own root by the
// owner of the token does not remove its exclusivity.
func TestReaderTokenKeepsOwnRebind(t *testing.T) {
	enableForTest(t)
	for name, consume := range tokenConsumers() {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			analysis, ok := scope.Analysis()
			require.True(t, ok)
			reader := strings.NewReader("body")
			require.True(t, BindReader(ctx, reader))
			token := ReaderOwner(reader)
			require.True(t, BindReader(ctx, reader))
			PropagateReader(reader, new(strings.Reader))
			require.True(t, consume(token, reader, analysis), "a rebind of the own root removed the exclusivity")
		})
	}
}

// TestReaderTokenOfFinishedOwnerIsMiss checks that a token of an owner that
// finished is a miss.
func TestReaderTokenOfFinishedOwnerIsMiss(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	reader := strings.NewReader("body")
	require.True(t, BindReader(ctx, reader))
	token := ReaderOwner(reader)
	require.True(t, token.OK())
	scope.Finish()
	require.False(t, RevalidateReader(token, reader))
	require.False(t, RevalidateReader(ReaderToken{}, reader))
	require.Nil(t, CloneReaderBytesForToken(token, reader, []byte("body")))
	ReadAllBytesForToken(token, reader, []byte("body"))
}

// TestWrapperBuiltAfterSecondOwnerEndedIsNotExclusive checks the sticky loss of
// rule (f) at the propagation functions: A binds the body, B binds it and
// ends, and only then A builds a wrapper over the body. The wrapper must not
// be exclusive, and a token of the body or of the wrapper must not be OK.
func TestWrapperBuiltAfterSecondOwnerEndedIsNotExclusive(t *testing.T) {
	enableForTest(t)
	for name, build := range derivedBuilders() {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginForTest(t)
			analysis, ok := scope.Analysis()
			require.True(t, ok)
			body := strings.NewReader("body")
			require.True(t, BindReader(ctx, body))
			otherCtx, other := beginOther(t)
			require.True(t, BindReader(otherCtx, body))
			other.Finish()

			wrapper := build(body)
			require.Equal(t, 1, LookupObject(wrapper, store.BindingReader, make([]store.OwnerRef, 4)),
				"the wrapper is bound to A")
			requireNoOwner(t, wrapper)
			requireNoOwner(t, body)
			for consumerName, consume := range tokenConsumers() {
				require.False(t, consume(ReaderOwner(wrapper), wrapper, analysis), consumerName)
			}
		})
	}
}

// TestRetargetCallbackFailureFailsClosed checks the fail-closed rule (a2): the
// Retarget callback panics, thus the retargeted bit of the owner is not
// set, and CheckRead removes the guard. A guarded wrapper, and each binding
// over it, must then not be exclusive (iobridge.RetargetLost). A binding with
// no guard is not changed.
func TestRetargetCallbackFailureFailsClosed(t *testing.T) {
	enableForTest(t)
	ctx, scope := beginForTest(t)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	body := strings.NewReader("body")
	require.True(t, BindReader(ctx, body))
	limit := &io.LimitedReader{R: body, N: 4}
	PropagateGuardedReader(body, limit)
	tee := new(strings.Reader)
	PropagateReader(limit, tee)
	requireOwner(t, scope, limit)
	requireOwner(t, scope, tee)
	tokens := map[string]ReaderToken{"limit": ReaderOwner(limit), "tee": ReaderOwner(tee)}
	readers := map[string]any{"limit": limit, "tee": tee}

	hook := func() { panic("retarget callback failure") }
	retargetHookForTest.Store(&hook)
	t.Cleanup(func() {
		retargetHookForTest.Store(nil)
		iobridge.ResetRetargetLostForTest()
	})
	iobridge.CheckRead(limit, strings.NewReader("other"))
	require.True(t, iobridge.RetargetLost())
	require.Zero(t, analysis.storeOwner().Counters().Retargets, "the bit was set")

	for name, reader := range readers {
		requireNoOwner(t, reader)
		for consumerName, consume := range tokenConsumers() {
			require.False(t, consume(tokens[name], reader, analysis), name+"/"+consumerName)
		}
	}
	requireOwner(t, scope, body)
}

// TestContentionDuringRevalidationIsMiss checks rule (b) at revalidation: a
// token is valid, but a binding table is locked while the revalidation
// looks up the reader. The lookup is incomplete, thus each consumer must miss.
// The same token is valid again after the release.
func TestContentionDuringRevalidationIsMiss(t *testing.T) {
	enableForTest(t)
	for _, holder := range []string{"owner", "other owner"} {
		for name, consume := range tokenConsumers() {
			t.Run(holder+"/"+name, func(t *testing.T) {
				ctx, scope := beginForTest(t)
				analysis, ok := scope.Analysis()
				require.True(t, ok)
				reader := strings.NewReader("body")
				require.True(t, BindReader(ctx, reader))
				token := ReaderOwner(reader)
				require.True(t, token.OK())
				held := analysis
				if holder == "other owner" {
					_, other := beginOther(t)
					held, ok = other.Analysis()
					require.True(t, ok)
				}

				var release func()
				hook := func() { release = store.HoldBindingTableForTest(held.storeOwner()) }
				revalidateHookForTest.Store(&hook)
				t.Cleanup(func() { revalidateHookForTest.Store(nil) })
				attributed := consume(token, reader, analysis)
				revalidateHookForTest.Store(nil)
				require.NotNil(t, release)
				release()
				require.False(t, attributed, "an incomplete revalidation attributed data")
				require.True(t, consume(token, reader, analysis), "control: the token is valid after the release")
			})
		}
	}
}
