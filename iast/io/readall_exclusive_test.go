// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package io_test

import (
	"bufio"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// The tests of this file are the io.ReadAll consumer tests of plan
// encoding-json-v2, step 3a, for the guarded wrappers of section 6.6: a
// retargeted wrapper, a wrapper with no Read guard, and normal use.

// readAllRetargets returns the six retargets of step 2b. Each builds a
// guarded wrapper over body, and returns a function that retargets it to
// other.
func readAllRetargets() map[string]func(body io.Reader) (io.Reader, func(other io.Reader)) {
	limited := func(body io.Reader) *io.LimitedReader { return io.LimitReader(body, 1<<20).(*io.LimitedReader) }
	return map[string]func(io.Reader) (io.Reader, func(io.Reader)){
		"lr.R = other": func(body io.Reader) (io.Reader, func(io.Reader)) {
			lr := limited(body)
			return lr, func(other io.Reader) { lr.R = other }
		},
		"*lr = LimitedReader{other}": func(body io.Reader) (io.Reader, func(io.Reader)) {
			lr := limited(body)
			return lr, func(other io.Reader) { *lr = io.LimitedReader{R: other, N: 1 << 20} }
		},
		"br.Reset(other)": func(body io.Reader) (io.Reader, func(io.Reader)) {
			br := bufio.NewReaderSize(body, 16)
			return br, func(other io.Reader) { br.Reset(other) }
		},
		"*br = *bufio.NewReader(other)": func(body io.Reader) (io.Reader, func(io.Reader)) {
			br := bufio.NewReaderSize(body, 16)
			return br, func(other io.Reader) { *br = *bufio.NewReader(other) }
		},
	}
}

// TestReadAllRetargetedWrapperIsMiss checks that io.ReadAll of a retargeted
// guarded wrapper is a miss: no new source in A, no source in B. The new
// target is clean or the body of a live request B. The retarget comes before
// io.ReadAll (no byte of the new target flowed when io.ReadAll takes its
// token) or during the reads.
func TestReadAllRetargetedWrapperIsMiss(t *testing.T) {
	requireWoven(t)
	for name, build := range readAllRetargets() {
		for _, target := range []string{"clean", "body of B"} {
			for _, when := range []string{"before io.ReadAll", "during the reads"} {
				t.Run(name+"/"+target+"/"+when, func(t *testing.T) {
					ctxA, scopeA := activeContext(t)
					ctxB, scopeB := activeContext(t)
					body := &steppedReader{data: []byte("request-body-of-a")}
					require.True(t, request.BindReader(ctxA, body))
					wrapper, retarget := build(body)
					var other io.Reader = strings.NewReader("other-bytes")
					if target == "body of B" {
						other = boundBody(t, ctxB, "other-bytes")
					}
					if when == "before io.ReadAll" {
						retarget(other)
					} else {
						body.onRead = func() { retarget(other) }
					}
					data, err := io.ReadAll(wrapper)
					require.NoError(t, err)
					require.Contains(t, string(data), "other-bytes")
					requireReadAllMiss(t, ctxA, data, scopeA, scopeB)
					requireReadAllMiss(t, ctxB, data)
				})
			}
		}
	}
}

func TestReadAllLimitReaderOfRetargetedBufioIsMiss(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	body := boundBody(t, ctx, "request-body")
	buffered := bufio.NewReaderSize(body, 16)
	limited := io.LimitReader(buffered, 1<<20)
	buffered.Reset(strings.NewReader("clean-bytes"))
	data, err := io.ReadAll(limited)
	require.NoError(t, err)
	require.Equal(t, "clean-bytes", string(data))
	requireReadAllMiss(t, ctx, data, scope)
}

// TestReadAllGuardedWrappersNormalUse checks that io.ReadAll of a guarded
// wrapper keeps the taint while the wrapper is not retargeted, also when a
// Reset with no Read after it (the pool Put pattern) follows. The root reader
// gives 7 bytes for each Read, thus each io.ReadAll does many guarded Reads.
func TestReadAllGuardedWrappersNormalUse(t *testing.T) {
	requireWoven(t)
	body := strings.Repeat("x", 300)
	for name, build := range map[string]func(io.Reader) io.Reader{
		"bufio":            func(body io.Reader) io.Reader { return bufio.NewReader(body) },
		"limit":            func(body io.Reader) io.Reader { return io.LimitReader(body, 1<<20) },
		"limit over bufio": func(body io.Reader) io.Reader { return io.LimitReader(bufio.NewReaderSize(body, 16), 1<<20) },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, _ := activeContext(t)
			root := &steppedReader{data: []byte(body)}
			require.True(t, request.BindReader(ctx, root))
			data, err := io.ReadAll(build(root))
			require.NoError(t, err)
			requireBodyRange(t, ctx, data, body)
		})
	}
	t.Run("bufio Reset(nil) after io.ReadAll", func(t *testing.T) {
		ctx, _ := activeContext(t)
		buffered := bufio.NewReaderSize(boundBody(t, ctx, body), 16)
		data, err := io.ReadAll(buffered)
		require.NoError(t, err)
		buffered.Reset(nil)
		requireBodyRange(t, ctx, data, body)
	})
}

// TestReadAllWrapperWithNoReadGuardIsMiss checks that a guarded wrapper that
// got no Read guard entry (a full guard table) is not exclusive, thus
// io.ReadAll attributes nothing.
func TestReadAllWrapperWithNoReadGuardIsMiss(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	body := boundBody(t, ctx, "request-body")
	require.Zero(t, iobridge.GuardEntriesForTest(), "a guard of another test is live")

	// Fill each slot of the guard table. The index is not an owner slot,
	// thus these guards have no owner.
	fillers := make([][16]byte, 4096)
	for index := range fillers {
		if iobridge.GuardEntriesForTest() == 128 {
			break
		}
		filler := &fillers[index]
		if iobridge.Guard(filler, filler, store.MaxOwners, 1) {
			t.Cleanup(func() { iobridge.Unguard(filler) })
		}
	}
	require.Equal(t, 128, iobridge.GuardEntriesForTest())
	for name, build := range map[string]func(io.Reader) io.Reader{
		"bufio": func(body io.Reader) io.Reader { return bufio.NewReaderSize(body, 16) },
		"limit": func(body io.Reader) io.Reader { return io.LimitReader(body, 1<<20) },
	} {
		body.Reset("request-body")
		wrapper := build(body)
		requireOneOwnerNotExclusive(t, wrapper)
		data, err := io.ReadAll(wrapper)
		require.NoError(t, err, name)
		require.Equal(t, "request-body", string(data), name)
		requireReadAllMiss(t, ctx, data, scope)
	}
	runtime.KeepAlive(fillers)
}
