// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package io_test

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

// The tests of this file check the io.ReadAll consumer of reader binding rule
// (f) (see the internal/taint/store package doc): the aspect takes the owner
// token BEFORE the first read, and checks it again AFTER the reads.

// steppedReader returns 7 bytes for each Read, and calls onRead (when it is
// not nil) inside its second Read, after it copied the bytes.
type steppedReader struct {
	data   []byte
	reads  int
	onRead func()
}

func (r *steppedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data[:min(7, len(r.data))])
	r.data = r.data[n:]
	r.reads++
	if r.reads == 2 && r.onRead != nil {
		r.onRead()
	}
	return n, nil
}

// requireReadAllMiss checks that data is not tainted and that no scope of
// scopes has a source.
func requireReadAllMiss(t *testing.T, ctx context.Context, data []byte, scopes ...*request.Scope) {
	t.Helper()
	_, found := bodySource(ctx, data)
	require.False(t, found, "the io.ReadAll result is tainted")
	for _, scope := range scopes {
		if analysis, ok := scope.Analysis(); ok {
			require.Zero(t, analysis.SourceCount(), "a request got a source")
		}
	}
}

// TestReadAllMissesSecondOwnerThatEndedDuringRead is the gap of rule (f) for a
// root reader: B binds the reader of A during the reads, and ends before
// io.ReadAll returns. Then a lookup of the reader finds only A again. The
// bytes could be data of B, thus the result is a miss.
func TestReadAllMissesSecondOwnerThatEndedDuringRead(t *testing.T) {
	requireWoven(t)
	for name, wrap := range map[string]func(io.Reader) io.Reader{
		"root":  func(reader io.Reader) io.Reader { return reader },
		"bufio": func(reader io.Reader) io.Reader { return bufio.NewReaderSize(reader, 16) },
		"tee":   func(reader io.Reader) io.Reader { return io.TeeReader(reader, io.Discard) },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := activeContext(t)
			otherCtx, other := activeContext(t)
			reader := &steppedReader{data: []byte("request-body-of-a")}
			require.True(t, request.BindReader(ctx, reader))
			reader.onRead = func() {
				require.True(t, request.BindReader(otherCtx, reader))
				other.Finish()
			}
			data, err := io.ReadAll(wrap(reader))
			require.NoError(t, err)
			require.Equal(t, "request-body-of-a", string(data))
			// Only A is bound to the reader after B ended, but the loss is
			// sticky (rule (f)).
			requireOneOwnerNotExclusive(t, reader)
			requireReadAllMiss(t, ctx, data, scope)
		})
	}
}

// TestReadAllLateBindIsMiss checks that a binding made during io.ReadAll does
// not claim the bytes that flowed before it.
func TestReadAllLateBindIsMiss(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	reader := &steppedReader{data: []byte("request-body-of-a")}
	reader.onRead = func() { require.True(t, request.BindReader(ctx, reader)) }
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	requireReadAllMiss(t, ctx, data, scope)

	// Control: the same reader, bound before io.ReadAll.
	bound := &steppedReader{data: []byte("request-body-of-a")}
	require.True(t, request.BindReader(ctx, bound))
	data, err = io.ReadAll(bound)
	require.NoError(t, err)
	requireBodyRange(t, ctx, data, "request-body-of-a")
}

// TestReadAllSecondOwnerDuringReadIsMiss checks that a second owner that is
// added during the reads, and that is still live, gives a miss.
func TestReadAllSecondOwnerDuringReadIsMiss(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	otherCtx, other := activeContext(t)
	reader := &steppedReader{data: []byte("request-body-of-a")}
	require.True(t, request.BindReader(ctx, reader))
	reader.onRead = func() { require.True(t, request.BindReader(otherCtx, reader)) }
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	requireReadAllMiss(t, ctx, data, scope, other)
	requireReadAllMiss(t, otherCtx, data)
}

// TestReadAllKeepsOwnRebindDuringRead checks that a rebind of its own root by
// the owner during the reads does not remove the exclusivity (rule (f)).
func TestReadAllKeepsOwnRebindDuringRead(t *testing.T) {
	requireWoven(t)
	ctx, _ := activeContext(t)
	reader := &steppedReader{data: []byte("request-body-of-a")}
	require.True(t, request.BindReader(ctx, reader))
	reader.onRead = func() {
		require.True(t, request.BindReader(ctx, reader))
		readerSink = io.TeeReader(reader, io.Discard)
	}
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	requireBodyRange(t, ctx, data, "request-body-of-a")
}

// TestReadAllStringReaderIsUnchanged is a control: a reader bound to one owner
// with no bind during the reads keeps its taint.
func TestReadAllStringReaderIsUnchanged(t *testing.T) {
	requireWoven(t)
	ctx, _ := activeContext(t)
	body := boundBody(t, ctx, strings.Repeat("x", 100))
	data, err := io.ReadAll(body)
	require.NoError(t, err)
	requireBodyRange(t, ctx, data, strings.Repeat("x", 100))
}
