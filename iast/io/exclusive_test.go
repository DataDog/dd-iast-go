// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package io_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The tests of this file check the exclusive reader bindings of plan
// encoding-json-v2, sections 6.5 and 6.6. They check the binding only, with
// request.ReaderOwner: ok means "one owner, effectively exclusive". The
// io.ReadAll consumer tests are in readall_token_test.go and
// readall_exclusive_test.go. The json.Decoder consumer tests are in
// iast/encoding/json.

func requireWoven(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
}

func requireExclusiveOwner(t *testing.T, scope *request.Scope, reader any) {
	t.Helper()
	index, generation, ok := request.ReaderOwner(reader).Identity()
	require.True(t, ok, "the reader has no exclusive owner")
	analysis, active := scope.Analysis()
	require.True(t, active)
	ownerIndex, _, ownerGeneration, _ := analysis.Identity()
	require.Equal(t, ownerIndex, index)
	require.Equal(t, ownerGeneration, generation)
}

func requireNotExclusive(t *testing.T, reader any) {
	t.Helper()
	_, _, ok := request.ReaderOwner(reader).Identity()
	require.False(t, ok, "the reader has an exclusive owner")
}

// requireOneOwnerNotExclusive checks that one request is bound to reader, and
// that the binding is not exclusive: the loss of plan encoding-json-v2,
// section 6.5, rule (f), is sticky after a second owner ends.
func requireOneOwnerNotExclusive(t *testing.T, reader any) {
	t.Helper()
	require.Equal(t, 1, request.LookupObject(reader, store.BindingReader, make([]store.OwnerRef, 4)),
		"one request is bound to the reader")
	requireNotExclusive(t, reader)
}

// boundBody returns a reader that is bound exclusively to the request of ctx,
// as the HTTP entry binds a request body.
func boundBody(t *testing.T, ctx context.Context, data string) *strings.Reader {
	t.Helper()
	body := strings.NewReader(data)
	require.True(t, request.BindReader(ctx, body))
	return body
}

func readOnce(t *testing.T, reader io.Reader) {
	t.Helper()
	_, _ = reader.Read(make([]byte, 1))
}

func TestTeeReaderOfExclusiveInputIsExclusive(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	body := boundBody(t, ctx, "request-body")
	var side bytes.Buffer
	tee := io.TeeReader(body, &side)
	requireExclusiveOwner(t, scope, tee)
	requireNotExclusive(t, io.TeeReader(strings.NewReader("clean"), &side))
}

func TestTeeReaderOfGuardedReaderDependsOnTheGuard(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	body := boundBody(t, ctx, "request-body")
	buffered := bufio.NewReaderSize(body, 16)
	tee := io.TeeReader(buffered, io.Discard)
	requireExclusiveOwner(t, scope, tee)
	readOnce(t, tee)
	requireExclusiveOwner(t, scope, tee)

	buffered.Reset(strings.NewReader("clean"))
	readOnce(t, tee)
	requireNotExclusive(t, tee)
	requireNotExclusive(t, buffered)
	requireExclusiveOwner(t, scope, body)
}

func TestMultiReaderExclusivity(t *testing.T) {
	requireWoven(t)
	// Each case has its own requests: an owner has at most
	// store.MaxReaderBindings reader bindings.
	for name, test := range map[string]struct {
		build     func(first, second, other io.Reader) io.Reader
		exclusive bool
	}{
		"one exclusive input":   {build: func(first, _, _ io.Reader) io.Reader { return io.MultiReader(first) }, exclusive: true},
		"two inputs, one owner": {build: func(first, second, _ io.Reader) io.Reader { return io.MultiReader(first, second) }, exclusive: true},
		"nested": {build: func(first, second, _ io.Reader) io.Reader {
			return io.MultiReader(io.MultiReader(first), second)
		}, exclusive: true},
		"eight inputs": {build: func(first, _, _ io.Reader) io.Reader {
			return io.MultiReader(first, first, first, first, first, first, first, first)
		}, exclusive: true},
		"nine inputs": {build: func(first, _, _ io.Reader) io.Reader {
			return io.MultiReader(first, first, first, first, first, first, first, first, first)
		}},
		"no input":          {build: func(_, _, _ io.Reader) io.Reader { return io.MultiReader() }},
		"clean first input": {build: func(first, _, _ io.Reader) io.Reader { return io.MultiReader(strings.NewReader(""), first) }},
		"clean last input":  {build: func(first, _, _ io.Reader) io.Reader { return io.MultiReader(first, strings.NewReader("")) }},
		"two owners":        {build: func(first, _, other io.Reader) io.Reader { return io.MultiReader(first, other) }},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := activeContext(t)
			otherCtx, _ := activeContext(t)
			first := boundBody(t, ctx, "first-")
			second := boundBody(t, ctx, "second")
			other := boundBody(t, otherCtx, "other")
			composed := test.build(first, second, other)
			if test.exclusive {
				requireExclusiveOwner(t, scope, composed)
			} else {
				requireNotExclusive(t, composed)
			}
		})
	}
}

// TestMultiReaderEightInputsOfAAndNinthOfB checks that a MultiReader with the
// owner A in its first 8 inputs and a live owner B in its ninth input is not
// exclusive to A, although only the first 8 inputs are inspected.
func TestMultiReaderEightInputsOfAAndNinthOfB(t *testing.T) {
	requireWoven(t)
	ctxA, scopeA := activeContext(t)
	ctxB, _ := activeContext(t)
	bodyA := boundBody(t, ctxA, "bytes-of-A")
	teeA := io.TeeReader(bodyA, io.Discard)
	bodyB := boundBody(t, ctxB, "bytes-of-B")
	inputs := []io.Reader{bodyA, bodyA, bodyA, bodyA, bodyA, bodyA, bodyA, teeA}
	// Control: the first 8 inputs alone are exclusive to A.
	requireExclusiveOwner(t, scopeA, io.MultiReader(inputs...))
	composed := io.MultiReader(append(inputs, bodyB)...)
	requireNotExclusive(t, composed)
	data, err := io.ReadAll(composed)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(string(data), "bytes-of-B"))
}

// TestWrapperLosesExclusivityWhenInputGetsSecondOwner checks plan
// encoding-json-v2, section 6.5, rule (e): a wrapper of an input that is
// exclusive to A stops being exclusive when the input gets a binding of a
// second live owner B.
func TestWrapperLosesExclusivityWhenInputGetsSecondOwner(t *testing.T) {
	requireWoven(t)
	for name, build := range wrapperBuilders() {
		t.Run(name, func(t *testing.T) {
			ctxA, scopeA := activeContext(t)
			ctxB, _ := activeContext(t)
			body := boundBody(t, ctxA, "request-body")
			wrapper := build(body)
			requireExclusiveOwner(t, scopeA, wrapper)
			readOnce(t, wrapper)
			requireExclusiveOwner(t, scopeA, wrapper)
			require.True(t, request.BindReader(ctxB, body))
			requireNotExclusive(t, body)
			requireNotExclusive(t, wrapper)
		})
	}
}

// TestWrapperStaysNotExclusiveAfterSecondOwnerEnds checks that the loss of
// rule (e) is sticky (follow-up review 1 of batch 1, finding 1): the input of
// a wrapper of A gets a binding of B, the wrapper reads (and bufio buffers)
// bytes while B is live, then B ends. The wrapper and its input must stay not
// exclusive to A (rules (e) and (f)).
func TestWrapperStaysNotExclusiveAfterSecondOwnerEnds(t *testing.T) {
	requireWoven(t)
	for name, build := range wrapperBuilders() {
		t.Run(name, func(t *testing.T) {
			ctxA, scopeA := activeContext(t)
			ctxB, scopeB := activeContext(t)
			body := boundBody(t, ctxA, "request-body")
			wrapper := build(body)
			requireExclusiveOwner(t, scopeA, wrapper)
			require.True(t, request.BindReader(ctxB, body))
			readOnce(t, wrapper)
			scopeB.Finish()
			requireOneOwnerNotExclusive(t, body)
			requireNotExclusive(t, wrapper)
			readOnce(t, wrapper)
			requireNotExclusive(t, wrapper)
		})
	}
}

// wrapperBuilders returns functions that make a wrapper over body with the
// woven constructors.
func wrapperBuilders() map[string]func(io.Reader) io.Reader {
	return map[string]func(io.Reader) io.Reader{
		"TeeReader":           func(body io.Reader) io.Reader { return io.TeeReader(body, io.Discard) },
		"MultiReader":         func(body io.Reader) io.Reader { return io.MultiReader(body) },
		"LimitReader":         func(body io.Reader) io.Reader { return io.LimitReader(body, 64) },
		"bufio":               func(body io.Reader) io.Reader { return bufio.NewReaderSize(body, 16) },
		"Tee over bufio":      func(body io.Reader) io.Reader { return io.TeeReader(bufio.NewReaderSize(body, 16), io.Discard) },
		"Multi of two inputs": func(body io.Reader) io.Reader { return io.MultiReader(io.LimitReader(body, 4), body) },
	}
}

func TestLimitReaderRetargetAfterBind(t *testing.T) {
	requireWoven(t)
	for name, retarget := range map[string]func(t *testing.T, limited *io.LimitedReader, other io.Reader){
		"field R": func(_ *testing.T, limited *io.LimitedReader, other io.Reader) { limited.R = other },
		"whole value": func(_ *testing.T, limited *io.LimitedReader, other io.Reader) {
			*limited = io.LimitedReader{R: other, N: 64}
		},
	} {
		for _, target := range []string{"clean", "other request"} {
			t.Run(name+"/"+target, func(t *testing.T) {
				ctx, scope := activeContext(t)
				otherCtx, _ := activeContext(t)
				body := boundBody(t, ctx, "request-body")
				sibling := io.LimitReader(body, 64)
				limited := io.LimitReader(body, 64).(*io.LimitedReader)
				requireExclusiveOwner(t, scope, limited)
				var other io.Reader = strings.NewReader("clean-bytes")
				if target == "other request" {
					other = boundBody(t, otherCtx, "other-bytes")
				}
				retarget(t, limited, other)
				// No byte flowed, thus the binding stays exclusive.
				requireExclusiveOwner(t, scope, limited)
				readOnce(t, limited)
				requireNotExclusive(t, limited)
				// The retargeted bit is per owner: all the guarded readers of
				// the owner lose the exclusivity. The input keeps it.
				requireNotExclusive(t, sibling)
				requireExclusiveOwner(t, scope, body)
			})
		}
	}
}

func TestLimitReaderOfBufioReaderRetargetedChain(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	body := boundBody(t, ctx, "request-body")
	buffered := bufio.NewReaderSize(body, 16)
	limited := io.LimitReader(buffered, 64)
	requireExclusiveOwner(t, scope, limited)
	buffered.Reset(strings.NewReader("clean"))
	readOnce(t, limited)
	requireNotExclusive(t, limited)
}

func TestGuardedReadersNormalUseKeepsExclusivity(t *testing.T) {
	requireWoven(t)
	for name, build := range map[string]func(io.Reader) io.Reader{
		"bufio":             func(body io.Reader) io.Reader { return bufio.NewReader(body) },
		"limit":             func(body io.Reader) io.Reader { return io.LimitReader(body, 1<<20) },
		"limit over bufio":  func(body io.Reader) io.Reader { return io.LimitReader(bufio.NewReaderSize(body, 16), 1<<20) },
		"multi over limit":  func(body io.Reader) io.Reader { return io.MultiReader(io.LimitReader(body, 1<<20)) },
		"tee over limit":    func(body io.Reader) io.Reader { return io.TeeReader(io.LimitReader(body, 1<<20), io.Discard) },
		"bufio over bufio2": func(body io.Reader) io.Reader { return bufio.NewReaderSize(bufio.NewReaderSize(body, 16), 32) },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := activeContext(t)
			body := boundBody(t, ctx, strings.Repeat("x", 200))
			wrapper := build(body)
			requireExclusiveOwner(t, scope, wrapper)
			for range 100 {
				readOnce(t, wrapper)
			}
			requireExclusiveOwner(t, scope, wrapper)
		})
	}
}

// customBody is a request body type whose first field has the address of the
// body itself.
type customBody struct {
	Buffer bytes.Buffer
	reads  int
}

func (b *customBody) Read(p []byte) (int, error) { b.reads++; return b.Buffer.Read(p) }

func TestLimitReaderRetargetToSameAddressOtherType(t *testing.T) {
	requireWoven(t)
	ctx, scope := activeContext(t)
	body := &customBody{}
	body.Buffer.WriteString("request-body")
	require.True(t, request.BindReader(ctx, body))
	limited := io.LimitReader(body, 64).(*io.LimitedReader)
	requireExclusiveOwner(t, scope, limited)
	requireNotExclusive(t, &body.Buffer)
	limited.R = &body.Buffer
	readOnce(t, limited)
	requireNotExclusive(t, limited)
	requireExclusiveOwner(t, scope, body)
}

func TestLimitedReaderCompositeLiteralIsUnbound(t *testing.T) {
	requireWoven(t)
	ctx, _ := activeContext(t)
	body := boundBody(t, ctx, "request-body")
	requireNotExclusive(t, &io.LimitedReader{R: body, N: 64})
}

// readerSink makes the constructor results escape in the woven and in the
// unwoven build, so that both builds have the same allocation count.
var readerSink io.Reader

// bytesSink makes the io.ReadAll results escape.
var bytesSink []byte

// TestGateOffReadersDoNotAllocate checks that the reader aspects add no
// allocation when no request is active. The counts are the counts of the
// unwoven standard library.
func TestGateOffReadersDoNotAllocate(t *testing.T) {
	data := []byte(strings.Repeat("x", 64))
	source := bytes.NewReader(data)
	buffered := bufio.NewReaderSize(source, 16)
	limited := io.LimitReader(source, 1<<30)
	buffer := make([]byte, 4)
	read := func(reader io.Reader) {
		if _, err := reader.Read(buffer); err == io.EOF {
			source.Reset(data)
		}
	}
	for name, test := range map[string]struct {
		run  func()
		want float64
	}{
		"bufio.Reader.Read":       {run: func() { read(buffered) }, want: 0},
		"io.LimitedReader.Read":   {run: func() { read(limited) }, want: 0},
		"io.LimitReader":          {run: func() { readerSink = io.LimitReader(source, 8) }, want: 1},
		"io.TeeReader":            {run: func() { readerSink = io.TeeReader(source, io.Discard) }, want: 1},
		"io.MultiReader":          {run: func() { readerSink = io.MultiReader(source, source) }, want: 2},
		"bufio.NewReaderSize":     {run: func() { readerSink = bufio.NewReaderSize(source, 16) }, want: 2},
		"bufio.NewReaderSize(br)": {run: func() { readerSink = bufio.NewReaderSize(buffered, 16) }, want: 0},
		// The 512-byte buffer of io.ReadAll. The owner token of rule (f) is
		// on the stack.
		"io.ReadAll": {run: func() { source.Reset(data); bytesSink, _ = io.ReadAll(source) }, want: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := request.ReaderOwner(source).Identity(); ok {
				t.Skip("a request is active")
			}
			require.Equal(t, test.want, testing.AllocsPerRun(200, test.run))
		})
	}
}
