// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bufio_test

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"

	iastbufio "github.com/DataDog/dd-iast-go/iast/bufio"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The tests of this file check the Read guard (see the reader binding rules in
// the internal/taint/store package doc). They check the binding only, with
// request.ReaderOwner: ok means "one owner, effectively exclusive".

func beginRequest(t *testing.T) (context.Context, *request.Scope) {
	t.Helper()
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	return ctx, scope
}

func boundBody(t *testing.T, ctx context.Context, data string) *strings.Reader {
	t.Helper()
	body := strings.NewReader(data)
	require.True(t, request.BindReader(ctx, body))
	return body
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

func readOnce(reader io.Reader) { _, _ = reader.Read(make([]byte, 1)) }

func TestBufioRetargetAfterBind(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	for name, retarget := range map[string]func(buffered *bufio.Reader, clean, other io.Reader){
		"Reset clean":        func(buffered *bufio.Reader, clean, _ io.Reader) { buffered.Reset(clean) },
		"Reset other body":   func(buffered *bufio.Reader, _, other io.Reader) { buffered.Reset(other) },
		"value copy (clean)": func(buffered *bufio.Reader, clean, _ io.Reader) { *buffered = *bufio.NewReader(clean) },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginRequest(t)
			otherCtx, _ := beginRequest(t)
			body := boundBody(t, ctx, "request-body")
			sibling := bufio.NewReaderSize(body, 16)
			buffered := bufio.NewReaderSize(body, 16)
			requireExclusiveOwner(t, scope, buffered)
			readOnce(buffered)
			requireExclusiveOwner(t, scope, buffered)

			retarget(buffered, strings.NewReader("clean-bytes"), boundBody(t, otherCtx, "other-bytes"))
			// No byte of the new target flowed, thus the binding stays
			// exclusive.
			requireExclusiveOwner(t, scope, buffered)
			readOnce(buffered)
			requireNotExclusive(t, buffered)
			// The retargeted bit is per owner (rule (a2)): one retarget removes
			// the exclusivity of all guarded readers of the owner.
			requireNotExclusive(t, sibling)
			requireExclusiveOwner(t, scope, body)
		})
	}
}

func TestBufioNoFalseRetarget(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	t.Run("Reset nil with no Read", func(t *testing.T) {
		ctx, scope := beginRequest(t)
		body := boundBody(t, ctx, "request-body")
		buffered := bufio.NewReaderSize(body, 16)
		sibling := bufio.NewReaderSize(body, 16)
		readOnce(buffered)
		// A pool Put pattern: no Read follows the Reset.
		buffered.Reset(nil)
		readOnce(sibling)
		requireExclusiveOwner(t, scope, sibling)
		requireExclusiveOwner(t, scope, buffered)
	})
	t.Run("Reset to the same input", func(t *testing.T) {
		ctx, scope := beginRequest(t)
		body := boundBody(t, ctx, "request-body")
		buffered := bufio.NewReaderSize(body, 16)
		readOnce(buffered)
		buffered.Reset(body)
		readOnce(buffered)
		requireExclusiveOwner(t, scope, buffered)
	})
	t.Run("Reset to itself", func(t *testing.T) {
		ctx, scope := beginRequest(t)
		body := boundBody(t, ctx, "request-body")
		buffered := bufio.NewReaderSize(body, 16)
		buffered.Reset(buffered)
		readOnce(buffered)
		requireExclusiveOwner(t, scope, buffered)
	})
	t.Run("NewReaderSize returns its input", func(t *testing.T) {
		ctx, scope := beginRequest(t)
		body := boundBody(t, ctx, "request-body")
		buffered := bufio.NewReaderSize(body, 32)
		guards := iobridge.GuardCountForTest()
		same := bufio.NewReaderSize(buffered, 16)
		require.Same(t, buffered, same)
		require.Equal(t, guards, iobridge.GuardCountForTest(), "the reuse case must not change the guard")
		readOnce(same)
		requireExclusiveOwner(t, scope, same)
	})
}

func TestBufioGuardReleasedAtFinish(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	ctx, scope := beginRequest(t)
	body := boundBody(t, ctx, "request-body")
	require.Zero(t, iobridge.GuardCountForTest())
	require.Zero(t, iobridge.GuardEntriesForTest())
	buffered := bufio.NewReaderSize(body, 16)
	require.Equal(t, 1, iobridge.GuardCountForTest())
	require.Equal(t, 1, iobridge.GuardEntriesForTest())
	scope.Finish()
	// The counter and each slot of the table are empty.
	require.Zero(t, iobridge.GuardCountForTest())
	require.Zero(t, iobridge.GuardEntriesForTest())
	requireNotExclusive(t, buffered)
	readOnce(buffered)
}

func TestManualPropagateIsNotExclusive(t *testing.T) {
	ctx, _ := beginRequest(t)
	body := boundBody(t, ctx, "request-body")
	output := bufio.NewReaderSize(strings.NewReader("unbound"), 16)
	iastbufio.Propagate(body, output)
	// An unwoven bufio has no Read guard.
	requireNotExclusive(t, output)
}
