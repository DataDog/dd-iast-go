// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// These tests use the real heap taint bits: they need a woven runtime.

func requireBits(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if !heapbits.Enabled() {
		t.Skip("the heap taint bits are not supported on this platform")
	}
}

func configure(t *testing.T) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = request.MaxAnalyses
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
}

type owner struct {
	ctx      context.Context
	scope    *request.Scope
	identity evidence.OwnerIdentity
}

func begin(t *testing.T) owner {
	t.Helper()
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	identity, ok := analysis.Owner()
	require.True(t, ok)
	return owner{ctx: ctx, scope: scope, identity: identity}
}

func (o owner) taint(name, value string) string {
	return taint.TaintString(o.ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: name}, strings.Clone(value))
}

func (o owner) target() evidence.Target {
	return evidence.Target{Owner: o.identity, Known: true}
}

var escape atomic.Pointer[[]byte]

// join returns a heap copy of the parts with their taint bits, as the
// runtime concatenation hook does (make and copy do not copy the bits).
func join(parts ...string) string {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, n)
	escape.Store(&out)
	at := 0
	for _, p := range parts {
		copy(out[at:], p)
		if len(p) != 0 {
			heapbits.Copy(unsafe.Pointer(&out[at]), unsafe.Pointer(unsafe.StringData(p)), uintptr(len(p)))
		}
		at += len(p)
	}
	return unsafe.String(unsafe.SliceData(out), len(out))
}

func parts(snapshot *evidence.Snapshot) []evidence.Part {
	result := make([]evidence.Part, 0, snapshot.PartCount())
	for index := 0; index < snapshot.PartCount(); index++ {
		part, _ := snapshot.PartAt(index)
		result = append(result, part)
	}
	return result
}

func TestCollectStringOwnsCanonicalEvidence(t *testing.T) {
	requireBits(t)
	configure(t)
	alpha := begin(t)
	managed := alpha.taint("query", "attacker")
	snapshot, status := evidence.CollectStringFor(alpha.target(), managed, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, evidence.StatusCollected, status)
	require.Equal(t, managed, snapshot.Value())
	require.True(t, unsafe.StringData(snapshot.Value()) != unsafe.StringData(managed), "the snapshot must own a clone")
	got, _ := snapshot.Owner()
	require.Equal(t, alpha.identity, got)
	require.Equal(t, 1, snapshot.SourceCount())
	source, _ := snapshot.SourceAt(0)
	require.Equal(t, evidence.Source{Origin: constants.OriginHttpRequestParameter, Name: "query", Value: "attacker"}, source)
	require.Equal(t, []evidence.Part{{Start: 0, Length: 8, Source: 0}}, parts(snapshot))

	// The ownerless collection finds the same owner.
	ownerless, status := evidence.CollectStringFor(evidence.Target{}, managed, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, evidence.StatusCollected, status)
	got, _ = ownerless.Owner()
	require.Equal(t, alpha.identity, got)

	// The snapshot stays valid after the request finished, and a new
	// collection finds nothing.
	alpha.scope.Finish()
	require.Equal(t, "attacker", snapshot.Value())
	source, _ = snapshot.SourceAt(0)
	require.Equal(t, "attacker", source.Value)
	again, status := evidence.CollectStringFor(alpha.target(), managed, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, evidence.StatusNone, status)
	require.Nil(t, again)
}

func TestCollectStringMasksForeignBytes(t *testing.T) {
	requireBits(t)
	configure(t)
	alpha, bravo := begin(t), begin(t)
	a := alpha.taint("alpha", "abcdefghijk")
	b := bravo.taint("bravo", "LMNOPQRSTUV")
	query := join("SELECT ", a, " -- ", b)

	for _, test := range []struct {
		owner owner
		name  string
		mine  evidence.Part
		other evidence.Part
	}{
		{alpha, "alpha", evidence.Part{Start: 7, Length: 11, Source: 0}, evidence.Part{Start: 22, Length: 11, Source: -1, Foreign: true}},
		{bravo, "bravo", evidence.Part{Start: 22, Length: 11, Source: 0}, evidence.Part{Start: 7, Length: 11, Source: -1, Foreign: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, status := evidence.CollectStringFor(test.owner.target(), query, constants.VulnerabilityTypeSqlInjection)
			require.Equal(t, evidence.StatusCollected, status)
			require.Equal(t, 1, snapshot.SourceCount())
			source, _ := snapshot.SourceAt(0)
			require.Equal(t, test.name, source.Name)
			require.Contains(t, parts(snapshot), test.mine)
			require.Contains(t, parts(snapshot), test.other)
		})
	}
}

func TestCollectStringForeignOnlyIsNone(t *testing.T) {
	requireBits(t)
	configure(t)
	alpha, bravo := begin(t), begin(t)
	b := bravo.taint("bravo", "LMNOPQRSTUV")
	snapshot, status := evidence.CollectStringFor(alpha.target(), join("SELECT ", b), constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, evidence.StatusNone, status)
	require.Nil(t, snapshot)
}

func TestCollectJoinedStringsPreservesArgumentOffsets(t *testing.T) {
	requireBits(t)
	configure(t)
	alpha := begin(t)
	managed := alpha.taint("argument", "secret")
	values := []string{"echo", managed, "tail"}
	result := strings.Join(values, " ")
	for _, target := range []evidence.Target{alpha.target(), {}} {
		snapshot, status := evidence.CollectJoinedStringsFor(target, values, " ", result, constants.VulnerabilityTypeCommandInjection)
		require.Equal(t, evidence.StatusCollected, status)
		require.Equal(t, result, snapshot.Value())
		require.Equal(t, 1, snapshot.SourceCount())
		require.Equal(t, []evidence.Part{
			{Start: 0, Length: 5, Source: -1},
			{Start: 5, Length: 6, Source: 0},
			{Start: 11, Length: 5, Source: -1},
		}, parts(snapshot))
	}
}

func TestCollectJoinedStringsFindsLateArgument(t *testing.T) {
	requireBits(t)
	configure(t)
	alpha := begin(t)
	managed := alpha.taint("argument", "secret")
	values := make([]string, 20)
	for index := range values {
		values[index] = "clean"
	}
	values[len(values)-1] = managed
	result := strings.Join(values, " ")
	snapshot, status := evidence.CollectJoinedStringsFor(evidence.Target{}, values, " ", result, constants.VulnerabilityTypeCommandInjection)
	require.Equal(t, evidence.StatusCollected, status)
	part, _ := snapshot.PartAt(snapshot.PartCount() - 1)
	require.Equal(t, evidence.Part{Start: uint32(len(result) - len(managed)), Length: uint32(len(managed)), Source: 0}, part)
}

func TestCollectJoinedStringsOwnerlessKeepsOneOwner(t *testing.T) {
	requireBits(t)
	configure(t)
	alpha, bravo := begin(t), begin(t)
	a := alpha.taint("alpha", "abcdefghijk")
	b := bravo.taint("bravo", "LMNOPQRSTUV")
	values := []string{"run", b, a}
	result := strings.Join(values, " ")
	snapshot, status := evidence.CollectJoinedStringsFor(evidence.Target{}, values, " ", result, constants.VulnerabilityTypeCommandInjection)
	require.Equal(t, evidence.StatusCollected, status)
	got, _ := snapshot.Owner()
	require.Equal(t, bravo.identity, got, "the first argument with a source selects the owner")
	require.Equal(t, 1, snapshot.SourceCount())
	require.Equal(t, []evidence.Part{
		{Start: 0, Length: 4, Source: -1},
		{Start: 4, Length: 11, Source: 0},
		{Start: 15, Length: 1, Source: -1},
		{Start: 16, Length: 11, Source: -1, Foreign: true},
	}, parts(snapshot))

	// The preferred owner comes first.
	snapshot, status = evidence.CollectJoinedStringsFor(evidence.Target{Owner: alpha.identity}, values, " ", result, constants.VulnerabilityTypeCommandInjection)
	require.Equal(t, evidence.StatusCollected, status)
	got, _ = snapshot.Owner()
	require.Equal(t, alpha.identity, got)
}
