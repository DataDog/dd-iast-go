// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func TestSnapshotAccessorsAfterRequestFinish(t *testing.T) {
	ctx := withScope(t)
	value := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "query"}, "attacker")
	snapshot, status := CollectString(value, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	request.FromContext(ctx).Finish()
	require.Equal(t, value, snapshot.Value())
	source, ok := snapshot.SourceAt(0)
	require.True(t, ok)
	require.Equal(t, Source{Origin: constants.OriginHttpRequestParameter, Name: "query", Value: value}, source)
	require.Equal(t, uint32(len("query")+len(value)), snapshot.SourceBytes())
	part, ok := snapshot.PartAt(0)
	require.True(t, ok)
	partValue, ok := snapshot.PartValue(part)
	require.True(t, ok)
	require.Equal(t, value, partValue)
	owner, ok := snapshot.OwnerAt(0)
	require.True(t, ok)
	require.NotZero(t, owner.ID)
	require.NotZero(t, owner.Generation)
	for _, index := range []int{-1, snapshot.SourceCount()} {
		_, ok = snapshot.SourceAt(index)
		require.False(t, ok)
	}
	for _, index := range []int{-1, snapshot.PartCount()} {
		_, ok = snapshot.PartAt(index)
		require.False(t, ok)
	}
	for _, index := range []int{-1, snapshot.OwnerCount()} {
		_, ok = snapshot.OwnerAt(index)
		require.False(t, ok)
	}
	for _, invalid := range []Part{{}, {Start: uint32(len(value)), Length: 1}, {Start: 1, Length: ^uint32(0)}} {
		_, ok = snapshot.PartValue(invalid)
		require.False(t, ok)
	}
}

func TestAbsentSnapshotAccessorsAreSafeMisses(t *testing.T) {
	snapshot, status := CollectString("clean-value", constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusNone, status)
	require.Nil(t, snapshot)
	require.Empty(t, snapshot.Value())
	require.Zero(t, snapshot.SourceBytes())
	require.Zero(t, snapshot.SourceCount())
	require.Zero(t, snapshot.PartCount())
	require.Zero(t, snapshot.OwnerCount())
	_, ok := snapshot.SourceAt(0)
	require.False(t, ok)
	_, ok = snapshot.PartAt(0)
	require.False(t, ok)
	_, ok = snapshot.OwnerAt(0)
	require.False(t, ok)
	_, ok = snapshot.PartValue(Part{Length: 1})
	require.False(t, ok)
}
