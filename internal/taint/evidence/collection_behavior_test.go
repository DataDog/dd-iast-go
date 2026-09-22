// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence

import (
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func TestCollectionSuppressesFullyMarkedLiveSources(t *testing.T) {
	ctx := withScope(t)
	value := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "query"}, "attacker")
	active := request.ActiveStore()
	key, ok := store.StringKey(value)
	require.True(t, ok)
	var metadata store.Snapshot
	require.True(t, active.Lookup(key, &metadata))
	entry, ok := metadata.At(0)
	require.True(t, ok)
	owner, ok := entry.Handle(active)
	require.True(t, ok)
	source, ok := entry.Ranges.At(0)
	require.True(t, ok)
	source.Marks, ok = ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	require.True(t, ok)
	var marked ranges.Set
	require.True(t, ranges.AdoptCanonical(&marked, entry.Ranges.Limit(), []ranges.Range{source}, uint32(len(value))).Valid)
	_, ok = owner.AdoptString(value, &marked)
	require.True(t, ok)
	require.True(t, request.IsTaintedString(value))
	snapshot, status := CollectString(value, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusSuppressed, status)
	require.Nil(t, snapshot)
	values := []string{"select", value}
	snapshot, status = CollectJoinedStrings(values, " ", strings.Join(values, " "), constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusSuppressed, status)
	require.Nil(t, snapshot)
	snapshot, status = CollectJoinedStrings(values, " ", strings.Join(values, " "), 0)
	require.Equal(t, StatusDropped, status)
	require.Nil(t, snapshot)
	snapshot, status = CollectString(value, 0)
	require.Equal(t, StatusDropped, status)
	require.Nil(t, snapshot)
}

func TestJoinedCollectionDropsCompleteReportAtSourceByteLimit(t *testing.T) {
	ctx := withScope(t)
	values := make([]string, MaxSnapshotBytes/store.MaxRootBytes+1)
	for index := range values {
		name := strconv.Itoa(index)
		source := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: name}, strings.Repeat("x", store.MaxRootBytes))
		require.True(t, request.IsTaintedString(source))
		values[index] = source[:2]
		propagation.StringWindow(source, values[index])
	}
	snapshot, status := CollectJoinedStrings(values, " ", strings.Join(values, " "), constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusDropped, status)
	require.Nil(t, snapshot, "the report must not contain a partial set of source identities")
}
