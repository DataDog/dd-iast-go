// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestAnalysisRejectedAdmissionsLeaveSourcesUnchanged(t *testing.T) {
	admissions := []struct {
		name string
		call func(Analysis, constants.Origin, string, string) (string, bool)
	}{
		{"string", Analysis.TaintString},
		{"managed string", Analysis.ManageString},
		{"bytes", func(a Analysis, origin constants.Origin, name, value string) (string, bool) {
			managed, ok := a.TaintBytes(origin, name, []byte(value))
			return string(managed), ok
		}},
	}
	for _, admission := range admissions {
		t.Run(admission.name, func(t *testing.T) {
			manager := NewManager(nil)
			analysis, ok := manager.Acquire(1)
			require.True(t, ok)
			t.Cleanup(analysis.Finish)
			for _, input := range []struct {
				origin constants.Origin
				value  string
			}{
				{0, "invalid origin"},
				{constants.OriginHttpRequestBody, "x"},
				{constants.OriginHttpRequestBody, strings.Repeat("x", store.MaxRootBytes+1)},
			} {
				value, admitted := admission.call(analysis, input.origin, "body", input.value)
				require.False(t, admitted)
				require.Equal(t, input.value, value)
				require.Zero(t, analysis.SourceCount())
				require.Zero(t, manager.Store().ProcessCharged())
			}

			for index := range MaxSources {
				_, admitted := admission.call(analysis, constants.OriginHttpRequestParameter, strconv.Itoa(index), "value")
				require.True(t, admitted)
			}
			charged := manager.Store().ProcessCharged()
			value, admitted := admission.call(analysis, constants.OriginHttpRequestParameter, "overflow", "value")
			require.False(t, admitted)
			require.Equal(t, "value", value)
			require.Equal(t, MaxSources, analysis.SourceCount())
			require.Equal(t, charged, manager.Store().ProcessCharged())

			analysis.Finish()
			value, admitted = admission.call(analysis, constants.OriginHttpRequestBody, "body", "finished")
			require.False(t, admitted)
			require.Equal(t, "finished", value)
			_, found := analysis.Source(0)
			require.False(t, found)
			require.Zero(t, manager.Store().ProcessCharged())
		})
	}
}

func TestAnalysisMutableDuplicatesKeepOneImmutableSource(t *testing.T) {
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	t.Cleanup(analysis.Finish)
	first, ok := analysis.TaintBytes(constants.OriginHttpRequestBody, "body", []byte("attack"))
	require.True(t, ok)
	second, ok := analysis.TaintBytes(constants.OriginHttpRequestBody, "body", []byte("attack"))
	require.True(t, ok)
	require.True(t, unsafe.SliceData(first) != unsafe.SliceData(second))
	first[0] = 'X'
	require.Equal(t, "attack", string(second))
	text, ok := analysis.TaintString(constants.OriginHttpRequestBody, "body", "attack")
	require.True(t, ok)
	require.Equal(t, "attack", text)
	require.Equal(t, 1, analysis.SourceCount())
	source, ok := analysis.Source(0)
	require.True(t, ok)
	require.Equal(t, Source{Origin: constants.OriginHttpRequestBody, Name: "body", Value: "attack", Kind: SourceBytes}, source)
}

func TestAnalysisSourceContentionDoesNotPublish(t *testing.T) {
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	t.Cleanup(analysis.Finish)
	slot := analysis.slot
	func() {
		slot.sourceMu.Lock()
		defer slot.sourceMu.Unlock()
		text, admitted := analysis.TaintString(constants.OriginHttpRequestBody, "body", "value")
		require.False(t, admitted)
		require.Equal(t, "value", text)
		text, admitted = analysis.ManageString(constants.OriginHttpRequestBody, "body", "value")
		require.False(t, admitted)
		require.Equal(t, "value", text)
		data, admitted := analysis.TaintBytes(constants.OriginHttpRequestBody, "body", []byte("value"))
		require.False(t, admitted)
		require.Equal(t, []byte("value"), data)
		_, found := analysis.Source(0)
		require.False(t, found)
		require.Zero(t, analysis.SourceCount())
	}()
	require.Zero(t, analysis.SourceCount())
	require.Zero(t, manager.Store().ProcessCharged())
	_, ok = analysis.TaintString(constants.OriginHttpRequestBody, "body", "value")
	require.True(t, ok)
}

func TestManagerReleasesPermitWhenStoreOwnersAreFull(t *testing.T) {
	taintStore := store.New()
	first := taintStore.Acquire()
	t.Cleanup(first.Finish)
	for range store.MaxOwners - 1 {
		owner := taintStore.Acquire()
		require.False(t, owner.Disabled())
		t.Cleanup(owner.Finish)
	}
	manager := NewManager(taintStore)
	_, ok := manager.Acquire(1)
	require.False(t, ok)
	require.Zero(t, manager.used.Load())
	first.Finish()
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	t.Cleanup(analysis.Finish)
}
