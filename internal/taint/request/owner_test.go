// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"sync"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

func TestManagerPermitAndFinish(t *testing.T) {
	manager := request.NewManager(nil)
	first, ok := manager.Acquire(2)
	require.True(t, ok)
	second, ok := manager.Acquire(2)
	require.True(t, ok)
	_, ok = manager.Acquire(2)
	require.False(t, ok)

	_, ok = first.TaintString(constants.OriginHttpRequestParameter, "q", "attacker")
	require.True(t, ok)

	first.Finish()
	require.False(t, first.Active())
	require.Zero(t, first.SourceCount())
	require.Zero(t, manager.Store().ProcessCharged())

	reused, ok := manager.Acquire(2)
	require.True(t, ok)
	first.Finish()
	require.True(t, reused.Active(), "stale finish must not close a reused slot")
	require.Zero(t, reused.SourceCount(), "source table must reset on reuse")
	second.Finish()
	reused.Finish()
}

func TestAnalysisTransactionalSources(t *testing.T) {
	manager := request.NewManager(nil)
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	original := "attacker"
	managed, ok := analysis.TaintString(constants.OriginHttpRequestHeader, "X-Input", original)
	require.True(t, ok)
	require.False(t, unsafe.StringData(original) == unsafe.StringData(managed))
	require.Equal(t, 1, analysis.SourceCount())
	source, ok := analysis.Source(0)
	require.True(t, ok)
	require.Equal(t, managed, source.Value)
	require.Equal(t, "X-Input", source.Name)

	duplicate, ok := analysis.TaintString(constants.OriginHttpRequestHeader, "X-Input", original)
	require.True(t, ok)
	require.Equal(t, original, duplicate)
	require.Equal(t, 1, analysis.SourceCount())

	_, ok = analysis.TaintString(constants.OriginHttpRequestHeader, "one", "x")
	require.False(t, ok)
	require.Equal(t, 1, analysis.SourceCount(), "failed publication must not commit a source")
	_, ok = analysis.TaintString(0, "invalid", "value")
	require.False(t, ok)
	require.Equal(t, 1, analysis.SourceCount())

	bytesValue := make([]byte, 6, 12)
	copy(bytesValue, "attack")
	managedBytes, ok := analysis.TaintBytes(constants.OriginHttpRequestBody, "body", bytesValue)
	require.True(t, ok)
	require.Equal(t, 2, analysis.SourceCount())
	byteSource, ok := analysis.Source(1)
	require.True(t, ok)
	managedBytes[0] = 'A'
	require.Equal(t, "attack", byteSource.Value)

	analysis.Finish()
	require.Zero(t, manager.Store().ProcessCharged())
}

func TestAnalysisSourceWritesRaceFinish(t *testing.T) {
	manager := request.NewManager(nil)
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < 100; i++ {
				analysis.TaintString(constants.OriginHttpRequestParameter, "q", "value")
			}
		}()
	}
	analysis.Finish()
	wait.Wait()
	require.False(t, analysis.Active())
}

func TestManagerClampAndZero(t *testing.T) {
	manager := request.NewManager(nil)
	_, ok := manager.Acquire(0)
	require.False(t, ok)
	analyses := make([]request.Analysis, request.MaxAnalyses)
	for i := range analyses {
		analyses[i], ok = manager.Acquire(request.MaxAnalyses + 100)
		require.True(t, ok)
	}
	_, ok = manager.Acquire(request.MaxAnalyses + 100)
	require.False(t, ok)
	for _, analysis := range analyses {
		analysis.Finish()
	}
}
