// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"sync"
	"testing"

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

	result := first.AddSource(constants.OriginHttpRequestParameter, "q", "value")
	require.Equal(t, request.AddAdded, result.Status)
	_, _, ok = first.StoreOwner().TaintString("attacker", result.ID)
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
				analysis.AddSource(constants.OriginHttpRequestParameter, "q", "value")
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
