// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/stretchr/testify/require"
)

// TestInactiveScopesConcurrentUse uses the shared inactive scopes from many
// goroutines at the same time. Run it with -race: the methods must not write
// a shared scope, and Finish must do nothing. After the run, each shared scope
// must have its initial state.
func TestInactiveScopesConcurrentUse(t *testing.T) {
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	// MaxConcurrentRequests is 0, thus a sampled request is capacity
	// dropped. A rate of 50 gives the two inactive decisions. The test sets
	// the configuration before the goroutines start, and does not change it
	// during the run.
	config.Enabled = true
	config.RequestSamplingPct = 50
	config.MaxConcurrentRequests = 0
	usedBefore := defaultManager().used.Load()

	const (
		goroutines = 32
		iterations = 500
	)
	var wait sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := range goroutines {
		wait.Go(func() {
			begin, entry := BeginContext, EntryFallback
			if g%2 == 1 {
				begin, entry = BeginServerContext, EntryServer
			}
			for range iterations {
				ctx, created := begin(context.Background())
				scope := FromContext(ctx)
				decision := scope.Decision()
				if !created || scope != inactiveScope(decision, entry) {
					errs <- fmt.Errorf("goroutine %d: the scope is not the shared %v scope of entry %d", g, decision, entry)
					return
				}
				// Each reader and Finish run more than one time on the
				// shared scope, also after Finish.
				for range 2 {
					_, analysed := scope.Analysis()
					if scope.Active() || analysed || scope.EnabledTagValue() != 0 ||
						scope.Entry() != entry || scope.Decision() != decision {
						errs <- fmt.Errorf("goroutine %d: the shared %v scope of entry %d changed", g, decision, entry)
						return
					}
					FinishContext(ctx, created)
					scope.Finish()
				}
			}
		})
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	require.Equal(t, usedBefore, defaultManager().used.Load(), "Finish of a shared scope changed the manager")
	for entry := range inactiveScopes {
		for _, decision := range []Decision{DecisionSampledOut, DecisionCapacityDropped} {
			scope := inactiveScope(decision, Entry(entry))
			scope.mu.RLock()
			state := []any{scope.analysis, scope.decision, scope.entry, scope.inactive}
			scope.mu.RUnlock()
			require.Equal(t, []any{Analysis{}, decision, Entry(entry), decision}, state,
				"state of the shared %v scope of entry %d", decision, entry)
		}
	}
}
