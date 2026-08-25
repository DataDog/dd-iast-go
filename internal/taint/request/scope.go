// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/config"
)

// Decision is the immutable sampling/capacity outcome for a request scope. It
// does not report liveness; callers must use [Scope.Active] after acquisition.
type Decision uint8

const (
	DecisionDisabled Decision = iota
	DecisionSampledOut
	DecisionCapacityDropped
	DecisionActive
)

type contextKey struct{}

var (
	processManager atomic.Pointer[Manager]
	defaultManager = sync.OnceValue(func() *Manager {
		manager := NewManager(nil)
		processManager.Store(manager)
		return manager
	})
)

// Scope carries one request analysis and decision. It is shared by nested
// handlers. The Begin call that returns created=true MUST defer [Scope.Finish].
type Scope struct {
	mu sync.RWMutex
	// +checklocks:mu
	analysis Analysis
	// +checklocks:mu
	decision Decision
}

// Begin makes one sampling decision and, when sampled, acquires one bounded
// analysis permit. An existing scope is reused and created is false.
func Begin(ctx context.Context) (derived context.Context, scope *Scope, created bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if existing := FromContext(ctx); existing != nil {
		return ctx, existing, false
	}
	if !config.Enabled {
		return ctx, nil, false
	}
	decision := sampleDecision(config.RequestSamplingPct)
	scope = &Scope{decision: decision}
	if decision == DecisionActive {
		if config.MaxConcurrentRequests <= 0 {
			scope.decision = DecisionCapacityDropped
		} else {
			analysis, ok := defaultManager().Acquire(config.MaxConcurrentRequests)
			if !ok {
				scope.decision = DecisionCapacityDropped
			} else {
				scope.analysis = analysis
			}
		}
	}
	return context.WithValue(ctx, contextKey{}, scope), scope, true
}

func sampleDecision(percent int) Decision {
	switch {
	case percent <= 0:
		return DecisionSampledOut
	case percent >= 100:
		return DecisionActive
	case rand.IntN(100) < percent:
		return DecisionActive
	default:
		return DecisionSampledOut
	}
}

// FromContext returns the request scope, if any.
func FromContext(ctx context.Context) *Scope {
	if ctx == nil {
		return nil
	}
	scope, _ := ctx.Value(contextKey{}).(*Scope)
	return scope
}

// Decision returns the immutable sampling/capacity outcome. It remains
// DecisionActive after Finish; use [Scope.Active] to test current liveness.
func (s *Scope) Decision() Decision {
	if s == nil {
		return DecisionDisabled
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.decision
}

// Active reports whether the scope owns a live analysis.
func (s *Scope) Active() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.decision == DecisionActive && s.analysis.Active()
}

// Analysis returns a copy of the generation-captured analysis handle.
func (s *Scope) Analysis() (Analysis, bool) {
	if s == nil {
		return Analysis{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.analysis, s.decision == DecisionActive && s.analysis.Active()
}

// EnabledTagValue returns the `_dd.iast.enabled` value for a bound span.
func (s *Scope) EnabledTagValue() int {
	if s != nil && s.Active() {
		return 1
	}
	return 0
}

// Finish releases this scope's analysis. It is idempotent.
func (s *Scope) Finish() {
	if s == nil {
		return
	}
	s.mu.Lock()
	analysis := s.analysis
	s.analysis = Analysis{}
	s.mu.Unlock()
	analysis.Finish()
}
