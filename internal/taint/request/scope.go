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
	"github.com/DataDog/dd-iast-go/internal/taint/commandbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/scopebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/sqlbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/urlbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
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

// Entry identifies the boundary that created a request scope.
type Entry uint8

const (
	EntryFallback Entry = iota
	EntryServer
)

type contextKey struct{}

var (
	processManager atomic.Pointer[Manager]
	defaultManager = sync.OnceValue(func() *Manager {
		manager := NewManager(nil)
		manager.store.BindWriterActive(writerbridge.ActiveCounter())
		commandbridge.BindActiveOwners(&manager.used)
		sqlbridge.BindActiveOwners(&manager.used)
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
	entry    Entry
}

// Begin makes one sampling decision and, when sampled, acquires one bounded
// analysis permit. An existing scope is reused and created is false.
func Begin(ctx context.Context) (derived context.Context, scope *Scope, created bool) {
	return begin(ctx, EntryFallback)
}

func begin(ctx context.Context, entry Entry) (derived context.Context, scope *Scope, created bool) {
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
	scope = &Scope{decision: decision, entry: entry}
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

// Entry returns the boundary that created this scope.
func (s *Scope) Entry() Entry {
	if s == nil {
		return EntryFallback
	}
	return s.entry
}

// BeginServerContext creates or reuses the standard net/http server scope.
// h2c connection-level requests are filtered by httpbridge before this call.
func BeginServerContext(ctx context.Context) (context.Context, bool) {
	derived, _, created := begin(ctx, EntryServer)
	return derived, created
}

// BeginContext creates or reuses a scope at an application handler boundary.
func BeginContext(ctx context.Context) (context.Context, bool) {
	derived, _, created := Begin(ctx)
	return derived, created
}

// FinishContext releases the scope only when the matching entry bridge created
// it. It is safe to defer and is idempotent through Scope.Finish.
func FinishContext(ctx context.Context, created bool) {
	if !created {
		return
	}
	if scope := FromContext(ctx); scope != nil {
		scope.Finish()
	}
}

func init() {
	httpbridge.Register(BeginServerContext, FinishContext, EagerHTTP)
	iobridge.Register(PropagateReader, ReadAllBytes)
	httpbridge.RegisterLazy(
		ManageForm, ManageParameter, ManageMultipartParameter,
		ManagePathParameter, ManageCookie, ManageMultipart,
	)
	urlbridge.Register(ManageURLQuery)
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
	index, id, generation, identified := analysis.Identity()
	analysis.Finish()
	if identified {
		scopebridge.Finish(index, id, generation)
	}
}
