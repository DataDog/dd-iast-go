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
	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
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
		jsonbridge.BindActiveOwners(&manager.used)
		jsonbridge.BindActiveValues(manager.store.IndexedRoots())
		// Only the process store is visible to the runtime hooks (plan
		// runtime-operator-hooks, section 3.2 rule 6). The store is not
		// shared yet, as BindRuntimeBridge requires.
		manager.store.BindRuntimeBridge(runtimebridge.Options{StringToSlice: config.StringToSlicePropagationEnabled})
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
	// inactive is the decision of a shared scope without analysis (see
	// inactiveScopes). It is DecisionDisabled for the scope of one request.
	// It does not change, thus the methods read it without mu, and they do not
	// lock or change a shared scope.
	inactive Decision
}

// inactiveScopes are the shared scopes of the requests that have no analysis
// (sampled out or capacity dropped), for each entry. A request of this type
// thus does not allocate a scope: only the context value. The scopes do not
// change. No caller compares scope pointers.
var inactiveScopes = func() (scopes [EntryServer + 1][DecisionActive]*Scope) {
	for entry := range scopes {
		for _, decision := range []Decision{DecisionSampledOut, DecisionCapacityDropped} {
			scopes[entry][decision] = &Scope{decision: decision, entry: Entry(entry), inactive: decision}
		}
	}
	return scopes
}()

// inactiveScope returns the shared scope of the given inactive decision and
// entry.
func inactiveScope(decision Decision, entry Entry) *Scope {
	return inactiveScopes[entry][decision]
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
	// The decision comes first: a request without analysis uses a shared
	// scope and allocates only the context value.
	scope = inactiveScope(DecisionSampledOut, entry)
	if sampleDecision(config.RequestSamplingPct) == DecisionActive {
		scope = inactiveScope(DecisionCapacityDropped, entry)
		if config.MaxConcurrentRequests > 0 {
			if analysis, ok := defaultManager().Acquire(config.MaxConcurrentRequests); ok {
				scope = &Scope{analysis: analysis, decision: DecisionActive, entry: entry}
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
	iobridge.Register(iobridge.Callbacks{
		Propagate:        PropagateReader,
		PropagateShared:  PropagateSharedReader,
		PropagateJoin:    PropagateJoinedReader,
		PropagateGuarded: PropagateGuardedReader,
		Retarget:         retargetReader,
		Owner:            readAllOwner,
		ReadAll:          readAllEnd,
	})
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
	if s.inactive != DecisionDisabled {
		return s.inactive
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.decision
}

// Active reports whether the scope owns a live analysis.
func (s *Scope) Active() bool {
	if s == nil || s.inactive != DecisionDisabled {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.decision == DecisionActive && s.analysis.Active()
}

// Analysis returns a copy of the generation-captured analysis handle.
func (s *Scope) Analysis() (Analysis, bool) {
	if s == nil || s.inactive != DecisionDisabled {
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
	if s == nil || s.inactive != DecisionDisabled {
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
