// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/heartbeat"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/puzpuzpuz/xsync/v4"
)

const (
	// tombstoneBudget is the maximum number of entries kept for finished root
	// spans, in addition to the entries of the requests in flight. A finished
	// root stays in the store (closed) until the garbage collector reclaims the
	// span, so that a late report does not bring its annotation back.
	tombstoneBudget = 4096
	// trimInterval is the minimum time between two scans of the store for
	// entries of spans that no longer exist.
	trimInterval = 250 * time.Millisecond
)

var (
	// store is the association of tracer spans to annotation objects. An entry is
	// either open (it holds one unit of capacity), or closed (the root span
	// finished; it holds no capacity and only prevents a new annotation).
	store = xsync.NewMap[weak.Pointer[tracer.Span], *Annotation](xsync.WithPresize(2 * config.MaxConcurrentRequests))
	// open is the number of capacity units in use: the open entries of the
	// store, plus the units reserved by callers that are about to insert one.
	open atomic.Int64
	// nextTrim is the earliest time (Unix nanoseconds) of the next scan for dead
	// keys.
	nextTrim atomic.Int64
)

type Annotation struct {
	sync.RWMutex
	// +checklocks:RWMutex
	model.Event

	// Sampled is set when the annotation is created and never changes after.
	Sampled bool

	// spanID is the identifier of the root span that this annotation belongs to.
	// A tracer can reuse the memory of a finished span for a new span, and the
	// store is keyed by that memory: the identifier tells the two apart.
	spanID uint64
	// tombstone is true for an entry that only remembers a finished root.
	tombstone bool

	// closed is set once, when the root span finishes (or when the span is
	// reclaimed). A closed annotation accepts no new finding.
	closed atomic.Bool
	// finishOnce runs the work of [Finished] one time. A second call to
	// [Finished] for the same root waits until the first one is done.
	finishOnce sync.Once

	// RequestTainted is the number of tainted elemets at the end of the request.
	RequestTainted atomic.Uint64
}

// Closed returns true when the root span of the annotation finished. A
// finding that is added to a closed annotation is lost, so the caller MUST
// check this while it holds the write lock, and drop the finding.
func (a *Annotation) Closed() bool {
	return a.closed.Load()
}

// close marks the annotation as closed. Returns true for the one caller that
// closed it, which MUST then give back the unit of capacity with [release].
func (a *Annotation) close() bool {
	return a.closed.CompareAndSwap(false, true)
}

// closeAndRelease closes the annotation and gives back its unit of capacity.
func (a *Annotation) closeAndRelease() {
	if a.close() {
		release()
	}
}

func release() { open.Add(-1) }

// rootOf returns the root of the span, or the span itself if it has none.
func rootOf(span *tracer.Span) *tracer.Span {
	root := span.Root()
	if root == nil {
		instrumentation.Instance.TelemetryLog().
			Debug("iast/annotation: span has no root, using span itself", slog.Any("span", span.Context().SpanID()))
		return span
	}
	return root
}

// SamplingDecision returns true if the request of the given span is sampled
// for IAST. The decision depends only on the identifier of the root span, so
// every call for one request gives the same answer without any storage, and a
// request that is not sampled never uses capacity.
func SamplingDecision(span *tracer.Span) bool {
	return sampled(rootOf(span))
}

func sampled(root *tracer.Span) bool {
	switch config.RequestSamplingPct {
	case 0:
		return false
	case 100:
		return true
	default:
		return int(mix64(root.Context().SpanID())%100) < config.RequestSamplingPct
	}
}

// mix64 spreads the bits of x (the finalizer of SplitMix64).
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// AnnotationFor returns the [*Annotation] for the root of the given
// [*tracer.Span] (or the span itself if it does not have a valid root). If none
// exists yet, and the request is sampled and there is capacity, a new
// [*Annotation] is allocated.
//
// The result for a request that is not sampled, for a request that finished,
// or for a request without capacity is a new annotation with Sampled set to
// false. It is not stored.
func AnnotationFor(span *tracer.Span) *Annotation {
	if span == nil {
		return new(Annotation)
	}
	root := rootOf(span)
	id := root.Context().SpanID()
	key := weak.Make(root)

	if ann, ok := lookup(key, id); ok {
		return usable(ann)
	}

	if !sampled(root) {
		root.SetTag(SpanTagEnabled, 0)
		return new(Annotation)
	}

	if int64(config.MaxConcurrentRequests) <= open.Load() {
		// Entries of spans that no longer exist may hold capacity.
		trimStore()
	}

	// The check of the capacity and the insertion are one step: the callback
	// runs while the bucket of the key is locked, so a second report of the same
	// request waits, then finds the annotation of the first.
	var inserted, full bool
	ann, _ := store.Compute(key, func(old *Annotation, loaded bool) (*Annotation, xsync.ComputeOp) {
		if loaded {
			if old.spanID == id {
				return old, xsync.CancelOp
			}
			// The entry is from an earlier span that used the same memory.
			old.closeAndRelease()
		}
		if !reserve() {
			full = true
			return old, xsync.CancelOp
		}
		inserted = true
		return &Annotation{Sampled: true, spanID: id}, xsync.UpdateOp
	})
	if full {
		instrumentation.Instance.TelemetryLog().
			Warn("iast/annotation: max concurrent requests reached, not storing annotation for span", slog.Any("span", id))
		return new(Annotation)
	}
	if inserted {
		root.SetTag(SpanTagEnabled, 1)
	}
	return usable(ann)
}

// lookup returns the entry of the root span, if it belongs to this span.
func lookup(key weak.Pointer[tracer.Span], id uint64) (*Annotation, bool) {
	ann, ok := store.Load(key)
	if !ok || ann.spanID != id {
		return nil, false
	}
	return ann, true
}

// usable returns ann, or an unsampled annotation if ann is closed.
func usable(ann *Annotation) *Annotation {
	if ann.Closed() {
		return new(Annotation)
	}
	return ann
}

// reserve takes one unit of capacity. The check and the increment are one
// atomic step, so the number of units never goes above the limit.
func reserve() bool {
	limit := int64(config.MaxConcurrentRequests)
	for {
		n := open.Load()
		if n >= limit {
			return false
		}
		if open.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (a *Annotation) submitTelemetry() {
	if config.TelemetryVerbosity == config.LogLevelOff {
		return
	}
	client := instrumentation.Instance.TelemetryMetrics()
	client.Count(instrumentation.TelemetryNamespaceIAST, "request.tainted", nil).Submit(float64(a.RequestTainted.Load()))
}

// trimStore removes the entries where the [weak.Pointer] has turned nil, and
// gives back the capacity of those that were still open. A scan runs at most
// once every [trimInterval].
func trimStore() {
	now := time.Now().UnixNano()
	next := nextTrim.Load()
	if now < next || !nextTrim.CompareAndSwap(next, now+int64(trimInterval)) {
		return
	}
	store.DeleteMatching(func(key weak.Pointer[tracer.Span], ann *Annotation) (delete bool, stop bool) {
		if key.Value() != nil {
			return false, false
		}
		ann.closeAndRelease()
		return true, false
	})
}

// retainClosed replaces the closed entry of a finished root by a small
// tombstone, so that a report that arrives after the root finished does not
// create a new annotation. If the number of entries is over the limit, the
// entry is removed instead: a late report for that root is then not detected.
func retainClosed(key weak.Pointer[tracer.Span], ann *Annotation) {
	limit := int(min(int64(config.MaxConcurrentRequests), math.MaxInt32)) + tombstoneBudget
	if store.Size() >= limit {
		trimStore()
	}
	over := store.Size() >= limit
	store.Compute(key, func(old *Annotation, loaded bool) (*Annotation, xsync.ComputeOp) {
		switch {
		case !loaded || old != ann:
			return old, xsync.CancelOp
		case over:
			return nil, xsync.DeleteOp
		case old.tombstone:
			return old, xsync.CancelOp
		default:
			return newTombstone(old.spanID), xsync.UpdateOp
		}
	})
}

func newTombstone(id uint64) *Annotation {
	t := &Annotation{spanID: id, tombstone: true}
	t.closed.Store(true)
	t.finishOnce.Do(func() {})
	return t
}

func init() {
	// Note: this is here and not in the [github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry] package in
	// order to avoid creating a dependency from it to some of the tracer's internal, as it would make it much harder to
	// avoid creating circular dependencies when instrumenting packages the tracer itself uses. The metrics are
	// submitted by [heartbeat.Report].
	instrumentation.Instance.TelemetryMetrics().OnHeartbeat(func(c instrumentation.TelemetryMetrics) {
		heartbeat.Report(heartbeat.Count(c))
	})
}
