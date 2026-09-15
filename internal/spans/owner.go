// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"sync/atomic"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/scopebridge"
	taintstore "github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

type ownerSpanBinding struct {
	id         uint64
	generation uint64
	root       weak.Pointer[tracer.Span]
	annotation *Annotation
}

var ownerSpans [request.MaxAnalyses]atomic.Pointer[ownerSpanBinding]
var _ [taintstore.MaxOwners - len(ownerSpans)]struct{}
var _ [len(ownerSpans) - taintstore.MaxOwners]struct{}

func bindOwnerSpan(scope *request.Scope, root *tracer.Span, annotation *Annotation) {
	if scope == nil || root == nil || annotation == nil || !annotation.Sampled {
		return
	}
	analysis, ok := scope.Analysis()
	if !ok {
		return
	}
	index, id, generation, ok := analysis.Identity()
	if !ok || int(index) >= len(ownerSpans) {
		return
	}
	current := ownerSpans[index].Load()
	if current != nil && current.id == id && current.generation == generation && current.annotation != nil && !current.annotation.Closed() && current.root.Value() != nil {
		return
	}
	binding := &ownerSpanBinding{
		id: id, generation: generation, root: weak.Make(root), annotation: annotation,
	}
	for {
		currentIndex, currentID, currentGeneration, active := analysis.Identity()
		if !active || currentIndex != index || currentID != id || currentGeneration != generation {
			return
		}
		if ownerSpans[index].CompareAndSwap(current, binding) {
			break
		}
		current = ownerSpans[index].Load()
		if current != nil && current.id == id && current.generation == generation && current.annotation != nil && !current.annotation.Closed() && current.root.Value() != nil {
			return
		}
	}
	currentIndex, currentID, currentGeneration, active := analysis.Identity()
	if !active || currentIndex != index || currentID != id || currentGeneration != generation {
		ownerSpans[index].CompareAndSwap(binding, nil)
	}
}

// ExistingForOwner resolves one generation-validated owner to an existing open
// request root and annotation. It never creates an annotation. The caller must
// use Annotation.TryUseOpen, tolerate closure after return, and not retain the
// returned strong span reference.
func ExistingForOwner(index uint8, id, generation uint64) (*tracer.Span, *Annotation, bool) {
	if int(index) >= len(ownerSpans) || id == 0 || generation == 0 {
		return nil, nil, false
	}
	binding := ownerSpans[index].Load()
	if binding == nil || binding.id != id || binding.generation != generation || binding.annotation == nil || binding.annotation.Closed() {
		return nil, nil, false
	}
	root := binding.root.Value()
	if root == nil {
		ownerSpans[index].CompareAndSwap(binding, nil)
		return nil, nil, false
	}
	if ownerSpans[index].Load() != binding || binding.annotation.Closed() {
		return nil, nil, false
	}
	return root, binding.annotation, true
}

func finishOwnerSpan(index uint8, id, generation uint64) {
	if int(index) >= len(ownerSpans) {
		return
	}
	binding := ownerSpans[index].Load()
	if binding != nil && binding.id == id && binding.generation == generation {
		ownerSpans[index].CompareAndSwap(binding, nil)
	}
}

func init() {
	scopebridge.Register(finishOwnerSpan)
}
