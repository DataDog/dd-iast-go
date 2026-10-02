// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
)

// liveContexts are the request contexts of the running tests, in the order of
// their start. taint.VisitString visits the ranges of one request only. A
// propagation test can combine the values of more than one request, so it
// visits the ranges of each request.
var liveContexts contextList

type contextList struct {
	mu sync.Mutex
	// +checklocks:mu
	values []context.Context
}

// trackContext adds ctx to liveContexts until the end of t.
func trackContext(t *testing.T, ctx context.Context) {
	t.Helper()
	liveContexts.mu.Lock()
	liveContexts.values = append(liveContexts.values, ctx)
	liveContexts.mu.Unlock()
	t.Cleanup(func() {
		liveContexts.mu.Lock()
		defer liveContexts.mu.Unlock()
		if index := slices.Index(liveContexts.values, ctx); index >= 0 {
			liveContexts.values = slices.Delete(liveContexts.values, index, index+1)
		}
	})
}

func trackedContexts() []context.Context {
	liveContexts.mu.Lock()
	defer liveContexts.mu.Unlock()
	return slices.Clone(liveContexts.values)
}

// visitString visits the ranges of value of each live request, in the order
// of the request start. It stops when visit returns false.
func visitString(value string, visit func(taint.Range) bool) bool {
	delivered, keepGoing := false, true
	for _, ctx := range trackedContexts() {
		delivered = taint.VisitString(ctx, value, func(found taint.Range) bool {
			keepGoing = visit(found)
			return keepGoing
		}) || delivered
		if !keepGoing {
			break
		}
	}
	return delivered
}

// visitBytes is visitString for a byte slice.
func visitBytes(value []byte, visit func(taint.Range) bool) bool {
	delivered, keepGoing := false, true
	for _, ctx := range trackedContexts() {
		delivered = taint.VisitBytes(ctx, value, func(found taint.Range) bool {
			keepGoing = visit(found)
			return keepGoing
		}) || delivered
		if !keepGoing {
			break
		}
	}
	return delivered
}
