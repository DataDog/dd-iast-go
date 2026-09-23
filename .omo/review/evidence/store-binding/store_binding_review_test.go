// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"io"
	"net/url"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

type reviewFirstFieldBody struct {
	url.URL
	state int
}

func (*reviewFirstFieldBody) Read([]byte) (int, error) { return 0, io.EOF }
func (*reviewFirstFieldBody) Close() error              { return nil }

func TestReviewURLBindingSurvivesReaderAtSameAddress(t *testing.T) {
	// Given: the request URL is the first field of its body reader.
	prevEnabled, prevSampling, prevMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = prevEnabled, prevSampling, prevMax
	})
	ctx, scope, created := Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("failed to acquire sampled scope")
	}
	defer scope.Finish()
	body := &reviewFirstFieldBody{URL: url.URL{RawQuery: "payload=attack"}}
	if uintptr(unsafe.Pointer(body)) != uintptr(unsafe.Pointer(&body.URL)) {
		t.Fatal("test setup does not alias first field")
	}

	// When: eager HTTP binds both objects and URL.Query returns parsed values.
	EagerHTTP(ctx, nil, nil, &body.URL.RawQuery, nil, &body.URL, body)
	got := ManageURLQuery(&body.URL, body.URL.Query())
	analysis, ok := scope.Analysis()
	if !ok {
		t.Fatal("active analysis disappeared")
	}
	var refs [1]store.OwnerRef
	urlBindings := store.LookupObjectValue(analysis.manager.store, &body.URL, store.BindingURL, refs[:])
	readerBindings := store.LookupObjectValue(analysis.manager.store, body, store.BindingReader, refs[:])
	tainted := IsTaintedString(got["payload"][0])
	t.Logf("URL bindings=%d reader bindings=%d query tainted=%t query=%q", urlBindings, readerBindings, tainted, got["payload"][0])

	// Then: both supported relationships retain provenance.
	if urlBindings != 1 || readerBindings != 1 || !tainted {
		t.Fatal("URL.Query source lost when reader shares the URL's address")
	}
}

func TestReviewOwnerFinishAfterHandlerPanicReleasesBindingsAndPermit(t *testing.T) {
	// Given: a request owns a bound reader and tainted value.
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	if !ok {
		t.Fatal("failed to acquire analysis")
	}
	reader := &reviewFirstFieldBody{state: 1}
	if !store.BindObjectValue(analysis.storeOwner(), reader, store.BindingReader) {
		t.Fatal("failed to bind reader")
	}
	var refs [1]store.OwnerRef
	if store.LookupObjectValue(manager.Store(), reader, store.BindingReader, refs[:]) != 1 {
		t.Fatal("failed to look up reader")
	}
	stale := refs[0]
	if _, tainted := analysis.TaintString(constants.OriginHttpRequestBody, "", "panic-source"); !tainted {
		t.Fatal("failed to taint source")
	}

	// When: handler cleanup is deferred and the handler panics.
	func() {
		defer func() { _ = recover() }()
		defer analysis.Finish()
		panic("handler")
	}()

	// Then: anchors, values and permit are released, and a stale ref stays dead.
	if manager.Store().ProcessCharged() != 0 || manager.Store().ProcessValues() != 0 {
		t.Fatal("owner retained charged roots after panic")
	}
	if store.LookupObjectValue(manager.Store(), reader, store.BindingReader, refs[:]) != 0 {
		t.Fatal("reader binding survived owner finish")
	}
	reused, ok := manager.Acquire(1)
	if !ok {
		t.Fatal("analysis permit leaked after panic")
	}
	defer reused.Finish()
	if _, ok := stale.Handle(); ok {
		t.Fatal("stale owner ref resolved into a reused slot")
	}
	t.Log("panic cleanup: roots=0 values=0 bindings=0 permit=reacquired stale-ref=invalid")
}
