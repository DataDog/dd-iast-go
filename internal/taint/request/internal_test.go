// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"fmt"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestEagerHTTPManagesFieldsHeadersAndBindings(t *testing.T) {
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	ctx, scope, created := Begin(context.Background())
	require.True(t, created)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	uri, path, query := "/source?q=value", "/source", "q=value"
	originalURI := unsafe.StringData(uri)
	originalPath := unsafe.StringData(path)
	originalQuery := unsafe.StringData(query)
	headers := map[string][]string{
		"Content-Type": {"application/test"},
		"X-Input":      {"attacker"},
	}
	type object struct{ value int }
	urlObject := &object{value: 1}
	bodyObject := &object{value: 2}
	managedHeaders := EagerHTTP(ctx, &uri, &path, &query, headers, urlObject, bodyObject)
	require.False(t, unsafe.StringData(uri) == originalURI)
	require.False(t, unsafe.StringData(path) == originalPath)
	require.False(t, unsafe.StringData(query) == originalQuery)
	require.Equal(t, 7, analysis.SourceCount())

	var contentTypeKey string
	for key := range managedHeaders {
		if key == "Content-Type" {
			contentTypeKey = key
		}
	}
	require.NotEmpty(t, contentTypeKey)
	key, valid := store.StringKey(contentTypeKey)
	require.True(t, valid)
	var snapshot store.Snapshot
	require.True(t, analysis.manager.store.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	literalKey, _ := store.StringKey("Content-Type")
	analysis.manager.store.Lookup(literalKey, &snapshot)
	require.Zero(t, snapshot.Len())

	var refs [2]store.OwnerRef
	require.Equal(t, 1, store.LookupObjectValue(analysis.manager.store, urlObject, store.BindingURL, refs[:]))
	resolved, ok := analysisForOwner(refs[0])
	require.True(t, ok)
	require.Equal(t, analysis.index, resolved.index)
	require.Equal(t, analysis.ownerIndex, resolved.ownerIndex)
	require.Equal(t, 1, store.LookupObjectValue(analysis.manager.store, bodyObject, store.BindingReader, refs[:]))
	wrapper := &object{value: 3}
	PropagateReader(bodyObject, wrapper)
	require.Equal(t, 1, store.LookupObjectValue(analysis.manager.store, wrapper, store.BindingReader, refs[:]))
	body := make([]byte, 4, 8)
	copy(body, "body")
	bodyPointer := unsafe.SliceData(body)
	ReadAllBytes(wrapper, body)
	require.True(t, bodyPointer == unsafe.SliceData(body))
	bodyKey, _ := store.BytesKey(body)
	require.True(t, analysis.manager.store.Lookup(bodyKey, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	scope.Finish()
	require.Zero(t, store.LookupObjectValue(analysis.manager.store, urlObject, store.BindingURL, refs[:]))
}

func TestManagedLazyMapIsIdempotentAndAllocationFree(t *testing.T) {
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	values := map[string][]string{"query": {"attacker"}}
	managed := analysis.manageMap(values, constants.OriginHttpRequestParameterName, constants.OriginHttpRequestParameter)
	require.Equal(t, 2, analysis.SourceCount())
	charged := manager.Store().ProcessCharged()
	allocations := testing.AllocsPerRun(100, func() {
		managed = analysis.manageMap(managed, constants.OriginHttpRequestParameterName, constants.OriginHttpRequestParameter)
	})
	require.Zero(t, allocations)
	require.Equal(t, 2, analysis.SourceCount())
	require.Equal(t, charged, manager.Store().ProcessCharged())
	analysis.Finish()
}

func TestReadAllBytesPublishesEveryBoundOwner(t *testing.T) {
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	firstCtx, firstScope, created := Begin(context.Background())
	require.True(t, created)
	secondCtx, secondScope, created := Begin(context.Background())
	require.True(t, created)
	reader := new(int)
	require.True(t, BindReader(firstCtx, reader))
	require.True(t, BindReader(secondCtx, reader))
	data := make([]byte, 4, 8)
	copy(data, "body")
	ReadAllBytes(reader, data)
	firstAnalysis, ok := firstScope.Analysis()
	require.True(t, ok)
	secondAnalysis, ok := secondScope.Analysis()
	require.True(t, ok)
	require.Equal(t, 1, firstAnalysis.SourceCount())
	require.Equal(t, 1, secondAnalysis.SourceCount())
	key, _ := store.BytesKey(data)
	var snapshot store.Snapshot
	require.True(t, firstAnalysis.manager.store.Lookup(key, &snapshot))
	require.Equal(t, 2, snapshot.Len())

	firstScope.Finish()
	require.True(t, secondAnalysis.manager.store.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	secondScope.Finish()
	if secondAnalysis.manager.store.Lookup(key, &snapshot) {
		require.Zero(t, snapshot.Len())
	}
}

func TestCloneReaderBytesPublishesIndependentDocument(t *testing.T) {
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})

	reader := new(int)
	require.Nil(t, CloneReaderBytes(reader, []byte("unbound")))
	require.Nil(t, CloneReaderBytes(reader, []byte("x")))
	require.Nil(t, CloneReaderBytes(reader, make([]byte, store.MaxRootBytes+1)))

	firstCtx, firstScope, created := Begin(context.Background())
	require.True(t, created)
	t.Cleanup(firstScope.Finish)
	secondCtx, secondScope, created := Begin(context.Background())
	require.True(t, created)
	t.Cleanup(secondScope.Finish)
	require.True(t, BindReader(firstCtx, reader))
	require.True(t, BindReader(secondCtx, reader))

	document := make([]byte, 4, 16)
	copy(document, "body")
	clone := CloneReaderBytes(reader, document)
	require.Equal(t, document, clone)
	require.Equal(t, len(clone), cap(clone))
	document[0] = 'x'
	require.Equal(t, []byte("body"), clone)

	firstAnalysis, ok := firstScope.Analysis()
	require.True(t, ok)
	secondAnalysis, ok := secondScope.Analysis()
	require.True(t, ok)
	require.Equal(t, 1, firstAnalysis.SourceCount())
	require.Equal(t, 1, secondAnalysis.SourceCount())
	key, valid := store.BytesKey(clone)
	require.True(t, valid)
	var snapshot store.Snapshot
	require.True(t, firstAnalysis.manager.store.Lookup(key, &snapshot))
	require.Equal(t, 2, snapshot.Len())
}

func TestAdoptBodyBytesPreservesSliceAndReusesSource(t *testing.T) {
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	first := make([]byte, 6, 12)
	copy(first, "attack")
	firstPointer := unsafe.SliceData(first)
	require.True(t, analysis.adoptBodyBytes(first))
	require.True(t, firstPointer == unsafe.SliceData(first))
	require.Equal(t, 1, analysis.SourceCount())
	firstCharge := manager.Store().ProcessCharged()

	second := make([]byte, 6, 12)
	copy(second, "attack")
	require.True(t, analysis.adoptBodyBytes(second))
	require.Equal(t, 1, analysis.SourceCount())
	require.Greater(t, manager.Store().ProcessCharged(), firstCharge)
	for _, value := range [][]byte{first, second} {
		key, valid := store.BytesKey(value)
		require.True(t, valid)
		var snapshot store.Snapshot
		require.True(t, manager.Store().Lookup(key, &snapshot))
		require.Equal(t, 1, snapshot.Len())
	}
	analysis.Finish()
	require.Zero(t, manager.Store().ProcessCharged())
}

func TestEagerHeadersDoNotAllocateWhenAnalysisIsInactive(t *testing.T) {
	headers := map[string][]string{"X-Test": {"value"}}
	allocations := testing.AllocsPerRun(100, func() {
		if got := (Analysis{}).taintHeaders(headers); len(got) != 1 {
			panic("headers changed")
		}
	})
	require.Zero(t, allocations)
}

func TestWholeFeaturePhase2MemoryBound(t *testing.T) {
	fixed := unsafe.Sizeof(store.Store{}) + unsafe.Sizeof(Manager{})
	total := fixed + uintptr(store.ProcessRootBytes)
	t.Logf("store=%d manager=%d fixed=%d total=%d", unsafe.Sizeof(store.Store{}), unsafe.Sizeof(Manager{}), fixed, total)
	require.LessOrEqual(t, total, uintptr(24<<20))
}

// TestCollisionComparesFullValues forces two distinct sources that hash to the
// same index slot and verifies that full equality distinguishes them.
func TestCollisionComparesFullValues(t *testing.T) {
	tab := New()
	origin := constants.OriginHttpRequestParameter
	name := "q"

	// Find two distinct values that collide on the same slot for this table's
	// randomized seed. With 512 slots the birthday bound makes this trivial.
	slotOf := func(value string) uint32 { return tab.hash(origin, name, value) }
	seen := make(map[uint32]string)
	var v1, v2 string
	for i := 0; ; i++ {
		v := fmt.Sprintf("value-%d", i)
		slot := slotOf(v)
		if prev, ok := seen[slot]; ok && prev != v {
			v1, v2 = prev, v
			break
		}
		seen[slot] = v
	}
	require.Equal(t, slotOf(v1), slotOf(v2), "the two values must collide on the same slot")
	require.NotEqual(t, v1, v2)

	r1 := tab.Add(origin, name, v1)
	r2 := tab.Add(origin, name, v2)
	require.Equal(t, AddAdded, r1.Status)
	require.Equal(t, AddAdded, r2.Status)
	require.NotEqual(t, r1.ID, r2.ID, "colliding-but-distinct sources must get distinct IDs")
	require.Equal(t, 2, tab.Len())

	// Re-adding each colliding source returns its own ID, proving full-value
	// comparison resolves the collision rather than matching on the slot alone.
	r1b := tab.Add(origin, name, v1)
	require.Equal(t, AddDuplicate, r1b.Status)
	require.Equal(t, r1.ID, r1b.ID)

	r2b := tab.Add(origin, name, v2)
	require.Equal(t, AddDuplicate, r2b.Status)
	require.Equal(t, r2.ID, r2b.ID)

	// The records are retrievable and exact.
	got1, ok := tab.Get(r1.ID)
	require.True(t, ok)
	require.Equal(t, Source{Origin: origin, Name: name, Value: v1}, got1)
	got2, ok := tab.Get(r2.ID)
	require.True(t, ok)
	require.Equal(t, Source{Origin: origin, Name: name, Value: v2}, got2)
}

// TestHashDoesNotAllocate guards the allocation-free probe path indirectly by
// checking the hash helper itself.
func TestOwnerDirectoryRejectsFinishedGeneration(t *testing.T) {
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	managed, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "q", "first")
	require.True(t, ok)
	key, ok := store.StringKey(managed)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, manager.store.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	var source Source
	require.True(t, manager.copySources(entry.OwnerIndex, entry.OwnerID, entry.OwnerGen, []SourceID{0}, []Source{source}))

	analysis.Finish()
	reused, ok := manager.Acquire(1)
	require.True(t, ok)
	_, ok = reused.TaintString(constants.OriginHttpRequestParameter, "q", "second")
	require.True(t, ok)
	var stale Source
	require.False(t, manager.copySources(entry.OwnerIndex, entry.OwnerID, entry.OwnerGen, []SourceID{0}, []Source{stale}))
	reused.Finish()
}

func TestPrepareBytesDoesNotAllocateOnDuplicate(t *testing.T) {
	tab := New()
	origin := constants.OriginHttpRequestBody
	added := tab.Add(origin, "body", "attack")
	require.Equal(t, AddAdded, added.Status)
	value := []byte("attack")
	allocs := testing.AllocsPerRun(100, func() {
		result, _ := tab.prepareBytes(origin, "body", value)
		if result.Status != AddDuplicate || result.ID != added.ID {
			t.Fatalf("prepareBytes() = %+v, want duplicate %d", result, added.ID)
		}
	})
	require.Zero(t, allocs)
}

func TestPreparedSourceDoesNotMutateUntilCommit(t *testing.T) {
	tab := New()
	result, token := tab.prepareString(constants.OriginHttpRequestParameter, "q", "value")
	require.Equal(t, AddAdded, result.Status)
	require.Zero(t, tab.Len())
	tab.commit(token, Source{Origin: constants.OriginHttpRequestParameter, Name: "q", Value: "value"})
	require.Equal(t, 1, tab.Len())
}

func TestHashDoesNotAllocate(t *testing.T) {
	tab := New()
	allocs := testing.AllocsPerRun(100, func() {
		_ = tab.hash(constants.OriginHttpRequestParameter, "name", "value")
	})
	require.Equal(t, float64(0), allocs)
}
