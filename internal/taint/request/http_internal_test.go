// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"net/url"
	"runtime"
	"strconv"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/stretchr/testify/require"
)

// testBody is a body type that the tests register as a hooked body type.
type testBody struct{ n int }

func init() {
	httpbridge.RegisterBodyType((*testBody)(nil))
}

// swapProcessManager makes m the process manager for the test (the lazy URL
// sources use the process manager).
func swapProcessManager(t *testing.T, m *Manager) {
	t.Helper()
	previous := processManager.Swap(m)
	t.Cleanup(func() { processManager.Store(previous) })
}

// scopeContext returns a context with an active scope of a.
func scopeContext(a Analysis) context.Context {
	return context.WithValue(context.Background(), contextKey{}, &Scope{decision: DecisionActive, analysis: a})
}

// sourcesOf returns "origin:name=value" for each source of the owner of a
// in value.
func sourcesOf(t *testing.T, a Analysis, value string) []string {
	t.Helper()
	var r Attribution
	a.AttributeString(value, &r)
	var found []string
	for i := 0; i < r.N; i++ {
		if source, ok := r.Source(i); ok {
			found = append(found, source.Origin.String()+":"+source.Name+"="+source.Value)
		}
	}
	return found
}

func TestEagerHTTPTaintsFieldsAndRegistersObjects(t *testing.T) {
	f := useFakeBits(t)
	m := NewManager()
	swapProcessManager(t, m)
	a := newAnalysis(t, m)
	ctx := scopeContext(a)

	uri := heapString("/source?q=value")
	path, query := uri[:7], uri[8:]
	readOnlyName := "Content-Type"
	// Read-only data in the real runtime: Set fails, and the value is
	// cloned.
	f.refuse = func(p, _ uintptr) bool { return p == uintptr(unsafe.Pointer(unsafe.StringData(readOnlyName))) }
	headers := map[string][]string{
		readOnlyName:       {heapString("application/test")},
		heapString("X-In"): {heapString("attacker")},
	}
	u := &url.URL{Path: path, RawQuery: query}
	body := &testBody{n: 1}

	managed := EagerHTTP(ctx, &uri, &path, &query, headers, u, body)
	require.Equal(t, "/source?q=value", uri)
	require.Equal(t, 7, a.SourceCount(), "URI, path, query, 2 header values, 2 header names")
	require.Equal(t, []string{"http.request.uri:=/source?q=value"}, sourcesOf(t, a, uri))
	require.Equal(t, []string{"http.request.path:=/source"}, sourcesOf(t, a, path))
	require.Equal(t, []string{"http.request.query:=q=value"}, sourcesOf(t, a, query))

	// The read-only header name is a clone in the new header map.
	require.Len(t, managed, 2)
	for name, values := range managed {
		require.Len(t, values, 1)
		require.Equal(t, []string{"http.request.header.name:" + name + "=" + name}, sourcesOf(t, a, name))
		require.Equal(t, []string{"http.request.header:" + name + "=" + values[0]}, sourcesOf(t, a, values[0]))
		if name == readOnlyName {
			require.NotSame(t, unsafe.StringData(readOnlyName), unsafe.StringData(name))
		}
	}

	require.True(t, a.bodyRegistered())
	owner, ok := m.urlOwner(u)
	require.True(t, ok)
	require.Equal(t, a.id, owner.id)
	_, ok = m.urlOwner(&url.URL{Path: "/source"})
	require.False(t, ok, "an other URL object has no owner")

	a.Finish()
	require.False(t, a.bodyRegistered())
	_, ok = m.urlOwner(u)
	require.False(t, ok, "the URL of a finished owner has no owner")
	runtime.KeepAlive(body)
}

func TestEagerHTTPRegistersOnlyHookedBodyTypes(t *testing.T) {
	useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	ctx := scopeContext(a)
	type otherBody struct{ n int }
	EagerHTTP(ctx, nil, nil, nil, nil, nil, &otherBody{n: 1})
	require.False(t, a.bodyRegistered())
	EagerHTTP(ctx, nil, nil, nil, nil, "not a URL", testBody{n: 2})
	require.False(t, a.bodyRegistered(), "a value of the element type is not a body object")
	require.Zero(t, a.SourceCount())
}

func TestEagerHTTPWithoutAnalysisKeepsHeaders(t *testing.T) {
	useFakeBits(t)
	headers := map[string][]string{"X-In": {heapString("attacker")}}
	uri := heapString("/uri")
	got := EagerHTTP(context.Background(), &uri, nil, nil, headers, nil, &testBody{})
	require.Equal(t, headers, got)
	require.Equal(t, "/uri", uri)
}

func TestManagedLazyMapIsIdempotentAndAllocationFree(t *testing.T) {
	useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	values := map[string][]string{heapString("query"): {heapString("attacker")}}
	managed := a.manageMap(values, constants.OriginHttpRequestParameterName, constants.OriginHttpRequestParameter)
	require.Equal(t, 2, a.SourceCount())
	budget := a.Budget()
	allocations := testing.AllocsPerRun(100, func() {
		managed = a.manageMap(managed, constants.OriginHttpRequestParameterName, constants.OriginHttpRequestParameter)
	})
	require.Zero(t, allocations)
	require.Equal(t, 2, a.SourceCount())
	require.Equal(t, budget, a.Budget())
}

func TestManageURLQueryNeedsOneOwner(t *testing.T) {
	useFakeBits(t)
	m := NewManager()
	swapProcessManager(t, m)
	alpha := newAnalysis(t, m)
	bravo := newAnalysis(t, m)
	u := &url.URL{RawQuery: "name=value"}
	require.True(t, alpha.registerURL(u))

	values := map[string][]string{heapString("name"): {heapString("value")}}
	got := ManageURLQuery(u, values)
	require.Equal(t, []string{"http.request.parameter:name=value"}, sourcesOf(t, alpha, got["name"][0]))
	require.Equal(t, 2, alpha.SourceCount())

	// A URL with two owners is ambiguous: the values are not managed.
	require.True(t, bravo.registerURL(u))
	fresh := map[string][]string{heapString("other"): {heapString("other-value")}}
	require.Equal(t, fresh, ManageURLQuery(u, fresh))
	require.Equal(t, 2, alpha.SourceCount())
	require.Zero(t, bravo.SourceCount())

	// Not a URL, or no values: no change.
	require.Equal(t, fresh, ManageURLQuery("not a URL", fresh))
	require.Nil(t, ManageURLQuery(u, nil))
	runtime.KeepAlive(u)
}

func TestLazyParametersPreserveValuesWhenSourceTableIsFull(t *testing.T) {
	useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	ctx := scopeContext(a)
	for index := range MaxSources {
		_, ok := a.TaintString(constants.OriginHttpRequestHeader, strconv.Itoa(index), heapString("header-value"))
		require.True(t, ok)
	}
	for _, manage := range []func(context.Context, string, string) string{
		ManageParameter, ManageMultipartParameter, ManagePathParameter,
	} {
		value := heapString("unchanged-value")
		got := manage(ctx, "missing", value)
		require.Equal(t, "unchanged-value", got)
		require.Same(t, unsafe.StringData(value), unsafe.StringData(got))
		require.Equal(t, MaxSources, a.SourceCount())
	}
}

func TestLazyMultipartWithoutScopePreservesMaps(t *testing.T) {
	ctx := context.Background()
	values := map[string][]string{"name": {"value"}}
	got := ManageMultipart(ctx, values, nil, nil)
	require.Equal(t, values, got)
	require.Equal(t, "value", ManageMultipartParameter(ctx, "name", "value"))
	require.Equal(t, "x", ManageMultipartParameter(ctx, "name", "x"))
}

func TestLazyMultipartPreservesNilValuesAndUnmatchedFormSuffixes(t *testing.T) {
	f := useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	ctx := scopeContext(a)
	bodyValue := heapString("body-value")
	other := heapString("different-value")
	values := map[string][]string{heapString("empty"): nil, heapString("part"): {bodyValue}}
	form := map[string][]string{"part": {heapString("query-value"), other}}
	post := map[string][]string{"part": {bodyValue}}
	managed := ManageMultipart(ctx, values, form, post)
	require.Nil(t, managed["empty"])
	require.Equal(t, []string{"query-value", "different-value"}, form["part"])
	require.Equal(t, []string{"http.request.multipart.parameter:part=body-value"}, sourcesOf(t, a, managed["part"][0]))
	require.Equal(t, []string{"http.request.multipart.parameter:part=body-value"}, sourcesOf(t, a, post["part"][0]))
	require.False(t, f.any(uintptr(unsafe.Pointer(unsafe.StringData(other))), uintptr(len(other))))
}

func TestLazyFormDropsExcessValuesWithoutPartialTaint(t *testing.T) {
	f := useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	ctx := scopeContext(a)
	form := map[string][]string{"name": make([]string, 97)}
	for index := range form["name"] {
		form["name"][index] = heapString("value")
	}
	got, post := ManageForm(ctx, form, nil)
	require.Equal(t, form, got)
	require.Nil(t, post)
	require.Zero(t, a.SourceCount())
	for _, value := range got["name"] {
		require.False(t, f.any(uintptr(unsafe.Pointer(unsafe.StringData(value))), uintptr(len(value))))
	}
}

// TestLazyParameterKeepsOwnSource checks that a value that is already a
// source of the owner (same address, same bytes) is not registered again,
// and that a window of a source is registered as its own source.
func TestLazyParameterKeepsOwnSource(t *testing.T) {
	useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	ctx := scopeContext(a)
	query, ok := a.TaintString(constants.OriginHttpRequestQuery, "", heapString("name=query-value&other=x"))
	require.True(t, ok)
	value := query[5:16]
	require.False(t, a.IsSource(value), "a window of a source is not a source")

	managed := ManageParameter(ctx, "name", value)
	require.Same(t, unsafe.StringData(value), unsafe.StringData(managed), "set in place")
	require.True(t, a.IsSource(managed))
	require.Equal(t, 2, a.SourceCount())
	require.Equal(t, []string{"http.request.parameter:name=query-value"}, sourcesOf(t, a, managed))
	require.Equal(t, managed, ManageParameter(ctx, "other", managed), "a source is not managed again")
	require.Equal(t, 2, a.SourceCount())
}

func TestManageCookieNameAndValue(t *testing.T) {
	useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	ctx := scopeContext(a)
	name, value := heapString("session"), heapString("cookie-value")
	ManageCookie(ctx, &name, &value)
	require.Equal(t, []string{"http.request.cookie.name:session=session"}, sourcesOf(t, a, name))
	require.Equal(t, []string{"http.request.cookie.value:session=cookie-value"}, sourcesOf(t, a, value))
	require.NotPanics(t, func() { ManageCookie(ctx, nil, nil) })
}
