// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"net/url"
	"runtime"
	"unsafe"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
)

const (
	maxEagerHeaderNames  = 32
	maxEagerHeaderValues = 64
)

// urlRef is a weak reference to the request URL object of an owner (plan
// section 6.5). The weak pointer does not retain the URL, and it cannot
// match a new object at a reused address.
type urlRef struct {
	// owner is the ID of the owner that registered the URL.
	owner uint64
	// addr is the address of the URL object. It is only a cheap first
	// check: the weak pointer gives the real answer.
	addr   uintptr
	object weak.Pointer[url.URL]
}

// EagerHTTP taints the request fields that are safe to read at the request
// entry, and registers the URL and body objects of the request. It never
// parses a form or reads the body. Header rebuilding is skipped when its
// bounded work limits are exceeded.
//
// bodyObject is registered only when its dynamic type is a hooked body type
// (see httpbridge.RegisterBodyType). The caller unwraps the body wrappers of
// the server (net/http expectContinueReader) before the call.
func EagerHTTP(
	ctx context.Context,
	requestURI, path, rawQuery *string,
	headers map[string][]string,
	urlObject, bodyObject any,
) map[string][]string {
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return headers
	}
	analysis.taintStringPointer(constants.OriginHttpRequestUri, "", requestURI)
	analysis.taintStringPointer(constants.OriginHttpRequestPath, "", path)
	analysis.taintStringPointer(constants.OriginHttpRequestQuery, "", rawQuery)
	if u, ok := urlObject.(*url.URL); ok && u != nil {
		analysis.registerURL(u)
	}
	if body := httpbridge.BodyObject(bodyObject); body != nil {
		analysis.RegisterBody(body)
	}
	return analysis.taintHeaders(headers)
}

// pinOwn pins the slot of a for an access of the owning request (bounded
// retries, as useOwn). On true, the caller must call a.manager.unpin.
func (a Analysis) pinOwn() bool {
	for attempt := 1; ; attempt++ {
		switch a.manager.pinOwner(a.slot, a.generation, a.id) {
		case accessDone:
			return true
		case accessGone:
			return false
		}
		if attempt >= ownAttempts {
			ownBusyDrops.Add(1)
			return false
		}
		runtime.Gosched()
	}
}

// registerURL makes u the request URL of the owner: the URL.Query hook then
// taints the values of the queries of u (see ManageURLQuery). The store
// occurs while the slot is pinned for this owner (same rule as
// RegisterBody).
func (a Analysis) registerURL(u *url.URL) bool {
	if u == nil || !a.Active() || !a.pinOwn() {
		return false
	}
	defer a.manager.unpin(a.slot)
	a.slot.url.Store(&urlRef{owner: a.id, addr: uintptr(unsafe.Pointer(u)), object: weak.Make(u)})
	return true
}

// bodyRegistered reports whether the owner of a has a registered request
// body that is still live (see RegisterBody).
func (a Analysis) bodyRegistered() bool {
	if !a.Active() {
		return false
	}
	ref := a.slot.body.Load()
	return ref != nil && ref.owner == a.id && ref.object.Value() != nil
}

// urlOwner returns the one live owner whose request URL is u. It returns
// false when no owner, or more than one owner, has u (an ambiguous owner is
// a safe drop).
func (m *Manager) urlOwner(u *url.URL) (Analysis, bool) {
	if u == nil || !m.Active() {
		return Analysis{}, false
	}
	addr := uintptr(unsafe.Pointer(u))
	var (
		found Analysis
		count int
	)
	m.forEachActive(func(s *slot, generation uint32, id uint64) bool {
		ref := s.url.Load()
		if ref == nil || ref.owner != id || ref.addr != addr || ref.object.Value() != u {
			return true
		}
		count++
		found = Analysis{manager: m, slot: s, id: id, generation: generation}
		return count < 2
	})
	if count != 1 || !found.Active() {
		return Analysis{}, false
	}
	return found, true
}

func (a Analysis) taintStringPointer(origin constants.Origin, name string, value *string) {
	if value == nil || *value == "" {
		return
	}
	if managed, ok := a.TaintString(origin, name, *value); ok {
		*value = managed
	}
}

type eagerHeader struct {
	name        string
	managedName string
	values      []string
	valueOffset uint16
}

func (a Analysis) taintHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 || len(headers) > maxEagerHeaderNames {
		return headers
	}
	valueCount := 0
	for _, values := range headers {
		if len(values) > maxEagerHeaderValues-valueCount {
			return headers
		}
		valueCount += len(values)
	}

	var entries [maxEagerHeaderNames]eagerHeader
	var managedValues [maxEagerHeaderValues]string
	entryCount := 0
	valueOffset := 0
	changed := false
	// Header values have higher admission priority than header names.
	for name, values := range headers {
		if entryCount >= maxEagerHeaderNames || valueOffset+len(values) > maxEagerHeaderValues {
			return headers
		}
		entry := &entries[entryCount]
		entry.name = name
		entry.managedName = name
		entry.values = values
		entry.valueOffset = uint16(valueOffset)
		for i, value := range values {
			managedValues[int(entry.valueOffset)+i] = value
			if replacement, ok := a.TaintString(constants.OriginHttpRequestHeader, name, value); ok {
				managedValues[int(entry.valueOffset)+i] = replacement
				changed = changed || !sameStringBacking(value, replacement)
			}
		}
		valueOffset += len(values)
		entryCount++
	}
	for i := 0; i < entryCount; i++ {
		entry := &entries[i]
		if replacement, ok := a.TaintString(constants.OriginHttpRequestHeaderName, entry.name, entry.name); ok {
			entry.managedName = replacement
			changed = changed || !sameStringBacking(entry.name, replacement)
		}
	}
	if !changed {
		return headers
	}
	managed := make(map[string][]string, entryCount)
	for i := 0; i < entryCount; i++ {
		entry := &entries[i]
		if entry.values == nil {
			managed[entry.managedName] = nil
			continue
		}
		values := make([]string, len(entry.values))
		copy(values, managedValues[int(entry.valueOffset):int(entry.valueOffset)+len(values)])
		managed[entry.managedName] = values
	}
	return managed
}
