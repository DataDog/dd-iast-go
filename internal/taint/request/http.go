// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

func analysisForOwner(ref store.OwnerRef) (Analysis, bool) {
	manager := processManager.Load()
	if manager == nil {
		return Analysis{}, false
	}
	ownerIndex, ownerGen, ownerID, ok := ref.Identity()
	if !ok || ownerIndex >= MaxAnalyses {
		return Analysis{}, false
	}
	slot := manager.directory[ownerIndex].Load()
	if slot == nil {
		return Analysis{}, false
	}
	generation := slot.generation.Load()
	if !slot.active.Load() || slot.ownerID.Load() != ownerID || slot.ownerGen.Load() != ownerGen {
		return Analysis{}, false
	}
	analysis := Analysis{
		manager: manager, slot: slot, index: slot.index,
		ownerIndex: ownerIndex, gen: generation,
	}
	return analysis,
		analysis.Active() &&
			slot.generation.Load() == generation &&
			manager.directory[ownerIndex].Load() == slot
}

// LookupObject returns active request owners bound to a dynamic pointer object.
func LookupObject(object any, kind store.BindingKind, out []store.OwnerRef) int {
	manager := processManager.Load()
	if manager == nil || manager.used.Load() == 0 {
		return 0
	}
	return store.LookupObjectValue(manager.store, object, kind, out)
}

const (
	maxEagerHeaderNames  = 32
	maxEagerHeaderValues = 64
)

// EagerHTTP manages safe request-entry fields and binds URL/body objects. It
// never parses a form or reads the body. Header rebuilding is skipped when its
// bounded work limits are exceeded.
func EagerHTTP(
	ctx context.Context,
	requestURI, path, rawQuery *string,
	headers map[string][]string,
	urlObject, bodyObject any,
) map[string][]string {
	scope := FromContext(ctx)
	analysis, ok := scope.Analysis()
	if !ok {
		return headers
	}
	analysis.taintStringPointer(constants.OriginHttpRequestUri, "", requestURI)
	analysis.taintStringPointer(constants.OriginHttpRequestPath, "", path)
	analysis.taintStringPointer(constants.OriginHttpRequestQuery, "", rawQuery)

	if owner := analysis.storeOwner(); owner != nil {
		store.BindObjectValue(owner, urlObject, store.BindingURL)
		store.BindObjectValue(owner, bodyObject, store.BindingReader)
	}
	return analysis.taintHeaders(headers)
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
				changed = true
			}
		}
		valueOffset += len(values)
		entryCount++
	}
	for i := 0; i < entryCount; i++ {
		entry := &entries[i]
		if replacement, ok := a.TaintString(constants.OriginHttpRequestHeaderName, entry.name, entry.name); ok {
			entry.managedName = replacement
			changed = true
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
