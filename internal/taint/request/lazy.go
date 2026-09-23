// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

const (
	maxLazyMapNames  = 48
	maxLazyMapValues = 96
)

type lazyMapEntry struct {
	name        string
	managedName string
	values      []string
	valueOffset uint16
}

// ManageURLQuery manages one fresh result of URL.Query when the URL has exactly
// one active request owner. Ambiguous multi-owner attribution is a safe drop.
// Repeated calls reuse the same source clones.
func ManageURLQuery(urlObject any, values map[string][]string) map[string][]string {
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count := LookupObject(urlObject, store.BindingURL, refs[:])
	if count != 1 {
		return values
	}
	analysis, ok := analysisForOwner(refs[0])
	if !ok {
		return values
	}
	return analysis.manageMap(
		values,
		constants.OriginHttpRequestParameterName,
		constants.OriginHttpRequestParameter,
	)
}

// ManageForm manages request form and post-form maps after parsing.
func ManageForm(ctx context.Context, form, postForm map[string][]string) (map[string][]string, map[string][]string) {
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return form, postForm
	}
	form = analysis.manageMap(form, constants.OriginHttpRequestParameterName, constants.OriginHttpRequestParameter)
	postForm = analysis.manageMap(postForm, constants.OriginHttpRequestParameterName, constants.OriginHttpRequestParameter)
	return form, postForm
}

// ManageParameter manages a lazily returned form/query parameter value.
func ManageParameter(ctx context.Context, name, value string) string {
	if len(value) < 2 || IsTaintedString(value) {
		return value
	}
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return value
	}
	managed, ok := analysis.ManageString(constants.OriginHttpRequestParameter, name, value)
	if !ok {
		return value
	}
	return managed
}

// ManageMultipartParameter manages a value returned from a multipart value
// part when map-level management was dropped.
func ManageMultipartParameter(ctx context.Context, name, value string) string {
	if len(value) < 2 || IsTaintedString(value) {
		return value
	}
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return value
	}
	managed, ok := analysis.ManageString(constants.OriginHttpRequestMultipartParameter, name, value)
	if !ok {
		return value
	}
	return managed
}

// ManagePathParameter manages a value returned by Request.PathValue.
func ManagePathParameter(ctx context.Context, name, value string) string {
	if len(value) < 2 || IsTaintedString(value) {
		return value
	}
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return value
	}
	managed, ok := analysis.ManageString(constants.OriginHttpRequestPathParameter, name, value)
	if !ok {
		return value
	}
	return managed
}

// ManageMultipart manages multipart value parts and replaces the matching
// appended suffixes in the combined form maps. File parts are untouched.
func ManageMultipart(ctx context.Context, values, form, postForm map[string][]string) map[string][]string {
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return values
	}
	managed := analysis.manageMap(
		values,
		constants.OriginHttpRequestMultipartParameter,
		constants.OriginHttpRequestMultipartParameter,
	)
	for name, originalValues := range values {
		managedValues, exists := managed[name]
		if !exists || len(managedValues) != len(originalValues) {
			continue
		}
		replaceMatchingSuffix(form[name], originalValues, managedValues)
		replaceMatchingSuffix(postForm[name], originalValues, managedValues)
	}
	return managed
}

func replaceMatchingSuffix(target, original, managed []string) {
	if len(original) == 0 || len(target) < len(original) {
		return
	}
	start := len(target) - len(original)
	for i := range original {
		if target[start+i] != original[i] {
			return
		}
	}
	copy(target[start:], managed)
}

// ManageCookie manages one cookie name and value in place.
func ManageCookie(ctx context.Context, name, value *string) {
	analysis, ok := FromContext(ctx).Analysis()
	if !ok || name == nil || value == nil {
		return
	}
	originalName := *name
	if len(*value) >= 2 && !IsTaintedString(*value) {
		if managed, ok := analysis.ManageString(constants.OriginHttpRequestCookieValue, originalName, *value); ok {
			*value = managed
		}
	}
	if len(originalName) >= 2 && !IsTaintedString(originalName) {
		if managed, ok := analysis.ManageString(constants.OriginHttpRequestCookieName, originalName, originalName); ok {
			*name = managed
		}
	}
}

func (a Analysis) manageMap(values map[string][]string, nameOrigin, valueOrigin constants.Origin) map[string][]string {
	if len(values) == 0 || len(values) > maxLazyMapNames {
		return values
	}
	valueCount := 0
	for _, items := range values {
		if len(items) > maxLazyMapValues-valueCount {
			return values
		}
		valueCount += len(items)
	}

	var entries [maxLazyMapNames]lazyMapEntry
	var managedValues [maxLazyMapValues]string
	entryCount := 0
	valueOffset := 0
	changed := false
	for name, items := range values {
		if entryCount >= maxLazyMapNames || valueOffset+len(items) > maxLazyMapValues {
			return values
		}
		entry := &entries[entryCount]
		entry.name = name
		entry.managedName = name
		entry.values = items
		entry.valueOffset = uint16(valueOffset)
		for i, value := range items {
			managedValues[valueOffset+i] = value
			if managed, ok := a.ManageString(valueOrigin, name, value); ok {
				managedValues[valueOffset+i] = managed
				changed = changed || !sameStringBacking(value, managed)
			}
		}
		valueOffset += len(items)
		entryCount++
	}
	for i := 0; i < entryCount; i++ {
		entry := &entries[i]
		if managed, ok := a.ManageString(nameOrigin, entry.name, entry.name); ok {
			entry.managedName = managed
			changed = changed || !sameStringBacking(entry.name, managed)
		}
	}
	if !changed {
		return values
	}
	managed := make(map[string][]string, entryCount)
	for i := 0; i < entryCount; i++ {
		entry := &entries[i]
		if entry.values == nil {
			managed[entry.managedName] = nil
			continue
		}
		items := make([]string, len(entry.values))
		copy(items, managedValues[int(entry.valueOffset):int(entry.valueOffset)+len(items)])
		managed[entry.managedName] = items
	}
	return managed
}

func sameStringBacking(left, right string) bool {
	if len(left) == 0 || len(left) != len(right) {
		return len(left) == len(right)
	}
	return unsafe.StringData(left) == unsafe.StringData(right)
}
