// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"reflect"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// CaseString propagates a Unicode case transform. An aliasing unchanged result
// derives exact input ranges. ASCII inputs with unchanged byte length keep exact
// positions. Other changed results use coarse ranges on an exact-length clone.
func CaseString(input, result string) string {
	if len(result) == 0 || len(result) > store.MaxRootBytes {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	key, ok := store.StringKey(input)
	if !ok || !s.MayContain(key) {
		return result
	}
	return caseStringHit(s, key, input, result)
}

//go:noinline
func caseStringHit(s *store.Store, key store.Key, input, result string) string {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return result
	}
	recordExecuted()
	if stringAlias(input, result) {
		deriveStringWindow(result, &snapshot, s)
		return result
	}
	if len(result) < 2 {
		return result
	}
	exact := len(input) == len(result) && asciiString(input)
	if !exact {
		recordCoarse()
	}
	clone := strings.Clone(result)
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, ok := snapshot.At(entryIndex)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		var outcome ranges.Outcome
		if exact {
			outcome = ranges.Copy(&resultSet, entry.Ranges.Limit(), &entry.Ranges, uint32(len(input)))
		} else {
			outcome = ranges.Coarse(&resultSet, entry.Ranges.Limit(), uint32(len(clone)), []ranges.Part{{
				Ranges: &entry.Ranges, Length: uint32(len(input)),
			}})
		}
		if !outcome.Valid || resultSet.Len() == 0 {
			continue
		}
		owner, ok := entry.Handle(s)
		if ok {
			owner.AdoptString(clone, &resultSet)
		}
	}
	return clone
}

func asciiString(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			return false
		}
	}
	return true
}

// CoarseFormatString propagates direct string and byte-slice format arguments.
// It inspects at most sixteen arguments and never invokes String methods again.
func CoarseFormatString(result string, arguments []any) string {
	if len(result) < 2 || len(result) > store.MaxRootBytes || len(arguments) == 0 {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	return coarseFormatStringHit(s, result, arguments)
}

// CoarseFormattedString propagates a format string and at most fifteen direct
// format arguments without allocating a combined argument slice.
func CoarseFormattedString(result, format string, arguments []any) string {
	if len(result) < 2 || len(result) > store.MaxRootBytes {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	return coarseFormattedStringHit(s, result, format, arguments)
}

//go:noinline
func coarseFormattedStringHit(s *store.Store, result, format string, arguments []any) string {
	if len(arguments) > maxInputs-1 {
		recordDropped()
	}
	var owners [store.MaxSnapshotOwners]coarseOwner
	ownerCount := accumulateCoarseKey(s, stringKey(format), &owners, 0)
	inspected := min(len(arguments), maxInputs-1)
	for argumentIndex := 0; argumentIndex < inspected; argumentIndex++ {
		key, ok := formatArgumentKey(arguments[argumentIndex])
		if ok {
			ownerCount = accumulateCoarseKey(s, key, &owners, ownerCount)
		}
	}
	return publishCoarseOwners(s, result, &owners, ownerCount)
}

//go:noinline
func coarseFormatStringHit(s *store.Store, result string, arguments []any) string {
	if len(arguments) > maxInputs {
		recordDropped()
	}
	var owners [store.MaxSnapshotOwners]coarseOwner
	ownerCount := 0
	inspected := min(len(arguments), maxInputs)
	for argumentIndex := 0; argumentIndex < inspected; argumentIndex++ {
		key, ok := formatArgumentKey(arguments[argumentIndex])
		if ok {
			ownerCount = accumulateCoarseKey(s, key, &owners, ownerCount)
		}
	}
	return publishCoarseOwners(s, result, &owners, ownerCount)
}

func accumulateCoarseKey(s *store.Store, key store.Key, owners *[store.MaxSnapshotOwners]coarseOwner, ownerCount int) int {
	if key.Pointer == 0 || !s.MayContain(key) {
		return ownerCount
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return ownerCount
	}
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, ok := snapshot.At(entryIndex)
		if !ok {
			continue
		}
		owner := coarseMatch(owners[:ownerCount], entry)
		if owner == nil {
			if ownerCount >= len(owners) {
				continue
			}
			owners[ownerCount].entry = *entry
			owner = &owners[ownerCount]
			ownerCount++
		}
		coarseAccumulate(owner, &entry.Ranges)
	}
	return ownerCount
}

func publishCoarseOwners(s *store.Store, result string, owners *[store.MaxSnapshotOwners]coarseOwner, ownerCount int) string {
	if ownerCount == 0 {
		return result
	}
	recordExecuted()
	recordCoarse()
	clone := strings.Clone(result)
	for ownerIndex := 0; ownerIndex < ownerCount; ownerIndex++ {
		state := &owners[ownerIndex]
		if !state.found {
			continue
		}
		owner, ok := state.entry.Handle(s)
		if !ok {
			continue
		}
		var resultSet ranges.Set
		var value [1]ranges.Range
		value[0] = ranges.Range{Length: uint32(len(clone)), SourceID: state.source, Marks: state.marks}
		if ranges.AdoptCanonical(&resultSet, state.entry.Ranges.Limit(), value[:], uint32(len(clone))).Valid {
			owner.AdoptString(clone, &resultSet)
		}
	}
	return clone
}

func stringKey(value string) store.Key {
	key, _ := store.StringKey(value)
	return key
}

func formatArgumentKey(argument any) (store.Key, bool) {
	if argument == nil {
		return store.Key{}, false
	}
	value := reflect.ValueOf(argument)
	switch value.Kind() {
	case reflect.String:
		return store.StringKey(value.String())
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 && !value.IsNil() {
			return store.BytesKey(value.Bytes())
		}
	}
	return store.Key{}, false
}
