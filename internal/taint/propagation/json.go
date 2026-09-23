// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"strings"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// JSONString propagates provenance intersecting a raw JSON literal to its
// decoded string. The boolean reports whether a managed clone was published.
func JSONString(document, literal []byte, result string) (string, bool) {
	if len(result) < 2 || len(result) > store.MaxRootBytes || len(document) < 2 || len(literal) == 0 {
		return result, false
	}
	s := request.ActiveStore()
	if s == nil {
		return result, false
	}
	key, ok := store.BytesKey(document)
	if !ok || !s.MayContain(key) || !bytesAlias(document, literal) {
		return result, false
	}
	documentPointer := uintptr(unsafe.Pointer(unsafe.SliceData(document)))
	literalPointer := uintptr(unsafe.Pointer(unsafe.SliceData(literal)))
	return jsonStringHit(s, key, uint32(literalPointer-documentPointer), uint32(len(literal)), result)
}

//go:noinline
func jsonStringHit(s *store.Store, key store.Key, offset, length uint32, result string) (string, bool) {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return result, false
	}
	clone := ""
	for index := 0; index < snapshot.Len(); index++ {
		entry, ok := snapshot.At(index)
		if !ok {
			continue
		}
		var intersected ranges.Set
		if outcome := ranges.Slice(&intersected, entry.Ranges.Limit(), &entry.Ranges, key.Length, offset, offset+length); !outcome.Valid || intersected.Len() == 0 {
			continue
		}
		var coarse ranges.Set
		if outcome := ranges.Coarse(&coarse, entry.Ranges.Limit(), uint32(len(result)), []ranges.Part{{Ranges: &intersected, Length: length}}); !outcome.Valid || coarse.Len() == 0 {
			continue
		}
		if clone == "" {
			clone = strings.Clone(result)
		}
		if owner, ok := entry.Handle(s); ok {
			owner.AdoptString(clone, &coarse)
		}
	}
	if clone == "" {
		return result, false
	}
	recordExecuted()
	recordCoarse()
	return clone, true
}
