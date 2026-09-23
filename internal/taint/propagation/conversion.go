// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// BytesToString copies byte provenance to an equal-length managed string.
func BytesToString(input []byte, result string) string {
	if len(result) < 2 || len(input) != len(result) || len(result) > store.MaxRootBytes {
		return result
	}
	active := request.ActiveStore()
	if active == nil {
		return result
	}
	key, ok := store.BytesKey(input)
	if !ok || !active.MayContain(key) {
		return result
	}
	var snapshot store.Snapshot
	if !active.Lookup(key, &snapshot) {
		return result
	}
	published := false
	for index := 0; index < snapshot.Len(); index++ {
		entry, ok := snapshot.At(index)
		if !ok {
			continue
		}
		var copied ranges.Set
		if !ranges.Copy(&copied, entry.Ranges.Limit(), &entry.Ranges, uint32(len(input))).Valid {
			continue
		}
		if owner, ok := entry.Handle(active); ok {
			if _, ok = owner.AdoptString(result, &copied); ok {
				published = true
			}
		}
	}
	if published {
		recordExecuted()
	}
	return result
}
