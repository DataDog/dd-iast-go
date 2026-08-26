// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// BindReader binds a non-nil pointer reader by address to the active context
// owner. Non-pointer and zero-sized values are safe misses.
func BindReader(ctx context.Context, reader any) bool {
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return false
	}
	owner := analysis.storeOwner()
	return owner != nil && store.BindObjectValue(owner, reader, store.BindingReader)
}

// PropagateReader binds output to every active owner bound to input. Dynamic
// non-pointer reader values are unsupported safe misses.
func PropagateReader(input, output any) {
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count := LookupObject(input, store.BindingReader, refs[:])
	for i := 0; i < count; i++ {
		owner, ok := refs[i].Handle()
		if !ok {
			continue
		}
		store.BindObjectValue(&owner, output, store.BindingReader)
	}
}

// ReadAllBytes adopts an io.ReadAll result into every active owner bound to its
// input reader without changing the result slice.
func ReadAllBytes(input any, data []byte) {
	if len(data) < 2 {
		return
	}
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count := LookupObject(input, store.BindingReader, refs[:])
	if len(data) > store.MaxRootBytes || cap(data) > store.MaxRootBytes {
		for i := 0; i < count; i++ {
			if owner, ok := refs[i].Handle(); ok {
				owner.RecordBytesDrop()
			}
		}
		return
	}
	for i := 0; i < count; i++ {
		analysis, ok := analysisForOwner(refs[i])
		if !ok {
			continue
		}
		analysis.adoptBodyBytes(data)
	}
}

func (a Analysis) adoptBodyBytes(data []byte) bool {
	if !a.Active() || !a.slot.sourceMu.TryLock() {
		return false
	}
	defer a.slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !a.Active() {
		return false
	}
	result, token := a.slot.table.prepareBytes(constants.OriginHttpRequestBody, "", data)
	if result.Status != AddAdded && result.Status != AddDuplicate {
		return false
	}
	owner := a.slot.owner.Load()
	if owner == nil || owner.Disabled() {
		return false
	}
	if result.Status == AddDuplicate {
		var set ranges.Set
		if !ranges.AdoptCanonical(
			&set,
			ranges.DefaultLimit,
			[]ranges.Range{{Length: uint32(len(data)), SourceID: result.ID}},
			uint32(cap(data)),
		).Valid {
			return false
		}
		_, ok := owner.AdoptBytes(data, &set)
		return ok
	}
	managedName, managedValue, _, ok := owner.AdoptSourceBytes(data, "", result.ID)
	if !ok {
		return false
	}
	a.slot.table.commit(token, Source{
		Origin: constants.OriginHttpRequestBody,
		Name:   managedName, Value: managedValue, Kind: SourceBytes,
	})
	return true
}
