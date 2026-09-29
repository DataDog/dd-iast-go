// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtimebridge

import "sync/atomic"

// The interior filter layout (plan section 5.2). The store imports these
// definitions, so the store and the bridge cannot use different hashes.
const (
	// ShiftS is the granule shift of tier S (64-byte granules).
	ShiftS = 6
	// ShiftL is the granule shift of tier L (4 KiB granules).
	ShiftL = 12
	// FilterBuckets is the number of filter counters.
	FilterBuckets = 1 << 15
	// TierLBit marks a tier L granule key.
	TierLBit = ^(^uintptr(0) >> 1)

	indexHashMultiplier = 0x9e3779b97f4a7c15
)

// Filter is the interior filter: one counter for each bucket. A bucket is not
// zero while an indexed root has a granule key in the bucket.
type Filter = [FilterBuckets]atomic.Uint32

// GranuleKey returns the index key of the granule that contains address.
func GranuleKey(address uintptr, large bool) uintptr {
	if large {
		return TierLBit | (address>>ShiftL + 1)
	}
	return address>>ShiftS + 1
}

// IndexHash returns the hash of an index key.
func IndexHash(key uintptr) uint64 { return uint64(key) * indexHashMultiplier }

// FilterBucket returns the filter bucket of an index key hash.
func FilterBucket(hash uint64) uint32 { return uint32(hash>>37) & (FilterBuckets - 1) }

func bucketS(p uintptr) uint32 { return FilterBucket(IndexHash(GranuleKey(p, false))) }

func bucketL(p uintptr) uint32 { return FilterBucket(IndexHash(GranuleKey(p, true))) }

// FilterHit reports whether an indexed root can contain a value with data
// pointer p. It reads tier S first, then tier L (plan section 5.2.2, "Reader
// order"). A false result proves that no indexed root contains the value. It
// does not allocate and it cannot panic: the bucket index is masked.
//
// It is the same as bucketS and bucketL, written out so that the compiler can
// inline it in the pre-checks and in Store.MayContain. TestFilterHitUsesBothTiers
// compares the two forms.
func FilterHit(f *Filter, p uintptr) bool {
	small := uint64(p>>ShiftS+1) * indexHashMultiplier
	if f[uint32(small>>37)&(FilterBuckets-1)].Load() != 0 {
		return true
	}
	large := uint64(TierLBit|(p>>ShiftL+1)) * indexHashMultiplier
	return f[uint32(large>>37)&(FilterBuckets-1)].Load() != 0
}
