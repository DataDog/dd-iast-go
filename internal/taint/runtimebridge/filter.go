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
// inline it in the filter checks, in the pre-checks and in Store.MayContain.
// TestFilterHitUsesBothTiers compares the two forms.
func FilterHit(f *Filter, p uintptr) bool { return filterHit(f, p, hashMultiplier) }

// hashMultiplier is indexHashMultiplier in a variable. A loop that checks many
// values reads it once before the loop. Then the multiplier stays in a
// register: the compiler does not make the 64-bit constant again in each
// iteration (4 instructions on arm64, and 4 more for the multiply-add of
// filterHit). Nothing writes this variable.
var hashMultiplier uint64 = indexHashMultiplier

// tierLHashBit is the part of TierLBit that changes the filter bucket: 0 on a
// 64-bit platform (bit 63 does not change bits 37 to 51 of the hash, see
// filterHit), TierLBit (bit 31) on a 32-bit platform. On a 64-bit platform,
// the compiler removes the OR with 0.
const tierLHashBit = TierLBit & (1<<32 - 1)

// filterHit is FilterHit with the hash multiplier m. m must be
// indexHashMultiplier.
//
// It always loads the two buckets and has one branch, not two. This is
// correct: the tier S load comes first in the program order, and Go atomic
// operations are sequentially consistent, so the tier L load cannot occur
// before the tier S load. When the tier S load is not zero, the result is
// true for each value of the tier L load.
//
// On a 64-bit platform, the tier L hash does not set TierLBit (bit 63) in the
// key. The key is less than 2^63, thus (TierLBit | key) * m = TierLBit * m +
// key * m, and TierLBit * m is TierLBit (modulo 2^64, m is odd). The two
// products are different only in bit 63, and the bucket uses bits 37 to 51.
// On a 32-bit platform, TierLBit is bit 31 and changes the bucket: there, the
// key keeps it (see tierLHashBit).
func filterHit(f *Filter, p uintptr, m uint64) bool {
	// (k+1)*m is written k*m + m: arm64 then uses one multiply-add.
	small := uint64(p>>ShiftS)*m + m
	large := uint64(p>>ShiftL|tierLHashBit)*m + m
	s := f[uint32(small>>37)&(FilterBuckets-1)].Load()
	l := f[uint32(large>>37)&(FilterBuckets-1)].Load()
	return s|l != 0
}
