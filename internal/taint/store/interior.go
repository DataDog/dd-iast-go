// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"sync"
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
)

// The interior index finds the root that contains a value from any data
// pointer inside the root, not only from the root base (plan section 5.2).
//
// The index has two tiers of granules. A root with a span of at most MaxSpanS
// bytes is in tier S (64-byte granules). A larger root is in tier L (4 KiB
// granules). A root has one ref in each granule that it covers, in its tier.
// All refs of one allocation base and one granule key are in one entry, with at
// most MaxSnapshotOwners refs and at most one ref for each owner.
//
// Lock order: owner.rootsMu, then indexShard.mu. A writer takes a shard lock
// only when it holds no rootsMu, except for the TryRLock of the commit check.
// Only rollback, the tier S clean-up of an extension and Owner.Finish wait on a
// shard lock. Readers only try the locks.
const (
	// ShiftS is the granule shift of tier S (64-byte granules). The runtime
	// bridge owns the filter layout, so both sides use the same hash.
	ShiftS = runtimebridge.ShiftS
	// ShiftL is the granule shift of tier L (4 KiB granules).
	ShiftL = runtimebridge.ShiftL
	// MaxSpanS is the largest root span in tier S.
	MaxSpanS = 256
	// IndexShards is the number of index shards. Each shard has its own lock.
	IndexShards = 256
	// IndexBucketsPerShard is the number of buckets in one shard.
	IndexBucketsPerShard = 16
	// IndexBucketSize is the number of entries in one bucket.
	IndexBucketSize = 8
	// IndexBucketProbe is the number of buckets that one key can use: the
	// home bucket and the next buckets of the same shard.
	IndexBucketProbe = 5
	// FilterBuckets is the number of filter counters.
	FilterBuckets = runtimebridge.FilterBuckets

	// maxRootKeys is the largest number of granules that one root covers:
	// 17 tier L granules for a root of MaxRootBytes at an unaligned base.
	maxRootKeys = MaxRootBytes>>ShiftL + 1
	// maxProbeRefs bounds the refs that one reader copies from both tiers.
	maxProbeRefs = 2 * MaxSnapshotOwners
	// writerLockTries bounds the TryLock tries of an index writer on one
	// shard (plan R14, "a bounded TryLock retry, at most 4 tries, no
	// blocking"). Readers try only once.
	writerLockTries = 4
	// writerLockSpin is the number of atomic loads between two tries.
	writerLockSpin = 64

	tierLBit = runtimebridge.TierLBit
)

// Tier S uses at most 5 granules for each root, and one granule key has at
// most 33 entries (64 / 2 + 1). Tier L uses at most 17 granules, and one key
// has at most 17 entries. Both are below the probe window.
const _ = uint(IndexBucketProbe*IndexBucketSize - 34)
const _ = uint(maxRootKeys - (MaxSpanS>>ShiftS + 1))

// ownerRef identifies one root of one owner. A ref never changes its rootID.
type ownerRef struct {
	ownerGen uint32 // low 32 bits of the owner generation
	rootID   uint16
	ownerIdx uint8
	kind     Kind
}

func (r ownerRef) sameRoot(other ownerRef) bool {
	return r.ownerIdx == other.ownerIdx && r.ownerGen == other.ownerGen && r.rootID == other.rootID
}

type indexEntry struct {
	key  uintptr // tier bit | (address >> shift) + 1; 0 = empty
	base uintptr // allocation base
	span uint32  // largest span of the refs; a prefilter only
	n    uint8   // refs in use
	refs [MaxSnapshotOwners]ownerRef
}

type indexShard struct {
	mu      sync.RWMutex
	buckets [IndexBucketsPerShard][IndexBucketSize]indexEntry
}

type indexPos struct {
	shard  *indexShard
	bucket uint8
	slot   uint8
}

type insertResult uint8

const (
	insertOK insertResult = iota
	insertContention
	insertFull
	insertFanout
)

type granuleKeys struct {
	keys [maxRootKeys]uintptr
	n    int
}

// forceIndexCollision is a test seam: every key uses shard 0 and bucket 0.
var forceIndexCollision atomic.Bool

// hookStage identifies a test hook point.
type hookStage uint8

const (
	// hookFirstInsert runs before the insert of key arg of a first adoption.
	// Returning true makes the insert fail with indexFull.
	hookFirstInsert hookStage = iota
	// hookFirstCommit runs before the commit TryLock of a first adoption.
	// Returning true makes the TryLock fail.
	hookFirstCommit
	// hookExtendBegin runs before the E1 TryLock. Returning true makes it fail.
	hookExtendBegin
	// hookExtendInsert runs before the insert of new key arg of an extension.
	// Returning true makes the insert fail with indexFull.
	hookExtendInsert
	// hookExtendCommit runs before the E4 TryLock. Returning true makes it fail.
	hookExtendCommit
	// hookExtendValid runs under rootsMu in E4, before the validity check.
	// Returning true makes the check fail.
	hookExtendValid
	// hookExtendPreCommit runs under rootsMu in E4, after the validity check
	// and before the commit. The return value is ignored.
	hookExtendPreCommit
	// hookExtendCleanup runs after the commit of a move from tier S to tier
	// L, before E5 removes the tier S refs. No lock is held.
	hookExtendCleanup
	// hookMutationLock runs before the rootsMu TryLock of a mutation.
	// Returning true makes the TryLock fail.
	hookMutationLock
	// hookMutationTail runs under rootsMu in a mutation of an extended root.
	// Returning true makes the ranges after cap(value) invalid.
	hookMutationTail
	// hookReaderTiers runs in readers after tier S and before tier L.
	hookReaderTiers
	// hookValidate runs in readers under rootsMu, for a root with
	// indexed == true.
	hookValidate
	// hookReaderBind runs in bindValue under the binding table lock, after
	// the reader bind counter add and before the table change (rule (e) of
	// plan encoding-json-v2, section 6.5). The result is not used.
	hookReaderBind
	// hookInputCounters runs in a reader lookup after it copied the input
	// identities of a derived exclusive binding, and before the input
	// lookups (rule (e)). No lock is held. The result is not used.
	hookInputCounters
	// hookLookupOwner runs in a reader lookup for each active owner, with
	// the owner slot as arg, before the lookup locks the owner (rule (f)).
	// No lock is held. The result is not used.
	hookLookupOwner
)

// testHook is a test seam. It is nil in production.
var testHook atomic.Pointer[func(stage hookStage, arg int) bool]

func runHook(stage hookStage, arg int) bool {
	if hook := testHook.Load(); hook != nil {
		return (*hook)(stage, arg)
	}
	return false
}

func largeSpan(span uint32) bool { return span > MaxSpanS }

// spinSink is only read by the spin loop, so the compiler keeps the loop.
var spinSink atomic.Uint32

// tryLockShard tries the write lock of shard at most writerLockTries times,
// with a short spin between the tries. It never waits on the lock.
func tryLockShard(shard *indexShard) bool {
	for try := 0; ; try++ {
		if shard.mu.TryLock() {
			return true
		}
		if try+1 >= writerLockTries {
			return false
		}
		for range writerLockSpin {
			spinSink.Load()
		}
	}
}

// tryRLockShard is tryLockShard for the read lock. Only writers use it.
func tryRLockShard(shard *indexShard) bool {
	for try := 0; ; try++ {
		if shard.mu.TryRLock() {
			return true
		}
		if try+1 >= writerLockTries {
			return false
		}
		for range writerLockSpin {
			spinSink.Load()
		}
	}
}

// granuleKey returns the index key of the granule that contains address.
func granuleKey(address uintptr, large bool) uintptr { return runtimebridge.GranuleKey(address, large) }

func indexHash(key uintptr) uint64 { return runtimebridge.IndexHash(key) }

func filterBucket(hash uint64) uint32 { return runtimebridge.FilterBucket(hash) }

func (s *Store) shardOf(hash uint64) (*indexShard, int) {
	if forceIndexCollision.Load() {
		return &s.index[0], 0
	}
	return &s.index[hash>>56&(IndexShards-1)], int(hash>>52) & (IndexBucketsPerShard - 1)
}

func (s *Store) filterHit(key uintptr) bool {
	return s.filter[filterBucket(indexHash(key))].Load() != 0
}

func (s *Store) filterAdd(key uintptr, delta int32) {
	s.filter[filterBucket(indexHash(key))].Add(uint32(delta))
}

// rootKeys returns the granule keys of [base, base+span) in one tier.
func rootKeys(base uintptr, span uint32, large bool) (granuleKeys, bool) {
	var keys granuleKeys
	if span == 0 || base+uintptr(span) < base {
		return keys, false
	}
	shift := uint(ShiftS)
	if large {
		shift = ShiftL
	}
	first := base >> shift
	last := (base + uintptr(span) - 1) >> shift
	if last-first >= maxRootKeys {
		return keys, false
	}
	for granule := first; granule <= last; granule++ {
		key := granule + 1
		if large {
			key |= tierLBit
		}
		keys.keys[keys.n] = key
		keys.n++
	}
	return keys, true
}

func (k *granuleKeys) contains(key uintptr) bool {
	for i := 0; i < k.n; i++ {
		if k.keys[i] == key {
			return true
		}
	}
	return false
}

// insertRef adds ref to the entry (key, base), or makes a new entry. It never
// waits for the shard lock.
func (s *Store) insertRef(key, base uintptr, span uint32, ref ownerRef) (indexPos, insertResult) {
	pos, result, step := s.insertRefStep(key, base, span, ref)
	if result == insertOK {
		for {
			current := s.indexMaxProbe.Load()
			if uint32(step) <= current || s.indexMaxProbe.CompareAndSwap(current, uint32(step)) {
				break
			}
		}
	}
	return pos, result
}

// insertRefStep is insertRef. It also returns the bucket distance that it used.
func (s *Store) insertRefStep(key, base uintptr, span uint32, ref ownerRef) (indexPos, insertResult, int) {
	shard, home := s.shardOf(indexHash(key))
	if !tryLockShard(shard) {
		return indexPos{}, insertContention, 0
	}
	defer shard.mu.Unlock() // +checklocksforce: TryLock.
	emptyBucket, emptySlot, emptyStep := -1, -1, 0
	for step := 0; step < IndexBucketProbe; step++ {
		bucket := (home + step) & (IndexBucketsPerShard - 1)
		for slot := range shard.buckets[bucket] {
			entry := &shard.buckets[bucket][slot]
			if entry.key == 0 {
				if emptyBucket < 0 {
					emptyBucket, emptySlot, emptyStep = bucket, slot, step
				}
				continue
			}
			if entry.key != key || entry.base != base {
				continue
			}
			for i := 0; i < int(entry.n); i++ {
				if entry.refs[i].ownerIdx == ref.ownerIdx && entry.refs[i].ownerGen == ref.ownerGen {
					// Another adoption of this owner on this allocation runs now.
					return indexPos{}, insertContention, 0
				}
			}
			if int(entry.n) >= len(entry.refs) {
				return indexPos{}, insertFanout, 0
			}
			entry.refs[entry.n] = ref
			entry.n++
			entry.span = max(entry.span, span)
			return indexPos{shard: shard, bucket: uint8(bucket), slot: uint8(slot)}, insertOK, step
		}
	}
	if emptyBucket < 0 {
		return indexPos{}, insertFull, 0
	}
	entry := &shard.buckets[emptyBucket][emptySlot]
	*entry = indexEntry{key: key, base: base, span: span, n: 1}
	entry.refs[0] = ref
	return indexPos{shard: shard, bucket: uint8(emptyBucket), slot: uint8(emptySlot)}, insertOK, emptyStep
}

// removeRefLocked removes ref from entry and clears the entry when it has no
// ref. It reports whether it removed a ref.
func removeRefLocked(entry *indexEntry, ref ownerRef) bool {
	for i := 0; i < int(entry.n); i++ {
		if !entry.refs[i].sameRoot(ref) {
			continue
		}
		last := int(entry.n) - 1
		entry.refs[i] = entry.refs[last]
		entry.refs[last] = ownerRef{}
		entry.n--
		if entry.n == 0 {
			*entry = indexEntry{}
		}
		return true
	}
	return false
}

// removeRefAt removes ref from the entry at pos. It waits for the shard lock.
func removeRefAt(pos indexPos, key, base uintptr, ref ownerRef) bool {
	if pos.shard == nil {
		return false
	}
	pos.shard.mu.Lock()
	defer pos.shard.mu.Unlock()
	entry := &pos.shard.buckets[pos.bucket][pos.slot]
	if entry.key != key || entry.base != base {
		return false
	}
	return removeRefLocked(entry, ref)
}

// removeRef finds and removes ref from the entry (key, base). It waits for the
// shard lock.
func (s *Store) removeRef(key, base uintptr, ref ownerRef) bool {
	shard, home := s.shardOf(indexHash(key))
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for step := 0; step < IndexBucketProbe; step++ {
		bucket := &shard.buckets[(home+step)&(IndexBucketsPerShard-1)]
		for slot := range bucket {
			entry := &bucket[slot]
			if entry.key == key && entry.base == base && removeRefLocked(entry, ref) {
				return true
			}
		}
	}
	return false
}

// widenEntry sets the prefilter span of the entry (key, base) to at least span.
// A wider prefilter is always safe, so no rollback restores it.
func (s *Store) widenEntry(key, base uintptr, span uint32) bool {
	shard, home := s.shardOf(indexHash(key))
	if !tryLockShard(shard) {
		return false
	}
	defer shard.mu.Unlock() // +checklocksforce: TryLock.
	for step := 0; step < IndexBucketProbe; step++ {
		bucket := &shard.buckets[(home+step)&(IndexBucketsPerShard-1)]
		for slot := range bucket {
			entry := &bucket[slot]
			if entry.key == key && entry.base == base {
				entry.span = max(entry.span, span)
				return true
			}
		}
	}
	return false
}

// ownRoot finds the root of this owner for the allocation base (plan section
// 5.2.2, step 0). It reads tier S first, then tier L. ok is false when a shard
// lock is contended, or when the refs of this owner name two roots.
func (o *Owner) ownRoot(base uintptr) (rootID uint16, found, ok bool) {
	gen := uint32(o.gen)
	for _, large := range [2]bool{false, true} {
		key := granuleKey(base, large)
		shard, home := o.store.shardOf(indexHash(key))
		if !tryRLockShard(shard) {
			return 0, false, false
		}
		mismatch := false
		for step := 0; step < IndexBucketProbe; step++ {
			bucket := &shard.buckets[(home+step)&(IndexBucketsPerShard-1)]
			for slot := range bucket {
				entry := &bucket[slot]
				if entry.key != key || entry.base != base {
					continue
				}
				for i := 0; i < int(entry.n); i++ {
					ref := entry.refs[i]
					if ref.ownerIdx != o.index || ref.ownerGen != gen {
						continue
					}
					if found && ref.rootID != rootID {
						mismatch = true
					}
					rootID, found = ref.rootID, true
				}
			}
		}
		shard.mu.RUnlock() // +checklocksforce: TryRLock.
		if mismatch {
			return 0, false, false
		}
	}
	return rootID, found, true
}

// commitCheckLocked runs the commit checks of a first adoption (plan section
// 5.2.2, step 5). The caller holds rootsMu. It only tries the shard locks. It
// reads the base-key entries of the allocation in both tiers and checks that:
//   - check (b): every ref of this owner names rootID. This stops two
//     concurrent first adoptions of one owner in different tiers;
//   - the allocation has at most MaxSnapshotOwners distinct owners in both
//     tiers together. An entry holds at most MaxSnapshotOwners refs, but one
//     allocation can have an entry in each tier. Each admission inserts its
//     refs before this check, so two concurrent admissions of different
//     owners always see each other: the limit is never passed. Both can be
//     refused, which is a counted fanout drop.
func (o *Owner) commitCheckLocked(base uintptr, rootID uint16) insertResult {
	gen := uint32(o.gen)
	var owners [2 * MaxSnapshotOwners]ownerRef
	count := 0
	for _, large := range [2]bool{false, true} {
		key := granuleKey(base, large)
		shard, home := o.store.shardOf(indexHash(key))
		if !tryRLockShard(shard) {
			return insertContention
		}
		result := insertOK
		for step := 0; step < IndexBucketProbe; step++ {
			bucket := &shard.buckets[(home+step)&(IndexBucketsPerShard-1)]
			for slot := range bucket {
				entry := &bucket[slot]
				if entry.key != key || entry.base != base {
					continue
				}
				for i := 0; i < int(entry.n); i++ {
					ref := entry.refs[i]
					if ref.ownerIdx == o.index && ref.ownerGen == gen {
						if ref.rootID != rootID {
							result = insertContention
						}
						continue
					}
					if !containsOwner(owners[:count], ref) && count < len(owners) {
						owners[count] = ref
						count++
					}
				}
			}
		}
		shard.mu.RUnlock() // +checklocksforce: TryRLock.
		if result != insertOK {
			return result
		}
	}
	if count+1 > MaxSnapshotOwners {
		return insertFanout
	}
	return insertOK
}

func containsOwner(owners []ownerRef, ref ownerRef) bool {
	for i := range owners {
		if owners[i].ownerIdx == ref.ownerIdx && owners[i].ownerGen == ref.ownerGen {
			return true
		}
	}
	return false
}

func (o *Owner) recordInsertFailure(result insertResult) {
	recordInsertFailure(&o.owner.drops, result)
}

func recordInsertFailure(drops *dropCounters, result insertResult) {
	switch result {
	case insertContention:
		drops.contention.Add(1)
	case insertFanout:
		drops.fanout.Add(1)
	default:
		drops.indexFull.Add(1)
	}
}

func (s *Store) removeInserted(positions []indexPos, keys []uintptr, base uintptr, ref ownerRef) {
	for i := range positions {
		removeRefAt(positions[i], keys[i], base, ref)
	}
}

// indexRoot publishes the index refs of a new root with all-or-nothing
// semantics (plan section 5.2.2, steps 1 to 6, without rollbackRoot). On
// success, the root is visible to lookups. On failure, no ref and no filter
// count of this root stays, and the caller must roll back the root.
func (o *Owner) indexRoot(rootID uint16, generation uint32, base uintptr, span uint32, kind Kind) bool {
	s := o.store
	keys, ok := rootKeys(base, span, largeSpan(span))
	if !ok {
		o.owner.drops.indexFull.Add(1)
		return false
	}
	ref := ownerRef{ownerGen: uint32(o.gen), rootID: rootID, ownerIdx: o.index, kind: kind}
	var inserted [maxRootKeys]indexPos
	for i := 0; i < keys.n; i++ {
		result := insertFull
		if !runHook(hookFirstInsert, i) {
			inserted[i], result = s.insertRef(keys.keys[i], base, span, ref)
		}
		if result != insertOK {
			s.removeInserted(inserted[:i], keys.keys[:i], base, ref)
			o.recordInsertFailure(result)
			return false
		}
	}
	// The gate goes on before the root can be visible.
	s.addIndexedRoots(1)
	for i := 0; i < keys.n; i++ {
		s.filterAdd(keys.keys[i], 1)
	}
	result := insertContention
	if !runHook(hookFirstCommit, 0) && o.owner.rootsMu.TryLock() {
		root := &o.owner.roots[rootID]
		if root.generation.Load() == generation {
			result = o.commitCheckLocked(base, rootID)
		}
		if result == insertOK {
			root.indexed = true
		}
		o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
	}
	if result == insertOK {
		return true
	}
	for i := 0; i < keys.n; i++ {
		s.filterAdd(keys.keys[i], -1)
	}
	s.removeInserted(inserted[:keys.n], keys.keys[:keys.n], base, ref)
	s.addIndexedRoots(-1)
	o.recordInsertFailure(result)
	return false
}

// unindexRootLocked removes every ref of an indexed root. The caller holds
// rootsMu (Finish). The indexed-root counter changes last.
func (o *Owner) unindexRootLocked(root *rootRecord, rootID uint16) {
	if !root.indexed {
		return
	}
	root.indexed = false
	s := o.store
	ref := ownerRef{ownerGen: uint32(o.gen), rootID: rootID, ownerIdx: o.index}
	if keys, ok := rootKeys(root.base, root.span, largeSpan(root.span)); ok {
		for i := 0; i < keys.n; i++ {
			if s.removeRef(keys.keys[i], root.base, ref) {
				s.filterAdd(keys.keys[i], -1)
			}
		}
	}
	s.addIndexedRoots(-1)
}

// candidate is a ref that a reader copied under the shard read lock.
type candidate struct {
	base uintptr
	ref  ownerRef
}

// probe copies the refs of the entries of key that contain [p, p+n). It
// reports false when the shard lock is contended.
func (s *Store) probe(key, p uintptr, n uint32, out *[maxProbeRefs]candidate, count int, overflow *bool) (int, bool) {
	shard, home := s.shardOf(indexHash(key))
	if !shard.mu.TryRLock() {
		return count, false
	}
	end := p + uintptr(n)
	for step := 0; step < IndexBucketProbe; step++ {
		bucket := &shard.buckets[(home+step)&(IndexBucketsPerShard-1)]
		for slot := range bucket {
			entry := &bucket[slot]
			if entry.key != key || p < entry.base || end < p || end > entry.base+uintptr(entry.span) {
				continue
			}
			for i := 0; i < int(entry.n); i++ {
				if count >= len(out) {
					s.drops.fanout.Add(1)
					*overflow = true
					break
				}
				out[count] = candidate{base: entry.base, ref: entry.refs[i]}
				count++
			}
		}
	}
	shard.mu.RUnlock() // +checklocksforce: TryRLock.
	return count, true
}

// probeBoth reads tier S completely (filter and probe), then tier L (plan
// section 5.2.4 step 2). It reports false when a shard lock is contended.
// overflow is true when out had no space for a ref.
func (s *Store) probeBoth(p uintptr, n uint32, out *[maxProbeRefs]candidate) (count int, acquired, overflow bool) {
	acquired = true
	if key := granuleKey(p, false); s.filterHit(key) {
		count, acquired = s.probe(key, p, n, out, count, &overflow)
	}
	runHook(hookReaderTiers, 0)
	if key := granuleKey(p, true); s.filterHit(key) {
		var ok bool
		count, ok = s.probe(key, p, n, out, count, &overflow)
		acquired = acquired && ok
	}
	return count, acquired, overflow
}
