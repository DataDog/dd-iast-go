// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import "github.com/DataDog/dd-iast-go/internal/taint/ranges"

// PublishBytesMutation publishes root-relative provenance after an in-place
// byte mutation. value must still start at the managed root base and remain
// within the root span. When cap(value) is smaller than the root span (an
// extended root, see "Lookup and validation" in the package doc), the new
// ranges replace the ranges on [0, cap(value)), and the ranges after cap(value)
// stay only when they were valid just before the claim.
//
// After this method claims the current generation, publication failure leaves
// that generation invalid because the application mutation has already
// occurred. Returning false never restores stale pre-mutation provenance. A
// mutation does not change the index: index refs store the root identity, not
// its generation.
func (o *Owner) PublishBytesMutation(ref RootRef, value []byte, set *ranges.Set) (RootRef, bool) {
	if ref.ID >= MaxRootsPerOwner || !o.beginWrite() {
		return RootRef{}, false
	}
	defer o.endWrite()
	generation, claimed := o.claimMutation(ref)
	if !claimed {
		return RootRef{}, false
	}
	if set == nil || len(value) == 0 || len(value) > MaxRootBytes || cap(value) > MaxRootBytes {
		return RootRef{}, false
	}
	key, ok := BytesKey(value)
	if !ok || !set.ValidFor(uint32(cap(value))) {
		o.owner.drops.ranges.Add(1)
		return RootRef{}, false
	}
	if runHook(hookMutationLock, 0) || !o.owner.rootsMu.TryLock() {
		o.owner.drops.contention.Add(1)
		return RootRef{}, false
	}
	root := &o.owner.roots[ref.ID]
	if root.generation.Load() != generation || root.bytesAnchor == nil || root.base != key.Pointer || uint32(cap(value)) > root.span {
		o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
		return RootRef{}, false
	}
	published := *set
	var dropped bool
	if uint32(cap(value)) < root.span {
		var outcome ranges.Outcome
		outcome, dropped = o.mutationTailLocked(root, ref.Generation, set, uint32(cap(value)), &published)
		if !outcome.Valid {
			o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
			o.owner.drops.ranges.Add(1)
			return RootRef{}, false
		}
		dropped = dropped || outcome.Truncated
	}
	oldOverflow := root.overflow
	truncated := o.storeRangesLocked(root, &published)
	if cap(value) >= cap(root.bytesAnchor) {
		root.bytesAnchor = value
	}
	root.setGen = generation
	o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
	o.store.freeOverflow(oldOverflow)
	if truncated || dropped {
		o.owner.drops.ranges.Add(1)
	}
	return RootRef{ID: ref.ID, Generation: generation}, true
}

// mutationTailLocked builds the ranges of a mutation of an extended root: the
// new ranges on [0, low), then the stored ranges on [low, root.span) when they
// were valid just before the claim (setGen == claimed). It reports whether it
// dropped the stored tail. The caller holds rootsMu.
func (o *Owner) mutationTailLocked(root *rootRecord, claimed uint32, set *ranges.Set, low uint32, dst *ranges.Set) (ranges.Outcome, bool) {
	limit := max(root.limit, set.Limit())
	tailValid := root.setGen == claimed && !runHook(hookMutationTail, 0)
	var all [2 * MaxRanges]ranges.Range
	count := set.CopyTo(all[:MaxRanges])
	dropped := false
	if tailValid {
		var stored [MaxRanges]ranges.Range
		storedCount := o.store.rootRangesLocked(root, &stored)
		var canonical, tail ranges.Set
		if !ranges.AdoptCanonical(&canonical, root.limit, stored[:storedCount], root.span).Valid ||
			!ranges.Clear(&tail, root.limit, &canonical, root.span, 0, low).Valid {
			return ranges.Outcome{}, false
		}
		count += tail.CopyTo(all[count:])
	} else if root.count != 0 {
		dropped = true
	}
	return ranges.Canonicalize(dst, limit, all[:count], root.span), dropped
}

func (o *Owner) claimMutation(ref RootRef) (uint32, bool) {
	if o.Disabled() || ref.ID >= MaxRootsPerOwner || ref.Generation == 0 {
		return 0, false
	}
	next := ref.Generation + 1
	if next == 0 {
		next = 1
	}
	root := &o.owner.roots[ref.ID]
	if !root.generation.CompareAndSwap(ref.Generation, next) {
		return 0, false
	}
	return next, true
}
