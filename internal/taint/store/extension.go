// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import "github.com/DataDog/dd-iast-go/internal/taint/ranges"

// extension is the state of one extension. The deferred finish method uses it
// to undo the work of an extension that did not commit, also when a panic
// stops the extension.
type extension struct {
	// record and store are the internal records of the owner. The extension
	// does not keep the *Owner handle, so the caller's handle does not escape.
	record    *owner
	store     *Store
	base      uintptr
	ref       ownerRef
	charge    int64
	charged   bool // the charge is reserved
	counted   bool // the filter counts the added refs
	locked    bool // this goroutine holds rootsMu
	committed bool
	// tierMove is true when the committed extension moved the root from
	// tier S to tier L, so finish must remove the tier S refs (E5).
	tierMove  bool
	oldSpan   uint32
	failure   insertResult // counter to record; insertOK records nothing
	added     granuleKeys
	positions [maxRootKeys]indexPos
}

// finish runs when extendRoot returns or panics. It releases rootsMu if it is
// held. For a committed move from tier S to tier L, it runs E5: it removes the
// tier S refs last, so a reader that reads tier S before tier L never misses
// the root. For an extension that did not commit, it runs E3: it removes the
// added refs and their filter counts and releases the charge. Then it clears
// owner.extending.
func (e *extension) finish() {
	record := e.record
	if e.locked {
		record.rootsMu.Unlock() // +checklocksforce: TryLock.
		e.locked = false
	}
	if e.committed && e.tierMove {
		s := e.store
		if keys, ok := rootKeys(e.base, e.oldSpan, false); ok {
			for i := 0; i < keys.n; i++ {
				if s.removeRef(keys.keys[i], e.base, e.ref) {
					s.filterAdd(keys.keys[i], -1)
				}
			}
		}
	}
	if !e.committed {
		s := e.store
		for i := 0; i < e.added.n; i++ {
			if e.counted {
				s.filterAdd(e.added.keys[i], -1)
			}
			removeRefAt(e.positions[i], e.added.keys[i], e.base, e.ref)
		}
		if e.charged {
			record.charged.Add(-e.charge)
			s.charged.Add(-e.charge)
		}
		if e.failure != insertOK {
			recordInsertFailure(&record.drops, e.failure)
		}
	}
	endExtension(record)
}

// extendRoot adds a new adoption of the same allocation by the same owner to
// the existing root rootID (plan section 5.2.2, "Extension", steps E1 to E5).
// One owner has at most one root for one allocation. After the extension, the
// root covers every value of the earlier adoptions and of the new adoption, and
// its ranges are the union of both range sets (the new ranges win on the bytes
// that both sets describe). The extension never writes the root generation or
// setGen: a mutation claim at any time makes all ranges of the root invalid.
// The caller holds beginWrite, so Finish cannot run at the same time.
func (o *Owner) extendRoot(rootID uint16, base uintptr, span uint32, charge int64, stringAnchor string, bytesAnchor []byte, set *ranges.Set) (RootRef, bool) {
	s := o.store
	record := o.owner
	if rootID >= MaxRootsPerOwner {
		record.drops.contention.Add(1)
		return RootRef{}, false
	}
	root := &record.roots[rootID]

	// E1: claim the extension right of this owner.
	if runHook(hookExtendBegin, 0) || !record.rootsMu.TryLock() {
		record.drops.contention.Add(1)
		return RootRef{}, false
	}
	if !root.indexed || root.base != base || record.extending {
		record.rootsMu.Unlock() // +checklocksforce: TryLock.
		record.drops.contention.Add(1)
		return RootRef{}, false
	}
	record.extending = true
	old := root.span
	e := &extension{
		record:  record,
		store:   s,
		base:    base,
		ref:     ownerRef{ownerGen: uint32(o.gen), rootID: rootID, ownerIdx: o.index, kind: root.kind},
		charge:  charge,
		failure: insertContention,
	}
	record.rootsMu.Unlock() // +checklocksforce: TryLock.
	// From here, e.finish always clears owner.extending, also after a panic.
	defer e.finish()
	if charge <= 0 || charge > MaxRootChargeBytes || !reserveInt64(&record.charged, charge, RequestRootBytes) {
		record.drops.bytes.Add(1)
		e.failure = insertOK
		return RootRef{}, false
	}
	if !reserveInt64(&s.charged, charge, ProcessRootBytes) {
		record.charged.Add(-charge)
		record.drops.bytes.Add(1)
		e.failure = insertOK
		return RootRef{}, false
	}
	e.charged = true

	// E2: add the refs of the new granule keys.
	union := max(old, span)
	if union != old {
		keys, ok := rootKeys(base, union, largeSpan(union))
		oldKeys, oldOK := rootKeys(base, old, largeSpan(old))
		if !ok || !oldOK {
			e.failure = insertFull
			return RootRef{}, false
		}
		sameTier := largeSpan(union) == largeSpan(old)
		for i := 0; i < keys.n; i++ {
			key := keys.keys[i]
			if sameTier && oldKeys.contains(key) {
				if !s.widenEntry(key, base, union) {
					return RootRef{}, false
				}
				continue
			}
			result := insertFull
			var pos indexPos
			if !runHook(hookExtendInsert, e.added.n) {
				pos, result = s.insertRef(key, base, union, e.ref)
			}
			if result != insertOK {
				e.failure = result
				return RootRef{}, false
			}
			e.added.keys[e.added.n] = key
			e.positions[e.added.n] = pos
			e.added.n++
		}
	}

	// E4: count the new refs, then commit under rootsMu.
	for i := 0; i < e.added.n; i++ {
		s.filterAdd(e.added.keys[i], 1)
	}
	e.counted = true
	if runHook(hookExtendCommit, 0) || !record.rootsMu.TryLock() {
		return RootRef{}, false
	}
	e.locked = true
	if runHook(hookExtendValid, 0) || !root.indexed || root.setGen != root.generation.Load() {
		return RootRef{}, false
	}
	runHook(hookExtendPreCommit, 0)
	var merged ranges.Set
	outcome := o.unionLocked(root, set, union, &merged)
	if !outcome.Valid {
		record.drops.ranges.Add(1)
		e.failure = insertOK
		return RootRef{}, false
	}
	oldOverflow := root.overflow
	truncated := o.storeRangesLocked(root, &merged) || outcome.Truncated
	root.span = union
	if len(stringAnchor) > len(root.stringAnchor) {
		root.stringAnchor = stringAnchor
	}
	if cap(bytesAnchor) > cap(root.bytesAnchor) {
		root.bytesAnchor = bytesAnchor
	}
	generation := root.generation.Load()
	e.committed = true
	e.tierMove = !largeSpan(old) && largeSpan(union)
	e.oldSpan = old
	e.locked = false
	record.rootsMu.Unlock() // +checklocksforce: TryLock.
	s.freeOverflow(oldOverflow)
	if truncated {
		record.drops.ranges.Add(1)
	}

	// E5 runs in e.finish, after this hook.
	if e.tierMove {
		runHook(hookExtendCleanup, 0)
	}
	return RootRef{ID: rootID, Generation: generation}, true
}

// unionLocked computes the union of the new ranges and the stored ranges of
// root (plan section 5.2.2, "Union rule"). The new ranges come first, so they
// win on the bytes that both sets describe. The caller holds rootsMu.
func (o *Owner) unionLocked(root *rootRecord, set *ranges.Set, span uint32, dst *ranges.Set) ranges.Outcome {
	var all [2 * MaxRanges]ranges.Range
	count := set.CopyTo(all[:MaxRanges])
	var stored [MaxRanges]ranges.Range
	storedCount := o.store.rootRangesLocked(root, &stored)
	count += copy(all[count:], stored[:storedCount])
	limit := max(root.limit, set.Limit())
	return ranges.Canonicalize(dst, limit, all[:count], span)
}

func endExtension(record *owner) {
	record.rootsMu.Lock()
	record.extending = false
	record.rootsMu.Unlock()
}
