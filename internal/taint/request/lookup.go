// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import "unsafe"

// AttributeString attributes the tainted bytes of s to the sources of the
// owner of a (plan section 4.5). r is reset first. It returns true when at
// least one segment is attributed to a source of the owner with a strong
// match (see [Segment.Strong]); when it returns false, r can still have
// foreign segments (tainted bytes of no source of the owner) and weak
// attributed segments. r has no segment when the analysis is not active, the slot is
// busy, or s has no tainted byte. The caller must call it on the
// goroutine that owns s (the sink goroutine).
func (a Analysis) AttributeString(s string, r *Attribution) bool {
	return a.attribute(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)), r)
}

// AttributeBytes is [Analysis.AttributeString] for a byte slice.
func (a Analysis) AttributeBytes(b []byte, r *Attribution) bool {
	return a.attribute(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)), r)
}

func (a Analysis) attribute(p unsafe.Pointer, n uintptr, r *Attribution) bool {
	strong, _ := a.attributeAccess(p, n, r)
	return strong
}

// attributeAccess is attribute, and also returns the result of the access
// to the slot (accessBusy: a busy drop). The tests use the result to know
// the reason of a miss of one call.
func (a Analysis) attributeAccess(p unsafe.Pointer, n uintptr, r *Attribution) (bool, access) {
	r.Reset()
	if n == 0 || !a.Active() || !bitsAny(p, n) {
		return false, accessGone
	}
	w := newWork()
	return a.manager.attributeOwnerAccess(a.slot, a.generation, a.id, true, p, n, matchAll, &w, r)
}

// attributeOwner attributes the n bytes at p to the owner (s, generation,
// id). own is true for the owning request itself (its sink, or a visit on
// its context): then the access is useOwn (bounded retries), else use (one
// attempt).
func (m *Manager) attributeOwner(s *slot, generation uint32, id uint64, own bool, p unsafe.Pointer, n uintptr, mode int, w *work, r *Attribution) bool {
	strong, _ := m.attributeOwnerAccess(s, generation, id, own, p, n, mode, w, r)
	return strong
}

// attributeOwnerAccess is attributeOwner, and also returns the result of the
// access to the slot.
func (m *Manager) attributeOwnerAccess(s *slot, generation uint32, id uint64, own bool, p unsafe.Pointer, n uintptr, mode int, w *work, r *Attribution) (bool, access) {
	r.Reset()
	f := func(d *ownerData) {
		r.Owner = Owner{ID: id, Generation: uint64(generation), Index: s.index}
		d.attribute(p, n, mode, rangeLimit(), w, r)
	}
	var result access
	if own {
		result = m.useOwnAccess(s, generation, id, f)
	} else {
		result = m.tryUse(s, generation, id, f)
	}
	return r.strong, result
}

// AttributeStringAny attributes s for an ownerless sink (plan section
// 4.5.3): first for prefer (when it is a live owner, for example the owner
// of the span annotation), then for the first owner whose address locators
// match, then for the first owner with a content match. All owners share
// one work budget. prefer is the request of the context of the sink: its
// access has the bounded retries of an own access; the scan of the other
// owners has one attempt for each owner.
func (m *Manager) AttributeStringAny(s string, prefer Owner, r *Attribution) bool {
	return m.attributeAny(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)), prefer, r)
}

// AttributeBytesAny is [Manager.AttributeStringAny] for a byte slice.
func (m *Manager) AttributeBytesAny(b []byte, prefer Owner, r *Attribution) bool {
	return m.attributeAny(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)), prefer, r)
}

func (m *Manager) attributeAny(p unsafe.Pointer, n uintptr, prefer Owner, r *Attribution) bool {
	r.Reset()
	if n == 0 || !m.Active() || !bitsAny(p, n) {
		return false
	}
	w := newWork()
	// preferred is the ID of the owner that was tried first (0: none). The
	// scan skips this owner, not its slot index: when prefer is stale, its
	// slot can have a new owner.
	var preferred uint64
	if prefer.ID != 0 && int(prefer.Index) < MaxAnalyses && prefer.Generation <= uint64(^uint32(0)) {
		preferred = prefer.ID
		if m.attributeOwner(&m.slots[prefer.Index], uint32(prefer.Generation), prefer.ID, true, p, n, matchAll, &w, r) {
			return true
		}
	}
	for _, mode := range [...]int{matchAddress, matchAll} {
		found := false
		m.forEachActive(func(s *slot, generation uint32, id uint64) bool {
			if id == preferred {
				return true
			}
			found = m.attributeOwner(s, generation, id, false, p, n, mode, &w, r)
			return !found && w.checks > 0
		})
		if found {
			return true
		}
	}
	r.Reset()
	return false
}

// IsTaintedString reports whether s has at least one byte that the
// attribution gives to a source of an active owner with a strong match (plan
// section 4.8, and [Segment.Strong]). The
// cheap check of the bits comes first. It returns false after the owner
// finished, and when the slots are busy.
func IsTaintedString(s string) bool {
	return isTainted(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)))
}

// IsTaintedBytes is [IsTaintedString] for a byte slice.
func IsTaintedBytes(b []byte) bool {
	return isTainted(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)))
}

func isTainted(p unsafe.Pointer, n uintptr) bool {
	if n == 0 || !bitsAny(p, n) {
		return false
	}
	m := processManager.Load()
	if !m.Active() {
		return false
	}
	return m.isTaintedHit(p, n)
}

//go:noinline
func (m *Manager) isTaintedHit(p unsafe.Pointer, n uintptr) bool {
	var r Attribution
	return m.attributeAny(p, n, Owner{}, &r)
}

// ResolvedRange is one attributed segment with its source. The strings of
// the source are owner copies.
type ResolvedRange struct {
	Start  uint32
	Length uint32
	Source Source
	ID     SourceID
}

// VisitStringOwner visits the attributed segments of s for owner (foreign
// segments are not visited). It visits nothing when no segment is strong
// (see [Segment.Strong]); else it visits also the weak segments. The visit runs after the slot lock is
// released. It returns true when it delivered at least one range, also when
// visit stopped early.
func VisitStringOwner(s string, owner Owner, visit func(ResolvedRange) bool) bool {
	return visitOwner(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)), owner, visit)
}

// VisitBytesOwner is [VisitStringOwner] for a byte slice.
func VisitBytesOwner(b []byte, owner Owner, visit func(ResolvedRange) bool) bool {
	return visitOwner(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)), owner, visit)
}

func visitOwner(p unsafe.Pointer, n uintptr, owner Owner, visit func(ResolvedRange) bool) bool {
	if visit == nil || n == 0 || !bitsAny(p, n) {
		return false
	}
	return visitOwnerHit(p, n, owner, visit)
}

//go:noinline
func visitOwnerHit(p unsafe.Pointer, n uintptr, owner Owner, visit func(ResolvedRange) bool) bool {
	analysis, ok := processManager.Load().Analysis(owner)
	if !ok {
		return false
	}
	var r Attribution
	if !analysis.attribute(p, n, &r) {
		return false
	}
	for i := 0; i < r.N; i++ {
		source, ok := r.Source(i)
		if !ok {
			continue
		}
		id, _ := r.SourceID(i)
		if !visit(ResolvedRange{Start: r.Segments[i].Start, Length: r.Segments[i].Length, Source: source, ID: id}) {
			break
		}
	}
	return true
}
