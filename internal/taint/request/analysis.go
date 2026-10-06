// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"runtime"
	"unsafe"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

// admitted reports whether a source value of n bytes and a name of
// nameLen bytes can be tainted (the admission rule).
func admitted(nameLen, n int) bool {
	return n >= MinValueBytes && n <= MaxValueBytes && nameLen <= MaxNameBytes
}

// TaintString registers a string source and sets the taint bits of value
// in place (plan section 4.2). When the bits cannot be set on value
// (read-only data, stack memory), it sets them on a heap clone and returns
// the clone. It returns value and false when the analysis is not active, the
// value is not admitted (see [MinValueBytes], [MaxValueBytes],
// [MaxNameBytes]), the origin is not valid, the source table is full, the
// budget is used, the slot is busy, or no bit can be set.
//
// An exact duplicate (origin, name, value) uses the existing record; the
// bits are set on the new value, and the locator of the record moves to it.
func (a Analysis) TaintString(origin constants.Origin, name, value string) (string, bool) {
	p, ok := a.taint(origin, name, stringBytes(value), SourceString, true)
	if !ok {
		return value, false
	}
	return unsafe.String(unsafe.SliceData(p), len(p)), true
}

// TaintStringInPlace is [Analysis.TaintString] for a hook that cannot
// replace the value: it never clones. When the bits cannot be set on value,
// it registers nothing and returns false.
func (a Analysis) TaintStringInPlace(origin constants.Origin, name, value string) bool {
	_, ok := a.taint(origin, name, stringBytes(value), SourceString, false)
	return ok
}

// TaintBytes registers a byte-slice source and sets the taint bits of value
// in place. The source value is a copy: it does not change when the
// application changes value. When the bits cannot be set on value, it sets
// them on a heap clone with the same length and capacity and returns the
// clone; when the capacity is larger than [MaxValueBytes], it does not clone
// and drops the taint. The other drop conditions are the same as for
// [Analysis.TaintString].
func (a Analysis) TaintBytes(origin constants.Origin, name string, value []byte) ([]byte, bool) {
	p, ok := a.taint(origin, name, value, SourceBytes, true)
	if !ok {
		return value, false
	}
	return p, true
}

// TaintBytesInPlace is [Analysis.TaintBytes] that never clones.
func (a Analysis) TaintBytesInPlace(origin constants.Origin, name string, value []byte) bool {
	_, ok := a.taint(origin, name, value, SourceBytes, false)
	return ok
}

func (a Analysis) taint(origin constants.Origin, name string, value []byte, kind SourceKind, mayClone bool) ([]byte, bool) {
	if !a.Active() || !admitted(len(name), len(value)) || !validOrigin(origin) {
		return value, false
	}
	result := value
	done := false
	a.manager.use(a.slot, a.generation, a.id, func(d *ownerData) {
		result, done = d.taint(origin, name, value, kind, mayClone)
	})
	if !done {
		return value, false
	}
	return result, true
}

// taint is the work of Analysis.taint, with the slot lock.
func (d *ownerData) taint(origin constants.Origin, name string, value []byte, kind SourceKind, mayClone bool) ([]byte, bool) {
	var (
		res   AddResult
		token addToken
	)
	if kind == SourceString {
		res, token = d.table.prepareString(origin, name, unsafe.String(unsafe.SliceData(value), len(value)))
	} else {
		res, token = d.table.prepareBytes(origin, name, value)
	}
	switch res.Status {
	case AddAdded:
		if !d.charge(len(name) + len(value)) {
			return value, false
		}
	case AddDuplicate:
	default:
		return value, false
	}
	tainted, ok := setOrClone(value, mayClone)
	if !ok {
		if res.Status == AddAdded {
			d.budget += len(name) + len(value)
		}
		return value, false
	}
	if res.Status == AddAdded {
		d.table.commit(token, Source{
			Origin: origin,
			Name:   ownerCopy(stringBytes(name)),
			Value:  ownerCopy(value),
			Kind:   kind,
		})
	}
	d.locs[res.ID] = locator{addr: uintptr(unsafe.Pointer(unsafe.SliceData(tainted))), n: uintptr(len(tainted))}
	d.srcOrder[res.ID] = d.nextOrder()
	return tainted, true
}

// setOrClone sets the bits of value, or of a heap clone of value when
// mayClone is true (same length and capacity, at most MaxValueBytes).
func setOrClone(value []byte, mayClone bool) ([]byte, bool) {
	if bitsSet(unsafe.Pointer(unsafe.SliceData(value)), uintptr(len(value))) {
		return value, true
	}
	// The clone has the capacity of value (the contract of TaintBytes).
	// Admission bounds len(value), not cap(value): a clone with a larger
	// capacity than MaxValueBytes can be a very large allocation, thus the
	// taint is dropped.
	if !mayClone || cap(value) > MaxValueBytes {
		return value, false
	}
	clone := cloneBytes(value, cap(value))
	if !bitsSet(unsafe.Pointer(unsafe.SliceData(clone)), uintptr(len(clone))) {
		return value, false
	}
	return clone, true
}

// IsSource reports whether value is exactly (same address and length, same
// bytes) a registered source value of the owner of a. A lazy source hook uses
// it to skip a source that is already registered.
func (a Analysis) IsSource(value string) bool {
	if len(value) == 0 || !a.Active() {
		return false
	}
	loc := locator{addr: uintptr(unsafe.Pointer(unsafe.StringData(value))), n: uintptr(len(value))}
	found := false
	a.manager.use(a.slot, a.generation, a.id, func(d *ownerData) {
		for i := 0; i < d.table.count; i++ {
			if d.locs[i] == loc && d.table.sources[i].Value == value {
				found = true
				return
			}
		}
	})
	return found
}

// Source returns the source record of id while the analysis is active. Its
// strings are owner copies.
func (a Analysis) Source(id SourceID) (Source, bool) {
	if !a.Active() {
		return Source{}, false
	}
	var (
		source Source
		ok     bool
	)
	a.manager.use(a.slot, a.generation, a.id, func(d *ownerData) {
		source, ok = d.source(id)
	})
	return source, ok
}

// SourceCount returns the current bounded source count.
func (a Analysis) SourceCount() int {
	if !a.Active() {
		return 0
	}
	count := 0
	a.manager.use(a.slot, a.generation, a.id, func(d *ownerData) {
		count = d.table.Len()
	})
	return count
}

// Budget returns the unused byte budget of the owner (tests and telemetry).
func (a Analysis) Budget() int {
	budget := 0
	a.manager.use(a.slot, a.generation, a.id, func(d *ownerData) {
		budget = d.budget
	})
	return budget
}

// RegisterBody makes object the request body of the owner: the Read hooks
// then taint the bytes that a Read of object writes, and the owner keeps a
// copy of the first body bytes. object must be the data pointer of a heap
// object (for example the dynamic value of http.Request.Body). The reference
// is weak: it does not retain the body, and it cannot match a new object at
// a reused address.
//
// The store occurs while the slot is pinned for this owner: the cleanup
// cannot run before the store (it clears the body after it), and a stale
// handle cannot replace the body of a new owner of the slot.
func (a Analysis) RegisterBody(object unsafe.Pointer) bool {
	if object == nil || !a.Active() {
		return false
	}
	for attempt := 1; ; attempt++ {
		result := a.manager.pinOwner(a.slot, a.generation, a.id)
		if result == accessGone {
			return false
		}
		if result == accessDone {
			break
		}
		if attempt >= ownAttempts {
			ownBusyDrops.Add(1)
			return false
		}
		runtime.Gosched()
	}
	defer a.manager.unpin(a.slot)
	if hook := testHookRegisterBody; hook != nil {
		hook()
	}
	a.slot.body.Store(&bodyRef{owner: a.id, object: weak.Make((*byte)(object))})
	return true
}

// testHookRegisterBody is nil, except in the unit tests: RegisterBody calls
// it while the slot is pinned, before the store.
var testHookRegisterBody func()
