// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

const (
	// OwnerBudget is the byte budget of one owner for all its copies: source
	// names and values, the body copy and the derived copies. With
	// MaxAnalyses owners, the copies use at most 16 MiB.
	OwnerBudget = 256 << 10
	// MaxNameBytes is the largest source name. A longer name drops the
	// source.
	MaxNameBytes = 256
	// MinValueBytes and MaxValueBytes bound the length of a source value
	// (the admission rule). A shorter or longer value is not tainted.
	MinValueBytes = 2
	MaxValueBytes = 64 << 10
	// MaxDerived is the number of derived entries of one owner.
	MaxDerived = 64
	// MaxDerivedSegments is the number of segments of one derived entry.
	MaxDerivedSegments = 16
	// MaxBodyChunks is the number of body chunk locators of one owner.
	MaxBodyChunks = 8
	// MaxBodyCopy is the size of the owner copy of the first body bytes.
	MaxBodyCopy = 64 << 10

	// minBodyCopyCap is the first capacity of the body copy.
	minBodyCopyCap = 512
)

// locator is the address range of a value of the application. It holds no
// reference: it only helps to find a candidate. The bytes are always checked
// against the owner copy.
type locator struct {
	addr, n uintptr
}

func (l locator) contains(addr uintptr) bool {
	return l.n != 0 && addr >= l.addr && addr-l.addr < l.n
}

// segment is one part of a derived value, with its source.
type segment struct {
	start, length uint32
	source        SourceID
}

// derivedEntry describes one output value that a "changed bytes"
// propagation made (plan section 4.3).
type derivedEntry struct {
	loc   locator
	data  string // owner copy of the output bytes
	order uint32
	nseg  uint8
	segs  [MaxDerivedSegments]segment // sorted by start, no overlap
}

// bodyChunk is the address range of the bytes that one body Read wrote, and
// their offset in the body.
type bodyChunk struct {
	loc    locator
	offset uint64
	order  uint32
}

type bodyData struct {
	// copy is the owner copy of the first body bytes (at most MaxBodyCopy).
	// Bytes in copy[:len(copy)] never change: a growth makes a new array.
	copy []byte
	// stopped is true when a gap (a dropped Read) or the budget stopped the
	// copy. Then the copy is not extended.
	stopped bool
	chunks  [MaxBodyChunks]bodyChunk
	// nextChunk is the next chunk to replace (a ring of the latest chunks).
	nextChunk int
}

// ownerData holds the mutable data of one owner. The slot mutex protects
// it.
type ownerData struct {
	budget int
	// order is the registration counter, for the tie rule ("the last
	// registered candidate").
	order uint32

	table    Table
	locs     [MaxSources]locator
	srcOrder [MaxSources]uint32

	derived  [MaxDerived]derivedEntry
	nderived int

	body bodyData
}

func (d *ownerData) start() {
	d.budget = OwnerBudget
	d.order = 0
	d.table.Reset()
}

// clear releases all the copies (the bytes that the owner retains).
func (d *ownerData) clear() {
	d.budget = 0
	d.order = 0
	d.table.Reset()
	clear(d.locs[:])
	clear(d.srcOrder[:])
	clear(d.derived[:d.nderived])
	d.nderived = 0
	d.body = bodyData{}
}

// charge takes n bytes of the budget. It returns false (and takes nothing)
// when the budget is too small.
func (d *ownerData) charge(n int) bool {
	if n < 0 || n > d.budget {
		return false
	}
	d.budget -= n
	return true
}

func (d *ownerData) nextOrder() uint32 {
	d.order++
	return d.order
}

// source returns the record of id.
func (d *ownerData) source(id SourceID) (Source, bool) {
	if id == BodySourceID {
		if len(d.body.copy) == 0 {
			return Source{}, false
		}
		return Source{
			Origin: constants.OriginHttpRequestBody,
			Value:  unsafe.String(unsafe.SliceData(d.body.copy), len(d.body.copy)),
			Kind:   SourceBody,
		}, true
	}
	return d.table.Get(id)
}

// addDerived adds a derived entry for the outLen bytes at out, with segs.
// It drops the entry when the table is full or the budget is used. It does
// not add a second entry for the same output with the same bytes: it
// replaces the segments and the registration order of the existing entry
// (the latest derivation gives the provenance of the bytes).
func (d *ownerData) addDerived(out unsafe.Pointer, outLen uintptr, segs []segment) bool {
	if len(segs) == 0 || outLen == 0 || outLen > MaxValueBytes {
		return false
	}
	bytes := unsafe.Slice((*byte)(out), outLen)
	loc := locator{addr: uintptr(out), n: outLen}
	for i := 0; i < d.nderived; i++ {
		e := &d.derived[i]
		if e.loc == loc && e.data == unsafe.String(unsafe.SliceData(bytes), len(bytes)) {
			e.order = d.nextOrder()
			e.nseg = uint8(copy(e.segs[:], segs))
			return true
		}
	}
	if d.nderived >= MaxDerived || !d.charge(int(outLen)) {
		return false
	}
	e := &d.derived[d.nderived]
	d.nderived++
	e.loc = loc
	e.data = ownerCopy(bytes)
	e.order = d.nextOrder()
	e.nseg = uint8(copy(e.segs[:], segs))
	return true
}

// recordBody records a body Read of n bytes at p, at offset of the body.
// located is true when the bytes have taint bits (they are heap memory):
// only then is the chunk locator kept.
func (d *ownerData) recordBody(p unsafe.Pointer, n uintptr, offset uint64, located bool) {
	b := &d.body
	if !b.stopped && offset == uint64(len(b.copy)) && len(b.copy) < MaxBodyCopy {
		take := min(int(n), MaxBodyCopy-len(b.copy))
		if len(b.copy)+take > cap(b.copy) {
			newCap := max(2*cap(b.copy), minBodyCopyCap, len(b.copy)+take)
			newCap = min(newCap, MaxBodyCopy)
			if d.charge(newCap - cap(b.copy)) {
				b.copy = cloneBytes(b.copy, newCap)
			} else {
				b.stopped = true
			}
		}
		if !b.stopped {
			// copy, not append: the appended part is a memmove with no bits.
			start := len(b.copy)
			b.copy = b.copy[:start+take]
			copy(b.copy[start:], unsafe.Slice((*byte)(p), take))
		}
	} else if offset != uint64(len(b.copy)) {
		// A Read was dropped (or a concurrent Read is not recorded yet): the
		// copy stops, so that copy offsets stay equal to body offsets.
		b.stopped = true
	}
	if located && offset < uint64(len(b.copy)) {
		b.chunks[b.nextChunk] = bodyChunk{loc: locator{addr: uintptr(p), n: n}, offset: offset, order: d.nextOrder()}
		b.nextChunk = (b.nextChunk + 1) % MaxBodyChunks
	}
}
