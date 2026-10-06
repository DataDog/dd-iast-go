// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"bytes"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
)

const (
	// CheckBudget is the number of candidate checks for one attribution
	// call (one sink value, or one propagation callback), for all owners.
	CheckBudget = 4096
	// CompareBudget is the number of bytes that one attribution call can
	// compare or scan. It bounds the work of the content match on large
	// copies (a check can compare up to 64 KiB).
	CompareBudget = 1 << 20

	// MaxAttributed is the hard bound of attributed segments for one value
	// (DD_IAST_MAX_RANGE_COUNT is clamped to it).
	MaxAttributed = config.MaxRangeCountLimit
	// maxSegments bounds all segments: foreign segments are always between
	// attributed segments (adjacent foreign segments are merged).
	maxSegments = 2*MaxAttributed + 1
)

// Segment is one part of the tainted bytes of a value.
type Segment struct {
	Start, Length uint32
	// Foreign is true when the bytes are not attributed to a source of the
	// owner: bytes of a different request, stale bits, or bytes after a
	// bound. A report must show them redacted, never as clean evidence.
	Foreign bool
	// source is the index in Attribution.sources (when Foreign is false).
	source uint8
}

// Attribution is the result of the attribution of one value to the sources
// of one owner. The segments are sorted by Start and do not overlap; bytes
// that are in no segment are not tainted. The zero value is ready to use;
// a large value: keep it on the stack of the caller, or reuse it.
type Attribution struct {
	Owner      Owner
	Segments   [maxSegments]Segment
	N          int
	Attributed int

	nsources int
	sources  [MaxAttributed]Source
	ids      [MaxAttributed]SourceID
	// stopped is true when a bound stopped the attribution.
	stopped bool
}

// Reset makes r empty.
func (r *Attribution) Reset() {
	r.Owner = Owner{}
	r.N = 0
	r.Attributed = 0
	clear(r.sources[:r.nsources])
	r.nsources = 0
	r.stopped = false
}

// Source returns the source of the segment i (false for a foreign segment).
// The strings of the source are owner copies: they never change.
func (r *Attribution) Source(i int) (Source, bool) {
	if i < 0 || i >= r.N || r.Segments[i].Foreign {
		return Source{}, false
	}
	return r.sources[r.Segments[i].source], true
}

// SourceID returns the request-local ID of the source of segment i.
func (r *Attribution) SourceID(i int) (SourceID, bool) {
	if i < 0 || i >= r.N || r.Segments[i].Foreign {
		return 0, false
	}
	return r.ids[r.Segments[i].source], true
}

// Stopped reports whether a bound (the range count, or the work budget)
// stopped the attribution. Then all the remaining tainted bytes are foreign.
func (r *Attribution) Stopped() bool { return r.stopped }

func (r *Attribution) addForeign(start, end int) {
	if end <= start {
		return
	}
	if r.N > 0 {
		last := &r.Segments[r.N-1]
		if last.Foreign && int(last.Start+last.Length) == start {
			last.Length = uint32(end) - last.Start
			return
		}
	}
	if r.N >= len(r.Segments) {
		// Cannot happen (see maxSegments); stay safe: extend the last
		// segment as foreign.
		last := &r.Segments[r.N-1]
		last.Foreign = true
		last.Length = uint32(end) - last.Start
		return
	}
	r.Segments[r.N] = Segment{Start: uint32(start), Length: uint32(end - start), Foreign: true}
	r.N++
}

// addAttributed adds an attributed segment. It returns false when the range
// count limit does not permit it (then nothing changed).
func (r *Attribution) addAttributed(start, end int, id SourceID, limit int, d *ownerData) bool {
	if end <= start {
		return true
	}
	if r.N > 0 {
		last := &r.Segments[r.N-1]
		if !last.Foreign && int(last.Start+last.Length) == start && r.ids[last.source] == id {
			last.Length = uint32(end) - last.Start
			return true
		}
	}
	if r.Attributed >= limit || r.N >= len(r.Segments) {
		return false
	}
	index := -1
	for i := 0; i < r.nsources; i++ {
		if r.ids[i] == id {
			index = i
			break
		}
	}
	if index < 0 {
		source, ok := d.source(id)
		if !ok || r.nsources >= len(r.sources) {
			r.addForeign(start, end)
			return true
		}
		index = r.nsources
		r.ids[index] = id
		r.sources[index] = source
		r.nsources++
	}
	r.Segments[r.N] = Segment{Start: uint32(start), Length: uint32(end - start), source: uint8(index)}
	r.N++
	r.Attributed++
	return true
}

// work is the shared work budget of one attribution call.
type work struct {
	checks int
	bytes  int
}

func newWork() work { return work{checks: CheckBudget, bytes: CompareBudget} }

func (w *work) check() bool {
	if w.checks <= 0 {
		return false
	}
	w.checks--
	return true
}

func (w *work) take(n int) bool {
	if w.bytes < n {
		w.bytes = 0
		return false
	}
	w.bytes -= n
	return true
}

// rangeLimit returns the configured bound of attributed segments.
func rangeLimit() int {
	limit := config.MaxRangeCount
	if limit < 1 {
		return 1
	}
	if limit > MaxAttributed {
		return MaxAttributed
	}
	return int(limit)
}

// Candidate kinds, in the order of the content match.
const (
	kindDerived = iota
	kindSource
	kindBody
)

// candidate is one match of a candidate at a position of the value.
type candidate struct {
	kind    int
	index   int    // source ID, or derived entry index
	offset  int    // offset in the candidate copy
	length  int    // length of the match
	size    int    // length of the candidate copy
	order   uint32 // registration order
	address bool   // found by its address locator
}

// better applies the tie rule: the address match wins; then the longest
// match; then the shortest candidate; then the last registered candidate.
func (c candidate) better(o candidate) bool {
	if c.address != o.address {
		return c.address
	}
	if c.length != o.length {
		return c.length > o.length
	}
	if c.size != o.size {
		return c.size < o.size
	}
	return c.order > o.order
}

// lcp returns the length of the longest common prefix of a and b. It
// returns -1 when the compare budget is used.
func lcp(a, b []byte, w *work) int {
	n := min(len(a), len(b))
	if !w.take(n) {
		return -1
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// attribution modes.
const (
	// matchAll: address locate, then content match.
	matchAll = iota
	// matchAddress: only the address locate (first pass of an owner search).
	matchAddress
)

// attribute cuts the tainted runs of the n bytes at p into segments of the
// owner d (plan section 4.5), and adds them to r. The caller holds the slot
// lock of d, and the memory at p is live.
func (d *ownerData) attribute(p unsafe.Pointer, n uintptr, mode int, limit int, w *work, r *Attribution) {
	if n == 0 {
		return
	}
	value := unsafe.Slice((*byte)(p), n)
	base := uintptr(p)
	var present byteSet
	for off := bitsNext(p, n, 0); off < n; {
		end := bitsNextClean(p, n, off)
		if end <= off || end > n {
			end = n
		}
		pos := int(off)
		for pos < int(end) && !r.stopped {
			consumed, stop := d.matchAt(value, base, pos, int(end), mode, limit, w, &present, r)
			if stop {
				r.stopped = true
			}
			if consumed == 0 && !stop {
				r.addForeign(pos, pos+1)
				consumed = 1
			}
			pos += consumed
		}
		if r.stopped && pos < int(end) {
			r.addForeign(pos, int(end))
		}
		off = bitsNext(p, n, end)
	}
}

// matchAt finds the best candidate for the bytes value[pos:end], and adds
// its segments to r. It returns the number of bytes that it attributed (0:
// no match), and stop when a bound stopped the work.
func (d *ownerData) matchAt(value []byte, base uintptr, pos, end, mode, limit int, w *work, present *byteSet, r *Attribution) (int, bool) {
	if r.Attributed >= limit {
		return 0, true
	}
	rest := value[pos:end]
	addr := base + uintptr(pos)
	best := candidate{}
	found := false
	consider := func(c candidate) {
		if c.length > 0 && (!found || c.better(best)) {
			best, found = c, true
		}
	}

	// 1. Locate by address, then check the bytes against the owner copy.
	for i := 0; i < d.nderived; i++ {
		e := &d.derived[i]
		if !e.loc.contains(addr) {
			continue
		}
		if !w.check() {
			return 0, true
		}
		offset := int(addr - e.loc.addr)
		if offset >= len(e.data) {
			continue
		}
		k := lcp(rest, stringBytes(e.data[offset:]), w)
		if k < 0 {
			return 0, true
		}
		consider(candidate{kind: kindDerived, index: i, offset: offset, length: k, size: len(e.data), order: e.order, address: true})
	}
	for i := 0; i < d.table.count; i++ {
		if !d.locs[i].contains(addr) {
			continue
		}
		if !w.check() {
			return 0, true
		}
		value := d.table.sources[i].Value
		offset := int(addr - d.locs[i].addr)
		if offset >= len(value) {
			continue
		}
		k := lcp(rest, stringBytes(value[offset:]), w)
		if k < 0 {
			return 0, true
		}
		consider(candidate{kind: kindSource, index: i, offset: offset, length: k, size: len(value), order: d.srcOrder[i], address: true})
	}
	for i := range d.body.chunks {
		c := &d.body.chunks[i]
		if !c.loc.contains(addr) {
			continue
		}
		if !w.check() {
			return 0, true
		}
		inChunk := int(addr - c.loc.addr)
		offset := c.offset + uint64(inChunk)
		if offset >= uint64(len(d.body.copy)) {
			continue
		}
		window := rest[:min(len(rest), int(c.loc.n)-inChunk)]
		k := lcp(window, d.body.copy[offset:], w)
		if k < 0 {
			return 0, true
		}
		consider(candidate{kind: kindBody, offset: int(offset), length: k, size: len(d.body.copy), order: c.order, address: true})
	}

	// 2. Content match: the candidate copy with the longest prefix of rest.
	// A match of 1 byte is valid, so the content match fails only when no
	// copy has the first byte: the set of the bytes of all copies (made one
	// time for each call) finds this case without a scan.
	if !found && mode == matchAll {
		if !present.ready {
			if !d.fillByteSet(present, w) {
				return 0, true
			}
		}
		if !present.has(rest[0]) {
			return 0, false
		}
		for i := d.nderived - 1; i >= 0; i-- {
			e := &d.derived[i]
			offset, k, ok := longestPrefix(stringBytes(e.data), rest, w)
			if !ok {
				return 0, true
			}
			consider(candidate{kind: kindDerived, index: i, offset: offset, length: k, size: len(e.data), order: e.order})
		}
		for i := d.table.count - 1; i >= 0; i-- {
			value := d.table.sources[i].Value
			offset, k, ok := longestPrefix(stringBytes(value), rest, w)
			if !ok {
				return 0, true
			}
			consider(candidate{kind: kindSource, index: i, offset: offset, length: k, size: len(value), order: d.srcOrder[i]})
		}
		if len(d.body.copy) != 0 {
			offset, k, ok := longestPrefix(d.body.copy, rest, w)
			if !ok {
				return 0, true
			}
			consider(candidate{kind: kindBody, offset: offset, length: k, size: len(d.body.copy)})
		}
	}
	if !found {
		return 0, false
	}
	return d.addCandidate(best, pos, limit, r)
}

// addCandidate adds the segments of the match c at pos of the value.
func (d *ownerData) addCandidate(c candidate, pos, limit int, r *Attribution) (int, bool) {
	switch c.kind {
	case kindSource:
		if !r.addAttributed(pos, pos+c.length, SourceID(c.index), limit, d) {
			return 0, true
		}
		return c.length, false
	case kindBody:
		if !r.addAttributed(pos, pos+c.length, BodySourceID, limit, d) {
			return 0, true
		}
		return c.length, false
	}
	// A derived entry: each part of the match gets the source of its
	// segment; the parts in no segment are bytes of a different owner.
	e := &d.derived[c.index]
	from, to := c.offset, c.offset+c.length
	at := from
	for i := 0; i < int(e.nseg) && at < to; i++ {
		s := e.segs[i]
		start, end := int(s.start), int(s.start)+int(s.length)
		if end <= at {
			continue
		}
		if start >= to {
			break
		}
		start = max(start, at)
		end = min(end, to)
		if start > at {
			r.addForeign(pos+at-from, pos+start-from)
		}
		if !r.addAttributed(pos+start-from, pos+end-from, s.source, limit, d) {
			return start - from, true
		}
		at = end
	}
	if at < to {
		r.addForeign(pos+at-from, pos+to-from)
	}
	return c.length, false
}

// longestPrefix returns the offset and length of the longest prefix of rest
// that is in data (the first offset for equal lengths). ok is false when the
// work budget is used.
func longestPrefix(data, rest []byte, w *work) (offset, length int, ok bool) {
	if len(rest) == 0 || len(data) == 0 {
		return 0, 0, true
	}
	first := rest[0]
	for i := 0; i < len(data); {
		j := bytes.IndexByte(data[i:], first)
		if j < 0 {
			if !w.take(len(data) - i) {
				return 0, 0, false
			}
			break
		}
		if !w.take(j + 1) {
			return 0, 0, false
		}
		i += j
		if !w.check() {
			return 0, 0, false
		}
		k := lcp(rest, data[i:], w)
		if k < 0 {
			return 0, 0, false
		}
		if k > length {
			offset, length = i, k
			if k == len(rest) {
				break
			}
		}
		i++
	}
	return offset, length, true
}

// byteSet is the set of the byte values of all the copies of one owner.
type byteSet struct {
	bits  [4]uint64
	ready bool
}

func (s *byteSet) add(data []byte) {
	for _, b := range data {
		s.bits[b>>6] |= 1 << (b & 63)
	}
}

func (s *byteSet) has(b byte) bool {
	return s.bits[b>>6]&(1<<(b&63)) != 0
}

// fillByteSet makes the byte set of the copies of d. It returns false when
// the compare budget is used.
func (d *ownerData) fillByteSet(s *byteSet, w *work) bool {
	s.ready = true
	for i := 0; i < d.nderived; i++ {
		data := stringBytes(d.derived[i].data)
		if !w.take(len(data)) {
			return false
		}
		s.add(data)
	}
	for i := 0; i < d.table.count; i++ {
		data := stringBytes(d.table.sources[i].Value)
		if !w.take(len(data)) {
			return false
		}
		s.add(data)
	}
	if !w.take(len(d.body.copy)) {
		return false
	}
	s.add(d.body.copy)
	return true
}
