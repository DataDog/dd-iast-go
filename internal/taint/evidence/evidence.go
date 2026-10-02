// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package evidence assembles bounded, report-owned taint evidence snapshots.
package evidence

import (
	"cmp"
	"slices"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

const (
	// MaxSnapshotBytes bounds complete cloned source names and values retained by
	// one report snapshot.
	MaxSnapshotBytes = 256 << 10
	// MaxCollectedRanges bounds cross-owner range collection.
	MaxCollectedRanges = store.MaxSnapshotOwners * ranges.HardLimit
	// MaxParts bounds alternating tainted and untainted evidence pieces.
	MaxParts = 2*MaxCollectedRanges + 1
	// MaxSources bounds exact source identities in one report.
	MaxSources = request.MaxSources
	// MaxJoinedValues bounds command argv traversal.
	MaxJoinedValues = 256
	maxOwners       = store.MaxSnapshotOwners
)

// Status is the result of collecting one value.
type Status uint8

const (
	// StatusNone means no complete live provenance was found.
	StatusNone Status = iota
	// StatusCollected means a complete unsafe snapshot was assembled.
	StatusCollected
	// StatusSuppressed means every live range was marked safe for the requested
	// vulnerability type.
	StatusSuppressed
	// StatusDropped means a hard snapshot bound or invalid range dropped the
	// complete report.
	StatusDropped
)

// Source is one exact, report-owned source identity.
type Source struct {
	Origin constants.Origin
	Name   string
	Value  string
}

// OwnerIdentity identifies one generation-validated contributing owner.
type OwnerIdentity = request.Owner

// Part is one consecutive pre-redaction evidence interval. Source is -1 for an
// untainted part and otherwise indexes Snapshot.SourceAt. Marks contains the
// remaining secure marks after the requested vulnerability's mark was excluded.
//
// Foreign is true for a part without a source (Source is -1) that can contain
// bytes of a different owner. A report must show only a redaction marker for
// it, also when redaction is disabled: the bytes are data of a different
// request.
type Part struct {
	Start   uint32
	Length  uint32
	Source  int16
	Marks   uint64
	Foreign bool
}

// Target tells a collection the one owner whose ranges it keeps. A report
// contains the evidence of exactly one owner.
type Target struct {
	// Owner is the request owner of the sink context. It is used only when
	// Known is true.
	Owner OwnerIdentity
	// Known is true when the sink context has a request owner. The
	// collection then keeps only the ranges of Owner.
	Known bool
	// Select selects one owner when Known is false and the value has ranges
	// of more than one owner. owners is sorted and has 1 to 4 owners. Select
	// must not change owners. When Select is nil, returns false, or returns
	// an owner that is not in owners, the first owner is selected.
	Select func(owners []OwnerIdentity) (OwnerIdentity, bool)
}

// Snapshot owns the evidence value and every source string. It contains only
// canonical unsafe intervals.
//
// A snapshot of more than one owner mixes the provenance of different
// requests. Do not report it. Use [Snapshot.ForOwner] to get the snapshot of
// exactly one owner before redaction and report creation.
type Snapshot struct {
	value       string
	sourceBytes uint32
	ranges      []collectedRange
	sources     []Source
	parts       []Part
	owners      []OwnerIdentity
	// mixed is true for a snapshot of a collection of every owner when a
	// different owner has bytes in the value: more than one owner has a
	// range (also a range with secure marks), or the owner of some bytes is
	// not known. Then ForOwner always builds a new snapshot, and admitted,
	// admittedSources, covers, coverOwners, and coverAll are set.
	mixed bool
	// admitted and admittedSources keep every admitted range and source
	// before cross-owner overlap selection, so that ForOwner can build the
	// complete evidence of one owner.
	admitted        []collectedRange
	admittedSources []Source
	// covers are the byte intervals of every range of the collection (also
	// ranges with secure marks), and of the bytes whose owner is not known.
	// coverOwners has the owner of each cover slot. coverAll is true when
	// some covers had no space: then every byte that is not in a range of
	// the selected owner is foreign.
	covers      []cover
	coverOwners []OwnerIdentity
	coverAll    bool
	// masks are the sorted, merged byte intervals of different owners. They
	// are used only while the parts are built. maskAll is true when every
	// part without a source is foreign.
	masks   []interval
	maskAll bool
}

// unknownSlot is the cover slot of bytes whose owner is not known. These
// bytes are foreign for every owner.
const unknownSlot = uint8(0xff)

// cover is the byte interval [start, end) of one owner slot.
type cover struct {
	start uint32
	end   uint32
	slot  uint8
}

// interval is one byte interval [start, end).
type interval struct {
	start uint32
	end   uint32
}

type collectedRange struct {
	start        uint32
	length       uint32
	marks        uint64
	ownerID      uint64
	ownerGen     uint64
	source       uint16
	ownerIndex   uint8
	rangeOrdinal uint8
}

// CollectString assembles complete unsafe provenance for value. It gates the
// fixed collection workspace behind an active-store possible-hit check. The
// result can have more than one owner: use [Snapshot.ForOwner] before a
// report. The collection records the bytes of every owner (also the bytes of
// ranges with secure marks), so that ForOwner masks the bytes of the other
// owners.
func CollectString(value string, vulnerability constants.VulnerabilityType) (*Snapshot, Status) {
	if len(value) == 0 || len(value) > store.MaxRootBytes {
		return nil, StatusNone
	}
	if _, valid := ranges.MarkBit(vulnerability); !valid {
		return nil, StatusDropped
	}
	active := request.ActiveStore()
	key, ok := store.StringKey(value)
	if active == nil || !ok || !active.MayContain(key) {
		return nil, StatusNone
	}
	snapshot, status, _ := collectString(nil, value, vulnerability)
	return snapshot, status
}

// MayCollectString is the cheap gate of [CollectStringFor]: it returns false
// when value cannot have live provenance. It does not allocate. Use it before
// expensive work that is necessary only for a collection.
func MayCollectString(value string) bool {
	if len(value) == 0 || len(value) > store.MaxRootBytes {
		return false
	}
	active := request.ActiveStore()
	key, ok := store.StringKey(value)
	return active != nil && ok && active.MayContain(key)
}

// MayCollectJoinedStrings is the cheap gate of [CollectJoinedStringsFor]: it
// returns false when no value can have live provenance. It does not allocate
// and does not compare values with result.
func MayCollectJoinedStrings(values []string, result string) bool {
	if len(values) == 0 || len(values) > MaxJoinedValues || len(result) == 0 || len(result) > store.MaxRootBytes {
		return false
	}
	active := request.ActiveStore()
	return active != nil && mayContainAny(active, values)
}

// CollectStringFor assembles the complete unsafe provenance of value for the
// one owner of target. The result has at most one owner. Every range of a
// different owner is only a foreign part (see [Part.Foreign]). The collection
// bounds apply to the ranges and sources of the selected owner only, so a
// different owner cannot make the collection drop.
func CollectStringFor(target Target, value string, vulnerability constants.VulnerabilityType) (*Snapshot, Status) {
	if len(value) == 0 || len(value) > store.MaxRootBytes {
		return nil, StatusNone
	}
	if _, valid := ranges.MarkBit(vulnerability); !valid {
		return nil, StatusDropped
	}
	active := request.ActiveStore()
	key, ok := store.StringKey(value)
	if active == nil || !ok || !active.MayContain(key) {
		return nil, StatusNone
	}
	if target.Known {
		snapshot, status, _ := collectString(&target.Owner, value, vulnerability)
		return snapshot, status
	}
	snapshot, status, mixed := collectString(nil, value, vulnerability)
	owner, again := selectOwner(target, snapshot, status, mixed, func(collector *collector) {
		collector.visit(value, vulnerability, 0)
	})
	if !again {
		return snapshot, status
	}
	snapshot, status, _ = collectString(&owner, value, vulnerability)
	return snapshot, status
}

// collectString collects the ranges of owner in value, or of every owner when
// owner is nil. mixed is true when owner is nil and value has ranges of more
// than one owner (also ranges with secure marks), or bytes with no known
// owner.
func collectString(owner *OwnerIdentity, value string, vulnerability constants.VulnerabilityType) (*Snapshot, Status, bool) {
	collector := newCollector(owner)
	delivered := collector.visit(value, vulnerability, 0)
	return collector.result(value, delivered)
}

// CollectJoinedStrings assembles provenance from values at their exact
// positions in result, with one untainted separator between values.
func CollectJoinedStrings(values []string, separator, result string, vulnerability constants.VulnerabilityType) (*Snapshot, Status) {
	if len(values) == 0 || len(values) > MaxJoinedValues || len(result) == 0 || len(result) > store.MaxRootBytes || !matchesJoin(values, separator, result) {
		return nil, StatusNone
	}
	if _, valid := ranges.MarkBit(vulnerability); !valid {
		return nil, StatusDropped
	}
	active := request.ActiveStore()
	if active == nil {
		return nil, StatusNone
	}
	if !mayContainAny(active, values) {
		return nil, StatusNone
	}
	snapshot, status, _ := collectJoined(nil, active, values, separator, result, vulnerability)
	return snapshot, status
}

// CollectJoinedStringsFor is [CollectJoinedStrings] for the one owner of
// target, with the rules of [CollectStringFor].
func CollectJoinedStringsFor(target Target, values []string, separator, result string, vulnerability constants.VulnerabilityType) (*Snapshot, Status) {
	if len(values) == 0 || len(values) > MaxJoinedValues || len(result) == 0 || len(result) > store.MaxRootBytes || !matchesJoin(values, separator, result) {
		return nil, StatusNone
	}
	if _, valid := ranges.MarkBit(vulnerability); !valid {
		return nil, StatusDropped
	}
	active := request.ActiveStore()
	if active == nil || !mayContainAny(active, values) {
		return nil, StatusNone
	}
	if target.Known {
		snapshot, status, _ := collectJoined(&target.Owner, active, values, separator, result, vulnerability)
		return snapshot, status
	}
	snapshot, status, mixed := collectJoined(nil, active, values, separator, result, vulnerability)
	owner, again := selectOwner(target, snapshot, status, mixed, func(collector *collector) {
		collector.visitJoined(active, values, separator, vulnerability)
	})
	if !again {
		return snapshot, status
	}
	snapshot, status, _ = collectJoined(&owner, active, values, separator, result, vulnerability)
	return snapshot, status
}

func mayContainAny(active *store.Store, values []string) bool {
	for _, value := range values {
		key, ok := store.StringKey(value)
		if ok && active.MayContain(key) {
			return true
		}
	}
	return false
}

func collectJoined(owner *OwnerIdentity, active *store.Store, values []string, separator, result string, vulnerability constants.VulnerabilityType) (*Snapshot, Status, bool) {
	collector := newCollector(owner)
	delivered := collector.visitJoined(active, values, separator, vulnerability)
	return collector.result(result, delivered)
}

// selectOwner decides from the collection of every owner (snapshot, status,
// and mixed) whether a collection of one owner is necessary, and selects this
// owner. It returns false when the collection of every owner is the result:
// the value has ranges of one owner only, or it has no unsafe range. When a
// bound dropped the collection of every owner, scan finds the owners again
// with no bounds, so that the ranges of a different owner cannot make the
// collection of the selected owner drop.
func selectOwner(target Target, snapshot *Snapshot, status Status, mixed bool, scan func(*collector)) (OwnerIdentity, bool) {
	var owners []OwnerIdentity
	switch {
	case status == StatusCollected && mixed:
		owners = snapshot.owners
	case status == StatusDropped:
		scanner := newOwnerScanner()
		scan(scanner)
		if !scanner.mixed || scanner.dropped {
			return OwnerIdentity{}, false
		}
		owners = scanner.sortedOwners()
	default:
		return OwnerIdentity{}, false
	}
	if len(owners) == 0 {
		return OwnerIdentity{}, false
	}
	if target.Select != nil {
		if owner, ok := target.Select(owners); ok && slices.Contains(owners, owner) {
			return owner, true
		}
	}
	return owners[0], true
}

func matchesJoin(values []string, separator, result string) bool {
	position := 0
	for index, value := range values {
		if len(value) > len(result)-position || result[position:position+len(value)] != value {
			return false
		}
		position += len(value)
		if index+1 < len(values) {
			if len(separator) > len(result)-position || result[position:position+len(separator)] != separator {
				return false
			}
			position += len(separator)
		}
	}
	return position == len(result)
}

type collector struct {
	count       int
	sourceCount int
	sourceBytes int
	dropped     bool
	// scoped is true when the collection keeps only the ranges of owner.
	// The ranges of the other owners go to foreign.
	scoped bool
	owner  OwnerIdentity
	// first and mixed record the owners of all delivered ranges (also ranges
	// with secure marks) of a collection that is not scoped. mixed is true
	// when there is more than one owner, or when some bytes have no known
	// owner (see addHidden).
	first    OwnerIdentity
	hasFirst bool
	mixed    bool
	// scanOnly is true for a collection that only finds the owners with
	// unsafe ranges (see selectOwner). It keeps no range and no source.
	scanOnly   bool
	scanOwners [maxOwners]OwnerIdentity
	scanCount  int
	// foreign keeps the byte intervals of different owners in a scoped
	// collection. In a collection that is not scoped (and not scanOnly), it
	// keeps the byte interval of every range (also a range with secure
	// marks) and of the bytes with no known owner, and foreignSlot keeps the
	// owner slot of each interval (see ownerSlots and unknownSlot).
	// foreignOverflow is true when foreign had no space: then every part
	// without a source is foreign.
	foreignCount    int
	foreignOverflow bool
	foreign         [MaxCollectedRanges]interval
	foreignSlot     [MaxCollectedRanges]uint8
	ownerSlots      [maxOwners]OwnerIdentity
	ownerSlotCount  int
	ranges          [MaxCollectedRanges]collectedRange
	sources         [MaxSources]Source
	sourceIndexes   [2 * MaxSources]uint16 // source index + 1; zero is empty.
}

func newCollector(owner *OwnerIdentity) *collector {
	collector := new(collector)
	if owner != nil {
		collector.scoped = true
		collector.owner = *owner
	}
	return collector
}

func newOwnerScanner() *collector {
	collector := new(collector)
	collector.scanOnly = true
	return collector
}

// visit adds the provenance of value at offset. It returns true when the
// store delivered at least one range of the collected owners.
func (c *collector) visit(value string, vulnerability constants.VulnerabilityType, offset uint32) bool {
	add := func(resolved request.ResolvedRange) bool {
		return c.addAt(value, vulnerability, resolved, offset)
	}
	if !c.scoped {
		if c.scanOnly {
			return request.VisitString(value, add)
		}
		return request.VisitStringHidden(value, add, func(start, length uint32) {
			c.addHidden(uint32(len(value)), offset, start, length)
		})
	}
	return request.VisitStringOwner(value, c.owner, add, func(start, length uint32) {
		c.addForeign(uint32(len(value)), offset, start, length)
	})
}

func (c *collector) visitJoined(active *store.Store, values []string, separator string, vulnerability constants.VulnerabilityType) bool {
	delivered := false
	offset := uint32(0)
	for index, value := range values {
		if key, ok := store.StringKey(value); ok && active.MayContain(key) {
			delivered = c.visit(value, vulnerability, offset) || delivered
		}
		offset += uint32(len(value))
		if index+1 < len(values) {
			offset += uint32(len(separator))
		}
		if c.dropped {
			return delivered
		}
	}
	return delivered
}

// result returns the snapshot of the collection of value. mixed is true when
// the collection is not scoped and value has ranges of more than one owner.
func (c *collector) result(value string, delivered bool) (*Snapshot, Status, bool) {
	if c.dropped {
		return nil, StatusDropped, c.mixed
	}
	if c.count == 0 {
		if delivered {
			return nil, StatusSuppressed, c.mixed
		}
		return nil, StatusNone, c.mixed
	}
	return c.finish(value), StatusCollected, c.mixed
}

// addForeign records the interval [start, start+length) of a different owner
// in a value of valueLength bytes at offset.
func (c *collector) addForeign(valueLength, offset, start, length uint32) {
	c.addInterval(valueLength, offset, start, length, 0)
}

// addCover records the interval [start, start+length) of owner in a value of
// valueLength bytes at offset, in a collection that is not scoped.
func (c *collector) addCover(owner OwnerIdentity, valueLength, offset, start, length uint32) {
	c.addInterval(valueLength, offset, start, length, c.ownerSlot(owner))
}

// addHidden records the interval [start, start+length) of bytes with no
// known owner, in a collection that is not scoped. These bytes can be data of
// a different owner, so the collection is mixed.
func (c *collector) addHidden(valueLength, offset, start, length uint32) {
	c.mixed = true
	c.addInterval(valueLength, offset, start, length, unknownSlot)
}

// ownerSlot returns the slot of owner in ownerSlots. It returns unknownSlot
// when ownerSlots has no space: the bytes of this owner are then foreign for
// every owner.
func (c *collector) ownerSlot(owner OwnerIdentity) uint8 {
	for index, current := range c.ownerSlots[:c.ownerSlotCount] {
		if current == owner {
			return uint8(index)
		}
	}
	if c.ownerSlotCount >= len(c.ownerSlots) {
		return unknownSlot
	}
	c.ownerSlots[c.ownerSlotCount] = owner
	c.ownerSlotCount++
	return uint8(c.ownerSlotCount - 1)
}

func (c *collector) addInterval(valueLength, offset, start, length uint32, slot uint8) {
	if start >= valueLength {
		return
	}
	length = min(length, valueLength-start)
	if length == 0 {
		return
	}
	if c.foreignCount >= len(c.foreign) {
		c.foreignOverflow = true
		return
	}
	c.foreign[c.foreignCount] = interval{start: offset + start, end: offset + start + length}
	c.foreignSlot[c.foreignCount] = slot
	c.foreignCount++
}

func (c *collector) add(value string, vulnerability constants.VulnerabilityType, resolved request.ResolvedRange) bool {
	return c.addAt(value, vulnerability, resolved, 0)
}

func (c *collector) addAt(value string, vulnerability constants.VulnerabilityType, resolved request.ResolvedRange, offset uint32) bool {
	if resolved.Length == 0 || resolved.Start > uint32(len(value)) || resolved.Length > uint32(len(value))-resolved.Start {
		c.dropped = true
		return false
	}
	owner := rangeOwnerOf(resolved)
	switch {
	case c.scoped:
		if owner != c.owner {
			// VisitStringOwner does not deliver a range of a different
			// owner. Treat it as foreign bytes.
			c.addForeign(uint32(len(value)), offset, resolved.Start, resolved.Length)
			return true
		}
	case !c.hasFirst:
		c.first, c.hasFirst = owner, true
	case owner != c.first:
		c.mixed = true
	}
	if !c.scoped && !c.scanOnly {
		// Record the bytes of every range, also of a range with secure
		// marks: they are data of the owner of the range.
		c.addCover(owner, uint32(len(value)), offset, resolved.Start, resolved.Length)
	}
	if ranges.HasMark(resolved.Marks, vulnerability) {
		return true
	}
	if c.scanOnly {
		c.addScanOwner(owner)
		return true
	}
	if c.count >= len(c.ranges) {
		c.dropped = true
		return false
	}
	source, ok := c.sourceIndex(resolved.Source)
	if !ok {
		c.dropped = true
		return false
	}
	c.ranges[c.count] = collectedRange{
		start:        offset + resolved.Start,
		length:       resolved.Length,
		marks:        resolved.Marks,
		ownerID:      resolved.OwnerID,
		ownerGen:     resolved.OwnerGen,
		source:       source,
		ownerIndex:   resolved.OwnerIndex,
		rangeOrdinal: resolved.RangeOrdinal,
	}
	c.count++
	return true
}

func (c *collector) addScanOwner(owner OwnerIdentity) {
	for _, current := range c.scanOwners[:c.scanCount] {
		if current == owner {
			return
		}
	}
	if c.scanCount < len(c.scanOwners) {
		c.scanOwners[c.scanCount] = owner
		c.scanCount++
	}
}

func (c *collector) sortedOwners() []OwnerIdentity {
	owners := append([]OwnerIdentity(nil), c.scanOwners[:c.scanCount]...)
	slices.SortFunc(owners, compareOwners)
	return owners
}

func compareOwners(left, right OwnerIdentity) int {
	if order := cmp.Compare(left.ID, right.ID); order != 0 {
		return order
	}
	if order := cmp.Compare(left.Generation, right.Generation); order != 0 {
		return order
	}
	return cmp.Compare(left.Index, right.Index)
}

func rangeOwnerOf(resolved request.ResolvedRange) OwnerIdentity {
	return OwnerIdentity{ID: resolved.OwnerID, Generation: resolved.OwnerGen, Index: resolved.OwnerIndex}
}

func (c *collector) sourceIndex(source request.Source) (uint16, bool) {
	hash := sourceHash(source)
	slot := int(hash % uint64(len(c.sourceIndexes)))
	for range len(c.sourceIndexes) {
		encoded := c.sourceIndexes[slot]
		if encoded == 0 {
			if c.sourceCount >= len(c.sources) || len(source.Name) > MaxSnapshotBytes-c.sourceBytes {
				return 0, false
			}
			nextBytes := c.sourceBytes + len(source.Name)
			if len(source.Value) > MaxSnapshotBytes-nextBytes {
				return 0, false
			}
			index := c.sourceCount
			c.sources[index] = Source{
				Origin: source.Origin,
				Name:   strings.Clone(source.Name),
				Value:  strings.Clone(source.Value),
			}
			c.sourceIndexes[slot] = uint16(index + 1)
			c.sourceCount++
			c.sourceBytes = nextBytes + len(source.Value)
			return uint16(index), true
		}
		index := int(encoded - 1)
		candidate := &c.sources[index]
		if candidate.Origin == source.Origin && candidate.Name == source.Name && candidate.Value == source.Value {
			return uint16(index), true
		}
		slot++
		if slot == len(c.sourceIndexes) {
			slot = 0
		}
	}
	return 0, false
}

func sourceHash(source request.Source) uint64 {
	const (
		offset = uint64(14695981039346656037)
		prime  = uint64(1099511628211)
	)
	hash := offset ^ uint64(source.Origin)
	for index := 0; index < len(source.Name); index++ {
		hash = (hash ^ uint64(source.Name[index])) * prime
	}
	hash = (hash ^ 0xff) * prime
	for index := 0; index < len(source.Value); index++ {
		hash = (hash ^ uint64(source.Value[index])) * prime
	}
	return hash
}

func (c *collector) finish(value string) *Snapshot {
	snapshot := &Snapshot{
		value:   strings.Clone(value),
		ranges:  append(make([]collectedRange, 0, c.count), c.ranges[:c.count]...),
		sources: append(make([]Source, 0, c.sourceCount), c.sources[:c.sourceCount]...),
		owners:  make([]OwnerIdentity, 0, maxOwners),
	}
	switch {
	case !c.scoped && (c.mixed || c.multipleOwners()):
		// A different owner has bytes in value. canonicalize changes
		// ranges and sources in place. Keep a copy of the admitted data
		// and the covers for ForOwner.
		snapshot.mixed = true
		snapshot.admitted = append(make([]collectedRange, 0, c.count), c.ranges[:c.count]...)
		snapshot.admittedSources = snapshot.sources
		snapshot.covers = make([]cover, c.foreignCount)
		for index := range snapshot.covers {
			current := c.foreign[index]
			snapshot.covers[index] = cover{start: current.start, end: current.end, slot: c.foreignSlot[index]}
		}
		snapshot.coverOwners = append(make([]OwnerIdentity, 0, c.ownerSlotCount), c.ownerSlots[:c.ownerSlotCount]...)
		snapshot.coverAll = c.foreignOverflow
	case !c.scoped:
		// Only one owner has bytes in value: its covers are not foreign.
	case c.foreignOverflow:
		snapshot.maskAll = true
	case c.foreignCount > 0:
		snapshot.masks = mergeIntervals(append(make([]interval, 0, c.foreignCount), c.foreign[:c.foreignCount]...))
	}
	snapshot.canonicalize()
	return snapshot
}

// masksFor returns the byte intervals of the owners that are not owner, for a
// mixed snapshot. all is true when every byte that is not in a range of owner
// must be foreign.
func (s *Snapshot) masksFor(owner OwnerIdentity) (masks []interval, all bool) {
	if !s.mixed || s.coverAll {
		return nil, true
	}
	masks = make([]interval, 0, len(s.covers))
	for _, current := range s.covers {
		if current.slot != unknownSlot && int(current.slot) < len(s.coverOwners) && s.coverOwners[current.slot] == owner {
			continue
		}
		masks = append(masks, interval{start: current.start, end: current.end})
	}
	return mergeIntervals(masks), false
}

// mergeIntervals sorts values and merges the intervals that overlap or touch.
func mergeIntervals(values []interval) []interval {
	slices.SortFunc(values, func(left, right interval) int {
		return cmp.Compare(left.start, right.start)
	})
	output := 0
	for _, current := range values {
		if output > 0 && current.start <= values[output-1].end {
			values[output-1].end = max(values[output-1].end, current.end)
			continue
		}
		values[output] = current
		output++
	}
	return values[:output]
}

func (c *collector) multipleOwners() bool {
	for index := 1; index < c.count; index++ {
		if rangeOwner(c.ranges[index]) != rangeOwner(c.ranges[0]) {
			return true
		}
	}
	return false
}

func rangeOwner(current collectedRange) OwnerIdentity {
	return OwnerIdentity{ID: current.ownerID, Generation: current.ownerGen, Index: current.ownerIndex}
}

// HasOwner reports whether owner contributed an admitted unsafe range.
func (s *Snapshot) HasOwner(owner OwnerIdentity) bool {
	if s == nil {
		return false
	}
	for _, current := range s.owners {
		if current == owner {
			return true
		}
	}
	return false
}

// ForOwner returns the snapshot that contains only the ranges, sources, and
// evidence parts of owner. The result has exactly one owner. It is s when s has
// only this owner and no different owner has bytes in the value. It returns
// false when owner did not contribute an admitted unsafe range: the value is
// not tainted for this owner. Overlap selection is done again with only the
// ranges of owner, so no range of a different owner can hide a range of
// owner. The bytes of a different owner (also bytes of its ranges with secure
// marks) and the bytes with no known owner are foreign parts.
func (s *Snapshot) ForOwner(owner OwnerIdentity) (*Snapshot, bool) {
	if !s.HasOwner(owner) {
		return nil, false
	}
	if len(s.owners) == 1 && !s.mixed {
		return s, true
	}
	selected := make([]collectedRange, 0, len(s.admitted))
	for _, current := range s.admitted {
		if rangeOwner(current) == owner {
			selected = append(selected, current)
		}
	}
	if len(selected) == 0 {
		return nil, false
	}
	// canonicalize reads admittedSources and does not change them: it
	// writes a new source slice.
	masks, all := s.masksFor(owner)
	restricted := &Snapshot{
		value:   s.value,
		ranges:  selected,
		sources: s.admittedSources,
		owners:  make([]OwnerIdentity, 0, 1),
		masks:   masks,
		maskAll: all,
	}
	restricted.canonicalize()
	return restricted, true
}

func (s *Snapshot) canonicalize() {
	values := s.ranges
	slices.SortFunc(values, func(left, right collectedRange) int {
		if order := cmp.Compare(left.start, right.start); order != 0 {
			return order
		}
		leftSource, rightSource := s.sources[left.source], s.sources[right.source]
		if order := cmp.Compare(leftSource.Origin, rightSource.Origin); order != 0 {
			return order
		}
		if order := cmp.Compare(leftSource.Name, rightSource.Name); order != 0 {
			return order
		}
		if order := cmp.Compare(leftSource.Value, rightSource.Value); order != 0 {
			return order
		}
		if order := cmp.Compare(left.length, right.length); order != 0 {
			return order
		}
		if order := cmp.Compare(left.marks, right.marks); order != 0 {
			return order
		}
		if order := cmp.Compare(left.ownerID, right.ownerID); order != 0 {
			return order
		}
		if order := cmp.Compare(left.ownerGen, right.ownerGen); order != 0 {
			return order
		}
		if order := cmp.Compare(left.ownerIndex, right.ownerIndex); order != 0 {
			return order
		}
		return cmp.Compare(left.rangeOrdinal, right.rangeOrdinal)
	})

	for _, current := range values {
		s.addOwner(OwnerIdentity{ID: current.ownerID, Generation: current.ownerGen, Index: current.ownerIndex})
	}
	slices.SortFunc(s.owners, compareOwners)
	if s.mixed {
		// The parts of a mixed snapshot mask the bytes of every owner that
		// is not its one owner. A snapshot of more than one owner must not
		// be reported, so all its parts without a source are foreign.
		if len(s.owners) == 1 {
			s.masks, s.maskAll = s.masksFor(s.owners[0])
		} else {
			s.maskAll = true
		}
	}

	output := 0
	var covered uint32
	for _, current := range values {
		end := current.start + current.length
		if current.start < covered {
			if end <= covered {
				continue
			}
			current.start = covered
			current.length = end - covered
		}
		if output > 0 {
			previous := &values[output-1]
			if previous.start+previous.length == current.start && previous.source == current.source && previous.marks == current.marks {
				previous.length += current.length
				covered = end
				continue
			}
		}
		values[output] = current
		output++
		covered = end
	}
	clear(values[output:])
	s.ranges = values[:output]
	s.reindexSources()
	s.buildParts()
}

func (s *Snapshot) reindexSources() {
	var remap [MaxSources]int16
	for index := range remap {
		remap[index] = -1
	}
	sources := make([]Source, 0, min(len(s.sources), len(s.ranges)))
	newSourceCount := 0
	for rangeIndex := range s.ranges {
		current := &s.ranges[rangeIndex]
		mapped := remap[current.source]
		if mapped < 0 {
			mapped = int16(newSourceCount)
			remap[current.source] = mapped
			sources = append(sources, s.sources[current.source])
			newSourceCount++
		}
		current.source = uint16(mapped)
	}
	s.sources = sources
	s.sourceBytes = 0
	for _, source := range sources {
		s.sourceBytes += uint32(len(source.Name) + len(source.Value))
	}
}

func (s *Snapshot) addOwner(identity OwnerIdentity) {
	for _, current := range s.owners {
		if current == identity {
			return
		}
	}
	if len(s.owners) < maxOwners {
		s.owners = append(s.owners, identity)
	}
}

func (s *Snapshot) buildParts() {
	// Masks apply only to the gaps between the ranges of the snapshot. A
	// part of a range of the snapshot is never masked, also when a range of
	// a different owner has the same bytes: these bytes are in a range of
	// the owner of the snapshot, so they come from a source value of this
	// owner. To show them discloses data of this owner only, not data of
	// the different owner. A snapshot of one owner never has the source of
	// the different owner.
	//
	// Each mask can add up to two parts. When the masks and ranges together
	// can make more than MaxParts parts, every gap that touches a mask is
	// foreign as one part: this does not add parts.
	split := !s.maskAll && len(s.masks)+len(s.ranges) <= MaxCollectedRanges
	capacity := 2*len(s.ranges) + 1
	if split {
		capacity += 2 * len(s.masks)
	}
	s.parts = make([]Part, 0, min(MaxParts, capacity))
	position := uint32(0)
	mask := 0
	for _, current := range s.ranges {
		if current.start > position {
			mask = s.appendGap(position, current.start, mask, split)
		}
		s.parts = append(s.parts, Part{Start: current.start, Length: current.length, Source: int16(current.source), Marks: current.marks})
		position = current.start + current.length
	}
	if position < uint32(len(s.value)) {
		s.appendGap(position, uint32(len(s.value)), mask, split)
	}
	s.ranges = nil
	s.masks = nil
}

// appendGap appends the parts without a source of [start, end). mask is the
// index of the first mask that can touch the gap. It returns the index for
// the next gap.
func (s *Snapshot) appendGap(start, end uint32, mask int, split bool) int {
	for mask < len(s.masks) && s.masks[mask].end <= start {
		mask++
	}
	if s.maskAll || !split {
		foreign := s.maskAll || mask < len(s.masks) && s.masks[mask].start < end
		s.parts = append(s.parts, Part{Start: start, Length: end - start, Source: -1, Foreign: foreign})
		return mask
	}
	position := start
	for position < end {
		if mask < len(s.masks) && s.masks[mask].start <= position {
			next := min(end, s.masks[mask].end)
			s.parts = append(s.parts, Part{Start: position, Length: next - position, Source: -1, Foreign: true})
			position = next
			if s.masks[mask].end <= position {
				mask++
			}
			continue
		}
		next := end
		if mask < len(s.masks) {
			next = min(next, s.masks[mask].start)
		}
		s.parts = append(s.parts, Part{Start: position, Length: next - position, Source: -1})
		position = next
	}
	return mask
}

// Value returns the report-owned evidence value.
func (s *Snapshot) Value() string {
	if s == nil {
		return ""
	}
	return s.value
}

// SourceBytes returns the cumulative source name/value bytes owned by s.
func (s *Snapshot) SourceBytes() uint32 {
	if s == nil {
		return 0
	}
	return s.sourceBytes
}

// SourceCount returns the number of exact source identities.
func (s *Snapshot) SourceCount() int {
	if s == nil {
		return 0
	}
	return len(s.sources)
}

// SourceAt returns one exact source identity.
func (s *Snapshot) SourceAt(index int) (Source, bool) {
	if s == nil || index < 0 || index >= len(s.sources) {
		return Source{}, false
	}
	return s.sources[index], true
}

// PartCount returns the number of consecutive evidence intervals.
func (s *Snapshot) PartCount() int {
	if s == nil {
		return 0
	}
	return len(s.parts)
}

// PartAt returns one consecutive evidence interval.
func (s *Snapshot) PartAt(index int) (Part, bool) {
	if s == nil || index < 0 || index >= len(s.parts) {
		return Part{}, false
	}
	return s.parts[index], true
}

// PartValue returns the bytes covered by part.
func (s *Snapshot) PartValue(part Part) (string, bool) {
	if s == nil || part.Length == 0 || part.Start > uint32(len(s.value)) || part.Length > uint32(len(s.value))-part.Start {
		return "", false
	}
	return s.value[part.Start : part.Start+part.Length], true
}

// OwnerCount returns up to four owners that contributed an admitted unsafe
// range, including owners whose byte coverage lost deterministic overlap
// selection. The store lookup has the same four-owner hard bound. A report
// needs a snapshot with exactly one owner (see [Snapshot.ForOwner]).
func (s *Snapshot) OwnerCount() int {
	if s == nil {
		return 0
	}
	return len(s.owners)
}

// OwnerAt returns one stable contributing owner identity.
func (s *Snapshot) OwnerAt(index int) (OwnerIdentity, bool) {
	if s == nil || index < 0 || index >= len(s.owners) {
		return OwnerIdentity{}, false
	}
	return s.owners[index], true
}
