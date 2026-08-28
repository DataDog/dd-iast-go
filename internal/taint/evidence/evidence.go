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
type OwnerIdentity struct {
	ID         uint64
	Generation uint64
	Index      uint8
}

// Part is one consecutive pre-redaction evidence interval. Source is -1 for an
// untainted part and otherwise indexes Snapshot.SourceAt. Marks contains the
// remaining secure marks after the requested vulnerability's mark was excluded.
type Part struct {
	Start  uint32
	Length uint32
	Source int16
	Marks  uint64
}

// Snapshot owns the evidence value and every source string. It contains only
// canonical unsafe intervals.
type Snapshot struct {
	value       string
	sourceBytes uint32
	ranges      []collectedRange
	sources     []Source
	parts       []Part
	owners      []OwnerIdentity
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
// fixed collection workspace behind an active-store possible-hit check.
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
	collector := new(collector)
	delivered := request.VisitString(value, func(resolved request.ResolvedRange) bool {
		return collector.add(value, vulnerability, resolved)
	})
	if collector.dropped {
		return nil, StatusDropped
	}
	if collector.count == 0 {
		if delivered {
			return nil, StatusSuppressed
		}
		return nil, StatusNone
	}
	return collector.finish(value), StatusCollected
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
	possible := false
	for _, value := range values {
		key, ok := store.StringKey(value)
		if ok && active.MayContain(key) {
			possible = true
			break
		}
	}
	if !possible {
		return nil, StatusNone
	}
	collector := new(collector)
	delivered := false
	offset := uint32(0)
	for index, value := range values {
		if key, ok := store.StringKey(value); ok && active.MayContain(key) {
			visited := request.VisitString(value, func(resolved request.ResolvedRange) bool {
				return collector.addAt(value, vulnerability, resolved, offset)
			})
			delivered = delivered || visited
		}
		offset += uint32(len(value))
		if index+1 < len(values) {
			offset += uint32(len(separator))
		}
		if collector.dropped {
			return nil, StatusDropped
		}
	}
	if collector.count == 0 {
		if delivered {
			return nil, StatusSuppressed
		}
		return nil, StatusNone
	}
	return collector.finish(result), StatusCollected
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
	count         int
	sourceCount   int
	sourceBytes   int
	dropped       bool
	ranges        [MaxCollectedRanges]collectedRange
	sources       [MaxSources]Source
	sourceIndexes [2 * MaxSources]uint16 // source index + 1; zero is empty.
}

func (c *collector) add(value string, vulnerability constants.VulnerabilityType, resolved request.ResolvedRange) bool {
	return c.addAt(value, vulnerability, resolved, 0)
}

func (c *collector) addAt(value string, vulnerability constants.VulnerabilityType, resolved request.ResolvedRange, offset uint32) bool {
	if resolved.Length == 0 || resolved.Start > uint32(len(value)) || resolved.Length > uint32(len(value))-resolved.Start {
		c.dropped = true
		return false
	}
	if ranges.HasMark(resolved.Marks, vulnerability) {
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
	snapshot.canonicalize()
	return snapshot
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
	slices.SortFunc(s.owners, func(left, right OwnerIdentity) int {
		if order := cmp.Compare(left.ID, right.ID); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Generation, right.Generation); order != 0 {
			return order
		}
		return cmp.Compare(left.Index, right.Index)
	})

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
	s.parts = make([]Part, 0, min(MaxParts, 2*len(s.ranges)+1))
	position := uint32(0)
	for _, current := range s.ranges {
		if current.start > position {
			s.parts = append(s.parts, Part{Start: position, Length: current.start - position, Source: -1})
		}
		s.parts = append(s.parts, Part{Start: current.start, Length: current.length, Source: int16(current.source), Marks: current.marks})
		position = current.start + current.length
	}
	if position < uint32(len(s.value)) {
		s.parts = append(s.parts, Part{Start: position, Length: uint32(len(s.value)) - position, Source: -1})
	}
	s.ranges = nil
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
// selection. The store lookup has the same four-owner hard bound.
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
