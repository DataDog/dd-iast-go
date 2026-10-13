// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package evidence assembles bounded, report-owned taint evidence snapshots.
//
// The input of a collection is the attribution of the request package (plan
// section 4.5): the segments of the tainted bytes of a value, each with one
// source of one request owner, or foreign. A snapshot has the evidence of
// exactly one owner. The bytes that are not attributed to a source of this
// owner are foreign parts: a report shows them only as a redaction marker.
package evidence

import (
	"cmp"
	"slices"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

const (
	// MaxValueBytes is the largest value that a collection examines. A larger
	// sink value is not collected (the PR #39 root bound).
	MaxValueBytes = 64 << 10
	// MaxSnapshotBytes bounds complete cloned source names and values retained by
	// one report snapshot.
	MaxSnapshotBytes = 256 << 10
	// MaxAttributedParts bounds the parts of one snapshot that have a source
	// (the hard bound of DD_IAST_MAX_RANGE_COUNT).
	MaxAttributedParts = request.MaxAttributed
	// MaxTaintedParts bounds the tainted parts (with a source, or foreign) of
	// one snapshot.
	MaxTaintedParts = 2*MaxAttributedParts + 1
	// MaxParts bounds the evidence pieces of one report, also after the
	// redaction splits the parts at the sensitive intervals of the sink (the
	// PR #39 value). A snapshot has at most 2*MaxTaintedParts+1 parts.
	MaxParts = 513
	// MaxSources bounds exact source identities in one report.
	MaxSources = MaxAttributedParts
	// MaxJoinedValues bounds command argv traversal.
	MaxJoinedValues = 256
)

var _ [MaxParts - (2*MaxTaintedParts + 1)]struct{}

// Status is the result of collecting one value.
type Status uint8

const (
	// StatusNone means that no byte of the value is attributed to a source of
	// a live request owner.
	StatusNone Status = iota
	// StatusCollected means a complete unsafe snapshot was assembled.
	StatusCollected
	// StatusDropped means that the input is not valid (for example an
	// unknown vulnerability type).
	StatusDropped
)

// Source is one exact, report-owned source identity.
type Source struct {
	Origin constants.Origin
	Name   string
	Value  string
}

// OwnerIdentity identifies one generation-validated request owner.
type OwnerIdentity = request.Owner

// Part is one consecutive pre-redaction evidence interval. Source is -1 for a
// part with no source and otherwise indexes Snapshot.SourceAt.
//
// Foreign is true for a part with no source (Source is -1) whose bytes are
// tainted, but not attributed to a source of the owner of the snapshot: bytes
// of a different request, stale taint, or bytes after a collection bound. A
// report must show only a redaction marker for it, also when redaction is
// disabled: the bytes can be data of a different request.
type Part struct {
	Start   uint32
	Length  uint32
	Source  int16
	Foreign bool
}

// Target tells a collection the one owner whose sources it uses. A report
// contains the evidence of exactly one owner.
type Target struct {
	// Owner is the request owner of the sink context. When Known is false,
	// Owner is only a preference: the collection tries it first (for
	// example the owner of the span annotation), then the other live
	// owners (plan section 4.5.3). The zero value has no preference.
	Owner OwnerIdentity
	// Known is true when the sink context has a request owner. The
	// collection then uses only the sources of Owner.
	Known bool
}

// Snapshot owns the evidence value and every source string. It has the
// evidence of exactly one owner.
type Snapshot struct {
	value       string
	sourceBytes uint32
	owner       OwnerIdentity
	sources     []Source
	parts       []Part
}

// validVulnerability reports whether vulnerability is a known type.
func validVulnerability(vulnerability constants.VulnerabilityType) bool {
	return vulnerability != 0 && uint(vulnerability) <= constants.VulnerabilityTypeCount
}

// MayCollectString is the cheap gate of [CollectStringFor]: it returns false
// when value cannot have live provenance (no live request owner, or no taint
// bit in value). It does not allocate. Use it before expensive work that is
// necessary only for a collection.
func MayCollectString(value string) bool {
	return len(value) != 0 && len(value) <= MaxValueBytes && request.ProcessManager().Active() && heapbits.AnyString(value)
}

// MayCollectJoinedStrings is the cheap gate of [CollectJoinedStringsFor]: it
// returns false when no value can have live provenance. It does not allocate
// and does not compare values with result.
func MayCollectJoinedStrings(values []string, result string) bool {
	if len(values) == 0 || len(values) > MaxJoinedValues || len(result) == 0 || len(result) > MaxValueBytes || !request.ProcessManager().Active() {
		return false
	}
	return anyTainted(values)
}

func anyTainted(values []string) bool {
	for _, value := range values {
		if heapbits.AnyString(value) {
			return true
		}
	}
	return false
}

// CollectStringFor assembles the unsafe provenance of value for the one owner
// of target. Every tainted byte that is not attributed to a source of this
// owner is a foreign part (see [Part.Foreign]). It returns StatusNone when
// no byte is attributed to a source of the owner with a strong match (see
// [request.Segment.Strong]). Weak parts have their source in a collected
// snapshot.
func CollectStringFor(target Target, value string, vulnerability constants.VulnerabilityType) (*Snapshot, Status) {
	if !validVulnerability(vulnerability) {
		return nil, StatusDropped
	}
	if !MayCollectString(value) {
		return nil, StatusNone
	}
	c := newCollector()
	manager := request.ProcessManager()
	if target.Known {
		analysis, ok := manager.Analysis(target.Owner)
		if !ok || !analysis.AttributeString(value, &c.attribution) {
			return nil, StatusNone
		}
	} else if !manager.AttributeStringAny(value, target.Owner, &c.attribution) {
		return nil, StatusNone
	}
	c.owner = c.attribution.Owner
	c.addAttribution(0)
	return c.result(value)
}

// CollectJoinedStringsFor assembles provenance from values at their exact
// positions in result, with one untainted separator between values. It uses
// the one owner of target, with the rules of [CollectStringFor]. When the
// owner is not known, the first value with an attributed byte selects the
// owner, and all values are then attributed for this owner.
func CollectJoinedStringsFor(target Target, values []string, separator, result string, vulnerability constants.VulnerabilityType) (*Snapshot, Status) {
	if !validVulnerability(vulnerability) {
		return nil, StatusDropped
	}
	if !MayCollectJoinedStrings(values, result) || !matchesJoin(values, separator, result) {
		return nil, StatusNone
	}
	manager := request.ProcessManager()
	c := newCollector()
	if !target.Known {
		owner, ok := selectJoinedOwner(manager, target.Owner, values, &c.attribution)
		if !ok {
			return nil, StatusNone
		}
		target = Target{Owner: owner, Known: true}
	}
	analysis, ok := manager.Analysis(target.Owner)
	if !ok {
		return nil, StatusNone
	}
	c.owner = target.Owner
	offset := uint32(0)
	for index, value := range values {
		if heapbits.AnyString(value) {
			analysis.AttributeString(value, &c.attribution)
			c.addAttribution(offset)
		}
		offset += uint32(len(value))
		if index+1 < len(values) {
			offset += uint32(len(separator))
		}
	}
	return c.result(result)
}

// selectJoinedOwner selects the owner of an ownerless joined collection:
// prefer when a value has a source of it, else the owner of the first value
// with a source of a live owner. r is a work area.
func selectJoinedOwner(manager *request.Manager, prefer OwnerIdentity, values []string, r *request.Attribution) (OwnerIdentity, bool) {
	defer r.Reset()
	if analysis, ok := manager.Analysis(prefer); ok {
		for _, value := range values {
			if heapbits.AnyString(value) && analysis.AttributeString(value, r) {
				return prefer, true
			}
		}
	}
	for _, value := range values {
		if heapbits.AnyString(value) && manager.AttributeStringAny(value, OwnerIdentity{}, r) {
			return r.Owner, true
		}
	}
	return OwnerIdentity{}, false
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

// tainted is one tainted part of the value of a collection. source is the
// index in collector.sources, or -1 for a foreign part.
type tainted struct {
	start  uint32
	end    uint32
	source int16
}

// collector assembles the snapshot of one value. It is large: allocate it
// only after the cheap gate.
type collector struct {
	attribution request.Attribution
	owner       OwnerIdentity
	// limit is the bound of the parts with a source (DD_IAST_MAX_RANGE_COUNT).
	limit       int
	attributed  int
	count       int
	parts       [MaxTaintedParts]tainted
	sourceCount int
	sourceBytes int
	sources     [MaxSources]Source
	// strong is true when at least one part with a source has a strong
	// match (see [request.Segment.Strong]).
	strong bool
}

func newCollector() *collector {
	c := new(collector)
	c.limit = rangeLimit()
	return c
}

// rangeLimit returns the configured bound of the parts with a source.
func rangeLimit() int {
	limit := config.MaxRangeCount
	if limit < 1 {
		return 1
	}
	if limit > MaxAttributedParts {
		return MaxAttributedParts
	}
	return int(limit)
}

// addAttribution adds the segments of c.attribution, for a value at offset
// in the value of the collection.
func (c *collector) addAttribution(offset uint32) {
	r := &c.attribution
	for index := 0; index < r.N; index++ {
		segment := r.Segments[index]
		source, ok := r.Source(index)
		if segment.Foreign || !ok {
			c.addForeign(offset+segment.Start, segment.Length)
			continue
		}
		c.addSource(offset+segment.Start, segment.Length, Source{Origin: source.Origin, Name: source.Name, Value: source.Value}, segment.Strong)
	}
	r.Reset()
}

// Segment is one tainted part of a value, for [Build].
type Segment struct {
	Start, Length uint32
	// Foreign is true when the bytes are not attributed to a source of the
	// owner. Source is then not used.
	Foreign bool
	// Weak is true when the segment has a source from a weak match (see
	// [request.Segment.Strong]). The zero value is a strong segment.
	Weak   bool
	Source Source
}

// Build assembles the snapshot of value for owner from segments, with the
// bounds of a collection: a segment that a bound does not permit is foreign.
// The segments must be in the order of Start; a segment that overlaps a
// previous segment is cut, a segment out of value is ignored. It returns
// StatusNone when no segment has a source with a strong match. A collection does the same work
// with the segments of the attribution of value.
func Build(owner OwnerIdentity, value string, segments []Segment) (*Snapshot, Status) {
	if len(value) == 0 || len(value) > MaxValueBytes {
		return nil, StatusNone
	}
	c := newCollector()
	c.owner = owner
	for _, segment := range segments {
		if segment.Start >= uint32(len(value)) {
			continue
		}
		length := min(segment.Length, uint32(len(value))-segment.Start)
		if segment.Foreign {
			c.addForeign(segment.Start, length)
		} else {
			c.addSource(segment.Start, length, segment.Source, !segment.Weak)
		}
	}
	return c.result(value)
}

// addSource adds an attributed part of length bytes at start; strong tells
// whether its match is strong. When a bound does not permit the part, the
// bytes are foreign: the report never shows them as clean evidence.
func (c *collector) addSource(start, length uint32, source Source, strong bool) {
	if length == 0 {
		return
	}
	if c.attributed >= c.limit {
		c.addForeign(start, length)
		return
	}
	index, ok := c.sourceIndex(source)
	if !ok {
		c.addForeign(start, length)
		return
	}
	if c.count > 0 {
		last := &c.parts[c.count-1]
		if last.source == index && last.end == start {
			last.end = start + length
			c.strong = c.strong || strong
			return
		}
	}
	// Keep one slot for a foreign tail (see addForeign).
	if c.count >= len(c.parts)-1 {
		c.addForeign(start, length)
		return
	}
	c.parts[c.count] = tainted{start: start, end: start + length, source: index}
	c.count++
	c.attributed++
	c.strong = c.strong || strong
}

// addForeign adds a foreign part of length bytes at start. When no slot is
// free, the last slot becomes one foreign part that covers all the bytes
// from its start to the end of the new part (clean bytes between them are
// then also redacted).
func (c *collector) addForeign(start, length uint32) {
	if length == 0 {
		return
	}
	end := start + length
	if c.count > 0 {
		last := &c.parts[c.count-1]
		if last.source < 0 && last.end >= start {
			last.end = max(last.end, end)
			return
		}
	}
	if c.count >= len(c.parts) {
		last := &c.parts[c.count-1]
		last.source = -1
		last.end = max(last.end, end)
		return
	}
	c.parts[c.count] = tainted{start: start, end: end, source: -1}
	c.count++
}

// sourceIndex returns the index of source in c.sources, and adds it when it
// is not there (equality is exact over Origin, Name and Value). It returns
// false when a bound does not permit a new source.
func (c *collector) sourceIndex(source Source) (int16, bool) {
	for index := 0; index < c.sourceCount; index++ {
		if c.sources[index] == source {
			return int16(index), true
		}
	}
	size := len(source.Name) + len(source.Value)
	if c.sourceCount >= len(c.sources) || size > MaxSnapshotBytes-c.sourceBytes {
		return 0, false
	}
	index := c.sourceCount
	c.sources[index] = Source{
		Origin: source.Origin,
		Name:   strings.Clone(source.Name),
		Value:  strings.Clone(source.Value),
	}
	c.sourceCount++
	c.sourceBytes += size
	return int16(index), true
}

// result returns the snapshot of value. It returns StatusNone when no part
// has a source of the owner with a strong match.
func (c *collector) result(value string) (*Snapshot, Status) {
	if c.attributed == 0 || !c.strong {
		return nil, StatusNone
	}
	return c.finish(value), StatusCollected
}

func (c *collector) finish(value string) *Snapshot {
	snapshot := &Snapshot{
		value: strings.Clone(value),
		owner: c.owner,
	}
	collected := c.parts[:c.count]
	// The parts are in order already (values and segments are in order);
	// sort to stay safe with an unexpected input.
	slices.SortStableFunc(collected, func(left, right tainted) int {
		return cmp.Compare(left.start, right.start)
	})
	// The source indexes in the order of their first part.
	var remap [MaxSources]int16
	for index := range remap {
		remap[index] = -1
	}
	sources := make([]Source, 0, c.sourceCount)
	parts := make([]Part, 0, 2*len(collected)+1)
	length := uint32(len(value))
	position := uint32(0)
	for _, current := range collected {
		start, end := max(current.start, position), min(current.end, length)
		if start >= end {
			continue
		}
		if start > position {
			parts = append(parts, Part{Start: position, Length: start - position, Source: -1})
		}
		part := Part{Start: start, Length: end - start, Source: -1, Foreign: true}
		if current.source >= 0 {
			mapped := remap[current.source]
			if mapped < 0 {
				mapped = int16(len(sources))
				remap[current.source] = mapped
				sources = append(sources, c.sources[current.source])
				snapshot.sourceBytes += uint32(len(c.sources[current.source].Name) + len(c.sources[current.source].Value))
			}
			part = Part{Start: start, Length: end - start, Source: mapped}
		}
		parts = append(parts, part)
		position = end
	}
	if position < length {
		parts = append(parts, Part{Start: position, Length: length - position, Source: -1})
	}
	snapshot.sources = sources
	snapshot.parts = parts
	return snapshot
}

// Value returns the report-owned evidence value.
func (s *Snapshot) Value() string {
	if s == nil {
		return ""
	}
	return s.value
}

// Owner returns the request owner of the snapshot.
func (s *Snapshot) Owner() (OwnerIdentity, bool) {
	if s == nil {
		return OwnerIdentity{}, false
	}
	return s.owner, true
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
