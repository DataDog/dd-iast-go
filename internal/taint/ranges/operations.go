// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges

// Part is one value and its canonical taint ranges. A nil Ranges field denotes
// an untainted value.
type Part struct {
	Ranges *Set
	Length uint32
}

// Segment selects [Low, High) from one value. Compose concatenates selected
// segments in order. This can express exact replacement without embedding
// string-specific policy in the algebra package.
type Segment struct {
	Part
	Low  uint32
	High uint32
}

// Copy copies canonical ranges unchanged to a distinct value of the same size.
func Copy(dst *Set, limit Limit, source *Set, valueLen uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	if !validInput(source, valueLen) {
		reset(dst, limit)
		return Outcome{}
	}
	var builder orderedBuilder
	builder.init(limit)
	builder.appendSet(source, 0)
	return builder.publish(dst)
}

// Shift moves all source ranges by offset into a result of resultLen bytes.
func Shift(dst *Set, limit Limit, source *Set, sourceLen, offset, resultLen uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	end, ok := addLength(offset, sourceLen)
	if !ok || end > resultLen || !validInput(source, sourceLen) {
		reset(dst, limit)
		return Outcome{}
	}
	var builder orderedBuilder
	builder.init(limit)
	builder.appendSet(source, offset)
	return builder.publish(dst)
}

// Concat concatenates left and right and shifts right ranges by leftLen.
func Concat(dst *Set, limit Limit, left *Set, leftLen uint32, right *Set, rightLen uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	_, ok := addLength(leftLen, rightLen)
	if !ok || !validInput(left, leftLen) || !validInput(right, rightLen) {
		reset(dst, limit)
		return Outcome{}
	}
	var builder orderedBuilder
	builder.init(limit)
	builder.appendSet(left, 0)
	builder.appendSet(right, leftLen)
	return builder.publish(dst)
}

// Append is the range-algebra equivalent of appending the complete source after
// the complete destination.
func Append(dst *Set, limit Limit, base *Set, baseLen uint32, source *Set, sourceLen uint32) Outcome {
	return Concat(dst, limit, base, baseLen, source, sourceLen)
}

// Slice intersects source ranges with [low, high) and shifts them by -low.
func Slice(dst *Set, limit Limit, source *Set, sourceLen, low, high uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	if low > high || high > sourceLen || !validInput(source, sourceLen) {
		reset(dst, limit)
		return Outcome{}
	}
	var builder orderedBuilder
	builder.init(limit)
	builder.appendWindow(source, low, high, 0)
	return builder.publish(dst)
}

// Join concatenates elements and inserts separator between adjacent elements.
func Join(dst *Set, limit Limit, elements []Part, separator Part) Outcome {
	if dst == nil {
		return Outcome{}
	}
	if !validPart(separator) {
		reset(dst, limit)
		return Outcome{}
	}
	var total uint64
	for i, element := range elements {
		if !validPart(element) {
			reset(dst, limit)
			return Outcome{}
		}
		total += uint64(element.Length)
		if i+1 < len(elements) {
			total += uint64(separator.Length)
		}
		if total > uint64(^uint32(0)) {
			reset(dst, limit)
			return Outcome{}
		}
	}

	var builder orderedBuilder
	builder.init(limit)
	var offset uint32
	for i, element := range elements {
		builder.appendSet(element.Ranges, offset)
		offset += element.Length
		if i+1 < len(elements) {
			builder.appendSet(separator.Ranges, offset)
			offset += separator.Length
		}
		if builder.truncated {
			break
		}
	}
	return builder.publish(dst)
}

// Repeat concatenates count copies of source.
func Repeat(dst *Set, limit Limit, source *Set, sourceLen uint32, count int) Outcome {
	if dst == nil {
		return Outcome{}
	}
	if count < 0 || !validInput(source, sourceLen) {
		reset(dst, limit)
		return Outcome{}
	}
	if count == 0 || sourceLen == 0 || source == nil || source.Len() == 0 {
		reset(dst, limit)
		return Outcome{Valid: true}
	}
	if uint64(count) > uint64(^uint32(0))/uint64(sourceLen) {
		reset(dst, limit)
		return Outcome{}
	}
	total := uint64(sourceLen) * uint64(count)
	if source.count == 1 {
		r := source.items[0]
		end, _ := checkedEnd(r)
		if r.Start == 0 && end == sourceLen {
			r.Length = uint32(total)
			return AdoptCanonical(dst, limit, []Range{r}, uint32(total))
		}
	}

	var builder orderedBuilder
	builder.init(limit)
	for i := 0; i < count; i++ {
		builder.appendSet(source, uint32(uint64(sourceLen)*uint64(i)))
		if builder.invalid || builder.truncated {
			break
		}
	}
	return builder.publish(dst)
}

// Compose concatenates selected source segments. It is the primitive used by
// exact replace operations after the caller identifies copied and replacement
// spans.
func Compose(dst *Set, limit Limit, segments []Segment) Outcome {
	if dst == nil {
		return Outcome{}
	}
	var total uint64
	for _, segment := range segments {
		if !validPart(segment.Part) || segment.Low > segment.High || segment.High > segment.Length {
			reset(dst, limit)
			return Outcome{}
		}
		total += uint64(segment.High - segment.Low)
		if total > uint64(^uint32(0)) {
			reset(dst, limit)
			return Outcome{}
		}
	}
	var builder orderedBuilder
	builder.init(limit)
	var offset uint32
	for _, segment := range segments {
		builder.appendWindow(segment.Ranges, segment.Low, segment.High, offset)
		offset += segment.High - segment.Low
		if builder.truncated {
			break
		}
	}
	return builder.publish(dst)
}

// Clear removes provenance in [low, high) while preserving all other bytes.
// The value length does not change.
func Clear(dst *Set, limit Limit, source *Set, valueLen, low, high uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	if low > high || high > valueLen || !validInput(source, valueLen) {
		reset(dst, limit)
		return Outcome{}
	}
	var builder orderedBuilder
	builder.init(limit)
	builder.appendBefore(source, low)
	builder.appendAfter(source, high)
	return builder.publish(dst)
}

// Overwrite replaces n bytes at destinationOffset with n bytes selected from
// source at sourceOffset. Inputs are immutable snapshots, so base and source
// may be the same set for overlapping Go copy semantics.
func Overwrite(dst *Set, limit Limit, base *Set, baseLen uint32, destinationOffset uint32, source *Set, sourceLen uint32, sourceOffset, n uint32) Outcome {
	if dst == nil {
		return Outcome{}
	}
	destinationEnd, destinationOK := addLength(destinationOffset, n)
	sourceEnd, sourceOK := addLength(sourceOffset, n)
	if !destinationOK || destinationEnd > baseLen || !sourceOK || sourceEnd > sourceLen ||
		!validInput(base, baseLen) || !validInput(source, sourceLen) {
		reset(dst, limit)
		return Outcome{}
	}
	var builder orderedBuilder
	builder.init(limit)
	builder.appendBefore(base, destinationOffset)
	builder.appendWindow(source, sourceOffset, sourceEnd, destinationOffset)
	builder.appendAfter(base, destinationEnd)
	return builder.publish(dst)
}

// Write is Overwrite with a source offset of zero. n is the number of bytes
// actually written, not necessarily the complete source length.
func Write(dst *Set, limit Limit, base *Set, baseLen uint32, destinationOffset uint32, source *Set, sourceLen, n uint32) Outcome {
	return Overwrite(dst, limit, base, baseLen, destinationOffset, source, sourceLen, 0, n)
}

// CopyOverwrite is an explicit name for pre-copy-snapshot overwrite semantics.
func CopyOverwrite(dst *Set, limit Limit, base *Set, baseLen uint32, destinationOffset uint32, source *Set, sourceLen uint32, sourceOffset, n uint32) Outcome {
	return Overwrite(dst, limit, base, baseLen, destinationOffset, source, sourceLen, sourceOffset, n)
}

// Coarse emits one whole-output range. The source is the first contributing
// range in input order. Marks are intersected across every contributing range.
func Coarse(dst *Set, limit Limit, outputLen uint32, inputs []Part) Outcome {
	if dst == nil {
		return Outcome{}
	}
	for _, input := range inputs {
		if !validPart(input) {
			reset(dst, limit)
			return Outcome{}
		}
	}
	var source SourceID
	var marks uint64
	found := false
	for _, input := range inputs {
		if input.Ranges == nil {
			continue
		}
		for i := 0; i < int(input.Ranges.count); i++ {
			r := input.Ranges.items[i]
			if !found {
				source = r.SourceID
				marks = r.Marks
				found = true
			} else {
				marks &= r.Marks
			}
		}
	}
	var result Set
	result.limit = normalizedLimit(limit)
	if found && outputLen > 0 {
		result.items[0] = Range{Length: outputLen, SourceID: source, Marks: marks}
		result.count = 1
	}
	*dst = result
	return Outcome{Valid: true}
}

type orderedBuilder struct {
	result    Set
	truncated bool
	invalid   bool
}

func (b *orderedBuilder) init(limit Limit) {
	b.result.limit = normalizedLimit(limit)
}

func (b *orderedBuilder) append(r Range) {
	if b.invalid || b.truncated || r.Length == 0 {
		return
	}
	_, ok := checkedEnd(r)
	if !ok || !validMarks(r.Marks) {
		b.invalid = true
		return
	}
	if b.result.count > 0 {
		previous := &b.result.items[b.result.count-1]
		previousEnd, _ := checkedEnd(*previous)
		if r.Start < previousEnd {
			b.invalid = true
			return
		}
		if r.Start == previousEnd && previous.SourceID == r.SourceID && previous.Marks == r.Marks {
			combined := uint64(previous.Length) + uint64(r.Length)
			if combined > uint64(^uint32(0)) {
				b.invalid = true
				return
			}
			previous.Length = uint32(combined)
			return
		}
	}
	if int(b.result.count) >= int(b.result.limit) {
		b.truncated = true
		return
	}
	b.result.items[b.result.count] = r
	b.result.count++
}

func (b *orderedBuilder) appendSet(source *Set, shift uint32) {
	if source == nil {
		return
	}
	for i := 0; i < int(source.count); i++ {
		r := source.items[i]
		start, ok := addLength(r.Start, shift)
		if !ok {
			b.invalid = true
			return
		}
		r.Start = start
		b.append(r)
		if b.invalid || b.truncated {
			return
		}
	}
}

func (b *orderedBuilder) appendWindow(source *Set, low, high, outputOffset uint32) {
	if source == nil || low == high {
		return
	}
	for i := 0; i < int(source.count); i++ {
		r := source.items[i]
		end, _ := checkedEnd(r)
		start := max(r.Start, low)
		clippedEnd := min(end, high)
		if start >= clippedEnd {
			continue
		}
		r.Start = outputOffset + (start - low)
		r.Length = clippedEnd - start
		b.append(r)
		if b.invalid || b.truncated {
			return
		}
	}
}

func (b *orderedBuilder) appendBefore(source *Set, endOffset uint32) {
	if source == nil || endOffset == 0 {
		return
	}
	for i := 0; i < int(source.count); i++ {
		r := source.items[i]
		if r.Start >= endOffset {
			return
		}
		end, _ := checkedEnd(r)
		r.Length = min(end, endOffset) - r.Start
		b.append(r)
		if b.invalid || b.truncated {
			return
		}
	}
}

func (b *orderedBuilder) appendAfter(source *Set, startOffset uint32) {
	if source == nil {
		return
	}
	for i := 0; i < int(source.count); i++ {
		r := source.items[i]
		end, _ := checkedEnd(r)
		if end <= startOffset {
			continue
		}
		if r.Start < startOffset {
			r.Start = startOffset
			r.Length = end - startOffset
		}
		b.append(r)
		if b.invalid || b.truncated {
			return
		}
	}
}

func (b *orderedBuilder) publish(dst *Set) Outcome {
	if b.invalid {
		reset(dst, b.result.limit)
		return Outcome{}
	}
	*dst = b.result
	return Outcome{Valid: true, Truncated: b.truncated}
}

func validPart(part Part) bool {
	return validInput(part.Ranges, part.Length)
}

func validInput(input *Set, valueLen uint32) bool {
	return input == nil || input.ValidFor(valueLen)
}

func addLength(left, right uint32) (uint32, bool) {
	result := left + right
	return result, result >= left
}
