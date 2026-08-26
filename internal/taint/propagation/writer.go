// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"strings"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
)

func init() {
	writerbridge.Register(invalidateWriterPointer)
}

// WriterActive reports whether at least one request analysis can own writer
// state. It is the cheap wrapper and standard-library invalidation gate.
func WriterActive() bool {
	return request.ActiveStore() != nil
}

// WriterInvalidationActive reports whether any request currently retains
// writer state that a standard-library mutation can invalidate.
func WriterInvalidationActive() bool {
	return writerbridge.Active()
}

func invalidateWriterPointer(pointer uintptr) {
	if s := request.ActiveStore(); s != nil {
		s.InvalidateWriterPointer(pointer)
	}
}

// UpdateStringWriter records one completed string write.
func UpdateStringWriter(object any, kind store.WriterKind, before, after store.WriterView, input string, written int) {
	if written < 0 || uint64(written) > uint64(^uint32(0)) || uint64(len(input)) > uint64(^uint32(0)) {
		ResetWriter(object, kind)
		return
	}
	s := request.ActiveStore()
	if s == nil {
		return
	}
	key, keyOK := store.StringKey(input)
	updateWriter(s, object, kind, before, after, key, keyOK, uint32(len(input)), uint32(written))
}

// UpdateBytesWriter records one completed byte-slice write.
func UpdateBytesWriter(object any, kind store.WriterKind, before, after store.WriterView, input []byte, written int) {
	if written < 0 || uint64(written) > uint64(^uint32(0)) || uint64(len(input)) > uint64(^uint32(0)) {
		ResetWriter(object, kind)
		return
	}
	s := request.ActiveStore()
	if s == nil {
		return
	}
	key, keyOK := store.BytesKey(input)
	updateWriter(s, object, kind, before, after, key, keyOK, uint32(len(input)), uint32(written))
}

// UpdateUntaintedWriter records one completed write with no taint-capable input.
func UpdateUntaintedWriter(object any, kind store.WriterKind, before, after store.WriterView, written int) {
	if written < 0 || uint64(written) > uint64(^uint32(0)) {
		ResetWriter(object, kind)
		return
	}
	s := request.ActiveStore()
	if s == nil {
		return
	}
	updateWriter(s, object, kind, before, after, store.Key{}, false, uint32(written), uint32(written))
}

func updateWriter(s *store.Store, object any, kind store.WriterKind, before, after store.WriterView, key store.Key, keyOK bool, inputLength, written uint32) {
	var input store.Snapshot
	if keyOK && s.MayContain(key) {
		s.Lookup(key, &input)
	}
	var refs [store.MaxSnapshotOwners]store.WriterRef
	refCount := store.LookupWriterValue(s, object, kind, refs[:])
	var seen [store.MaxSnapshotOwners]writerIdentity
	seenCount := 0
	for refIndex := 0; refIndex < refCount; refIndex++ {
		ref := refs[refIndex]
		owner, ok := ref.Handle()
		if !ok {
			continue
		}
		index, generation, ok := ref.Identity()
		if !ok {
			continue
		}
		seen[seenCount] = writerIdentity{index: index, generation: generation}
		seenCount++
		inputRanges := snapshotOwnerRanges(&input, index, generation)
		owner.UpdateWriter(object, kind, before, after, inputRanges, inputLength, written)
	}
	for entryIndex := 0; entryIndex < input.Len(); entryIndex++ {
		entry, ok := input.At(entryIndex)
		if !ok || containsWriterIdentity(seen[:seenCount], entry.OwnerIndex, entry.OwnerGen) {
			continue
		}
		owner, ok := entry.Handle(s)
		if !ok {
			continue
		}
		owner.UpdateWriter(object, kind, before, after, &entry.Ranges, inputLength, written)
	}
}

type writerIdentity struct {
	index      uint8
	generation uint64
}

func containsWriterIdentity(values []writerIdentity, index uint8, generation uint64) bool {
	for _, value := range values {
		if value.index == index && value.generation == generation {
			return true
		}
	}
	return false
}

func snapshotOwnerRanges(snapshot *store.Snapshot, index uint8, generation uint64) *ranges.Set {
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, ok := snapshot.At(entryIndex)
		if ok && entry.OwnerIndex == index && entry.OwnerGen == generation {
			return &entry.Ranges
		}
	}
	return nil
}

// ResetWriter removes every active-owner state for object.
func ResetWriter(object any, kind store.WriterKind) {
	s := request.ActiveStore()
	if s == nil {
		return
	}
	var refs [store.MaxSnapshotOwners]store.WriterRef
	count := store.LookupWriterValue(s, object, kind, refs[:])
	for index := 0; index < count; index++ {
		if owner, ok := refs[index].Handle(); ok {
			owner.ResetWriter(object, kind)
		}
	}
}

// TruncateWriter applies one completed truncation to every active owner.
func TruncateWriter(object any, kind store.WriterKind, before, after store.WriterView) {
	s := request.ActiveStore()
	if s == nil {
		return
	}
	var refs [store.MaxSnapshotOwners]store.WriterRef
	count := store.LookupWriterValue(s, object, kind, refs[:])
	for index := 0; index < count; index++ {
		if owner, ok := refs[index].Handle(); ok {
			owner.TruncateWriter(object, kind, before, after)
		}
	}
}

// BuilderString clones and publishes one strings.Builder result.
func BuilderString(object any, view store.WriterView, result string) string {
	if len(result) < 2 || len(result) > store.MaxRootBytes {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	return publishWriterString(s, object, store.WriterStringBuilder, view, result, true)
}

// BufferString adopts and publishes one audited fresh bytes.Buffer.String result.
func BufferString(object any, view store.WriterView, result string) string {
	if len(result) < 2 || len(result) > store.MaxRootBytes {
		return result
	}
	s := request.ActiveStore()
	if s == nil {
		return result
	}
	return publishWriterString(s, object, store.WriterBytesBuffer, view, result, false)
}

//go:noinline
func publishWriterString(s *store.Store, object any, kind store.WriterKind, view store.WriterView, result string, clone bool) string {
	var refs [store.MaxSnapshotOwners]store.WriterRef
	count := store.LookupWriterValue(s, object, kind, refs[:])
	if count == 0 {
		return result
	}
	published := result
	if clone {
		published = strings.Clone(result)
	}
	for index := 0; index < count; index++ {
		owner, ok := refs[index].Handle()
		if !ok {
			continue
		}
		var set ranges.Set
		if !owner.SnapshotWriter(object, kind, view, &set) || !set.ValidFor(uint32(len(published))) {
			continue
		}
		owner.AdoptString(published, &set)
	}
	return published
}
