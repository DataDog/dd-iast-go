// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package jsonbridge is the dependency-minimal bridge imported by encoding/json.
package jsonbridge

import (
	"reflect"
	"sync/atomic"
	"unsafe"
)

type callbacks struct {
	document func(any, []byte) []byte
	literal  func([]byte, []byte, reflect.Value, error)
}
type readerRef struct {
	value any
}
type document struct {
	original uintptr
	length   uint32
	clone    []byte
}
type quotedLiteral struct {
	original       uintptr
	documentLength uint32
	offset         uint32
	length         uint32
}
type decoderSlot struct {
	pointer  atomic.Uintptr
	depth    atomic.Uint32
	reader   atomic.Pointer[readerRef]
	document atomic.Pointer[document]
	quoted   atomic.Pointer[quotedLiteral]
}

var registered atomic.Pointer[callbacks]
var activeOwners atomic.Pointer[atomic.Uint64]
var activeValues atomic.Pointer[atomic.Int32]
var decoderStates [64]decoderSlot

// BindActiveValues replaces the process active-value counter and returns the previous counter.
func BindActiveValues(values *atomic.Int32) *atomic.Int32 { return activeValues.Swap(values) }

// BindActiveOwners replaces the process request-owner bitset and returns the previous bitset.
func BindActiveOwners(owners *atomic.Uint64) *atomic.Uint64 { return activeOwners.Swap(owners) }

// Register installs the JSON document and literal callbacks.
func Register(document func(any, []byte) []byte, literal func([]byte, []byte, reflect.Value, error)) {
	registered.Store(&callbacks{document: document, literal: literal})
}
func active() bool    { owners := activeOwners.Load(); return owners != nil && owners.Load() != 0 }
func hasValues() bool { values := activeValues.Load(); return values != nil && values.Load() != 0 }

// Bind associates state with reader until the matching Unbind.
func Bind(reader, state any) bool {
	if !active() {
		return false
	}
	slot := addDecoderState(pointerOf(state))
	if slot == nil {
		return false
	}
	if reader != nil {
		slot.reader.Store(&readerRef{value: reader})
	}
	return true
}

// Unbind releases one state binding depth and all state metadata at the final depth.
func Unbind(state any) {
	pointer := pointerOf(state)
	slot := findDecoderState(pointer)
	if slot == nil {
		return
	}
	for {
		depth := slot.depth.Load()
		if depth == 0 {
			return
		}
		if !slot.depth.CompareAndSwap(depth, depth-1) {
			continue
		}
		if depth > 1 {
			return
		}
		slot.quoted.Store(nil)
		slot.document.Store(nil)
		slot.reader.Store(nil)
		if slot.depth.Load() == 0 {
			slot.pointer.CompareAndSwap(pointer, 0)
		}
		return
	}
}

// Document publishes data read by the reader associated with state.
func Document(state any, data []byte) {
	if !active() {
		return
	}
	slot := findDecoderState(pointerOf(state))
	callback := registered.Load()
	if slot == nil || callback == nil {
		return
	}
	slot.document.Store(nil)
	reader := slot.reader.Load()
	if reader == nil {
		return
	}
	clone := documentSlow(callback, reader.value, data)
	if len(clone) != len(data) {
		return
	}
	slot.document.Store(&document{original: slicePointer(data), length: uint32(len(data)), clone: clone})
}

// Quoted records the outer token when valueQuoted returns an encoded string.
func Quoted(state any, original []byte, start, end int, result any) {
	slot := findDecoderState(pointerOf(state))
	if slot == nil {
		return
	}
	slot.quoted.Store(nil)
	if !active() || !hasValues() {
		return
	}
	encoded, ok := result.(string)
	// Null and invalid scalar tokens can leave a string destination unchanged.
	// Do not attribute that existing value to this token.
	if !ok || len(encoded) == 0 || encoded[0] != '"' {
		return
	}
	if start < 0 || start >= end || end > len(original) || uint64(len(original)) > uint64(^uint32(0)) {
		return
	}
	slot.quoted.Store(&quotedLiteral{
		original:       slicePointer(original),
		documentLength: uint32(len(original)),
		offset:         uint32(start),
		length:         uint32(end - start),
	})
}

// Literal publishes a decoded typed string and its exact source token.
func Literal(state any, original, item []byte, value reflect.Value, err error, fromQuoted bool) {
	slot := findDecoderState(pointerOf(state))
	var quoted *quotedLiteral
	if slot != nil {
		quoted = slot.quoted.Swap(nil)
	}
	if !active() || !hasValues() {
		return
	}
	if fromQuoted && quoted != nil && quoted.original == slicePointer(original) && quoted.documentLength == uint32(len(original)) {
		end := uint64(quoted.offset) + uint64(quoted.length)
		if end <= uint64(len(original)) {
			item = original[quoted.offset:end]
		}
	}
	document, literal := original, item
	if slot != nil {
		if mapped := slot.document.Load(); mapped != nil && mapped.original == slicePointer(original) && mapped.length == uint32(len(original)) {
			offset := slicePointer(item) - mapped.original
			if offset <= uintptr(len(mapped.clone)) && uintptr(len(item)) <= uintptr(len(mapped.clone))-offset {
				document = mapped.clone
				literal = mapped.clone[offset : offset+uintptr(len(item))]
			}
		}
	}
	if callback := registered.Load(); callback != nil {
		literalSlow(callback, document, literal, value, err)
	}
}

//go:noinline
func documentSlow(callback *callbacks, reader any, data []byte) (result []byte) {
	defer shield()
	return callback.document(reader, data)
}

//go:noinline
func literalSlow(callback *callbacks, document, item []byte, value reflect.Value, err error) {
	defer shield()
	callback.literal(document, item, value, err)
}
func pointerOf(value any) uintptr {
	reflection := reflect.ValueOf(value)
	if !reflection.IsValid() || reflection.Kind() != reflect.Pointer || reflection.IsNil() {
		return 0
	}
	return reflection.Pointer()
}
func slicePointer(value []byte) uintptr {
	if len(value) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(value)))
}
func addDecoderState(pointer uintptr) *decoderSlot {
	if pointer == 0 {
		return nil
	}
	start := int((pointer >> 3) % uintptr(len(decoderStates)))
	for probe := 0; probe < 4; probe++ {
		slot := &decoderStates[(start+probe)%len(decoderStates)]
		if slot.pointer.Load() == pointer {
			slot.depth.Add(1)
			return slot
		}
		if slot.pointer.CompareAndSwap(0, 1) {
			slot.reader.Store(nil)
			slot.document.Store(nil)
			slot.quoted.Store(nil)
			slot.depth.Store(1)
			slot.pointer.Store(pointer)
			return slot
		}
	}
	return nil
}
func findDecoderState(pointer uintptr) *decoderSlot {
	if pointer == 0 {
		return nil
	}
	start := int((pointer >> 3) % uintptr(len(decoderStates)))
	for probe := 0; probe < 4; probe++ {
		slot := &decoderStates[(start+probe)%len(decoderStates)]
		if slot.pointer.Load() == pointer {
			return slot
		}
	}
	return nil
}
func shield() { _ = recover() }
