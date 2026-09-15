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
	bind     func(any, any)
	document func(any, []byte) []byte
	literal  func([]byte, []byte, reflect.Value, error)
}
type document struct {
	original uintptr
	length   uint32
	clone    []byte
}
type decoderSlot struct {
	pointer  atomic.Uintptr
	depth    atomic.Uint32
	document atomic.Pointer[document]
}

var registered atomic.Pointer[callbacks]
var activeOwners atomic.Pointer[atomic.Uint64]
var activeValues atomic.Pointer[atomic.Int32]
var decoderStates [64]decoderSlot

func BindActiveValues(values *atomic.Int32) {
	if values != nil {
		activeValues.Store(values)
	}
}
func BindActiveOwners(owners *atomic.Uint64) {
	if owners != nil {
		activeOwners.Store(owners)
	}
}
func Register(bind func(any, any), document func(any, []byte) []byte, literal func([]byte, []byte, reflect.Value, error)) {
	registered.Store(&callbacks{bind: bind, document: document, literal: literal})
}
func active() bool    { owners := activeOwners.Load(); return owners != nil && owners.Load() != 0 }
func hasValues() bool { values := activeValues.Load(); return values != nil && values.Load() != 0 }

func Bind(reader, state any) bool {
	if !active() {
		return false
	}
	slot := addDecoderState(pointerOf(state))
	if slot == nil {
		return false
	}
	if callback := registered.Load(); callback != nil {
		bindSlow(callback, reader, state)
	}
	return true
}
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
		slot.document.Store(nil)
		if slot.depth.Load() == 0 {
			slot.pointer.CompareAndSwap(pointer, 0)
		}
		return
	}
}
func Document(state any, data []byte) {
	if !active() {
		return
	}
	slot := findDecoderState(pointerOf(state))
	callback := registered.Load()
	if slot == nil || callback == nil {
		return
	}
	clone := documentSlow(callback, state, data)
	if len(clone) != len(data) {
		slot.document.Store(nil)
		return
	}
	slot.document.Store(&document{original: slicePointer(data), length: uint32(len(data)), clone: clone})
}
func Literal(state any, original, item []byte, value reflect.Value, err error) {
	if !active() || !hasValues() {
		return
	}
	document, literal := original, item
	if slot := findDecoderState(pointerOf(state)); slot != nil {
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
func bindSlow(callback *callbacks, reader, state any) { defer shield(); callback.bind(reader, state) }

//go:noinline
func documentSlow(callback *callbacks, state any, data []byte) (result []byte) {
	defer shield()
	return callback.document(state, data)
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
			slot.document.Store(nil)
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
