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

// Callbacks are the JSON callbacks. The iast/encoding/json package registers
// them during package initialization.
type Callbacks struct {
	// Literal publishes a decoded typed string and its exact source token.
	Literal func(document, item []byte, value reflect.Value, err error)
	// Owner returns the exclusive owner token of reader (ReaderBinding.Capture,
	// before the first byte of reader flows). The token is OK only when a
	// complete lookup finds exactly one owner of reader, with an effectively
	// exclusive binding (plan encoding-json-v2, section 6.5).
	Owner func(reader any) OwnerToken
	// Clone revalidates token for reader (plan encoding-json-v2, section 6.5,
	// rule (f)), and then adopts an exact-length clone of data into the owner
	// of token only. proven is false when the revalidation fails. When proven
	// is true and clone is nil, it is a miss for this data only (for example
	// data larger than the root limit).
	Clone func(reader any, token OwnerToken, data []byte) (clone []byte, proven bool)
	// MayBeTainted reports whether the store filter matches data. A false
	// result proves that data has no taint. It does no lookup and no lock.
	MayBeTainted func(data []byte) bool
}

// OwnerToken is the exclusive owner of a reader at one lookup. Only the
// request package makes it and reads its fields: they are a copy of a store
// reader token. Store holds a pointer, thus a token needs no allocation. The
// zero value is not OK.
type OwnerToken struct {
	Store      any
	Generation uint64
	Index      uint8
	Entry      uint8
	OK         bool
}

// The states of a ReaderBinding.
const (
	// bindingNone: Capture did not run while a request was active and a
	// decoder consumer was installed. The decoder never propagates.
	bindingNone uint8 = iota
	// bindingExclusive: Capture found one exclusive owner of the reader.
	bindingExclusive
	// bindingClosed: a proof failed. The state is sticky: the decoder never
	// propagates again.
	bindingClosed
)

// ReaderBinding is the owner of the reader of one json.Decoder (plan
// encoding-json-v2, sections 6.1 and 6.3). An aspect adds it as a field to
// json.Decoder. NewDecoder calls Capture BEFORE the first byte of the reader
// flows. Each Decode revalidates the captured token AFTER the bytes of the
// value flowed, before it attributes them. The zero value never propagates.
//
// A Decoder is not safe for concurrent use, thus the fields have no lock.
type ReaderBinding struct {
	reader     any
	store      any
	generation uint64
	index      uint8
	entry      uint8
	state      uint8
}

// Capture takes the exclusive owner token of reader. Call it once, when the
// decoder is made, before the first byte of reader flows. It returns at once
// (the state stays "none") when no decoder consumer of the token is
// installed (EnableV1, EnableV2), or when no request is active. Thus a
// decoder of a variant that does not use the token does no lookup. Else the
// state becomes "exclusive" only when the Owner callback proves one
// exclusive owner, and "closed" in all other cases.
func (b *ReaderBinding) Capture(reader any) {
	if consumers.Load() != 0 && active() {
		b.capture(reader)
	}
}

//go:noinline
func (b *ReaderBinding) capture(reader any) {
	if b == nil {
		return
	}
	*b = ReaderBinding{state: bindingClosed}
	callback := registered.Load()
	if callback == nil || reader == nil {
		return
	}
	token := ownerSlow(callback, reader)
	if !token.OK || token.Store == nil {
		return
	}
	*b = ReaderBinding{
		reader: reader, store: token.Store, generation: token.Generation,
		index: token.Index, entry: token.Entry, state: bindingExclusive,
	}
}

// clone revalidates the token of b and returns the clone of data that the
// Clone callback adopted into the owner of the token. It returns nil when b
// is not exclusive, when the proof fails (then b becomes "closed"), or when
// the callback gives no clone of the same length as data.
func (b *ReaderBinding) clone(callback *Callbacks, data []byte) []byte {
	token := OwnerToken{Store: b.store, Generation: b.generation, Index: b.index, Entry: b.entry, OK: true}
	clone, proven := cloneSlow(callback, b.reader, token, data)
	if !proven {
		// Sticky: release the references, the decoder never propagates
		// again.
		*b = ReaderBinding{state: bindingClosed}
		return nil
	}
	if len(clone) != len(data) {
		return nil
	}
	return clone
}

// ReaderDocument returns an immutable clone of value that the owner of b
// adopted, or value itself. The v2 Decode aspect calls it for the value bytes
// of each Decode (plan encoding-json-v2, section 6.3). It returns value
// unless EnableV2 ran, a request is active, and b is exclusive. It does not
// need an indexed root: the clone can be the first root of the request.
func ReaderDocument[V ~[]byte](b *ReaderBinding, value V) V {
	if consumers.Load()&consumerV2 == 0 || b == nil || b.state != bindingExclusive || !active() {
		return value
	}
	callback := registered.Load()
	if callback == nil {
		return value
	}
	if clone := b.clone(callback, []byte(value)); clone != nil {
		return V(clone)
	}
	return value
}

// The decoder consumers of the owner token that NewDecoder captures (bits of
// consumers).
const (
	// consumerV1: the v1 Document path (BindDecoder) uses the token.
	consumerV1 uint32 = 1 << iota
	// consumerV2: the v2 Decode path (ReaderDocument) uses the token.
	consumerV2
)

// consumers holds the decoder consumers that the variant of encoding/json
// installed. When it is zero, Capture does no lookup: no code uses the token.
var consumers atomic.Uint32

// EnableV1 tells the bridge that the v1 Document path of encoding/json uses
// the owner token of NewDecoder. Only the init function that the v1 aspect
// injects calls it.
func EnableV1() { consumers.Or(consumerV1) }

// EnableV2 tells the bridge that encoding/json is the v2-backed variant, and
// that its Decode uses the owner token of NewDecoder. Only the init function
// that the Go 1.27 v2 aspect injects calls it.
func EnableV2() { consumers.Or(consumerV2) }

// SetV1ForTest sets the v1 consumer flag until restore is called. Only tests
// call it.
func SetV1ForTest(enabled bool) (restore func()) { return setConsumerForTest(consumerV1, enabled) }

// SetV2ForTest sets the v2 flag until restore is called. Only tests call it.
func SetV2ForTest(enabled bool) (restore func()) { return setConsumerForTest(consumerV2, enabled) }

func setConsumerForTest(bit uint32, enabled bool) (restore func()) {
	set := func(on bool) {
		if on {
			consumers.Or(bit)
		} else {
			consumers.And(^bit)
		}
	}
	previous := consumers.Load()&bit != 0
	set(enabled)
	return func() { set(previous) }
}

// Active reports whether a request is active and the process has an indexed
// root. The v2 string wrapper uses it as its cheap gate.
func Active() bool { return active() && hasValues() }

// String publishes a decoded string and its raw JSON token (with the quotes)
// to the Literal callback. The v2 string wrapper calls it. raw must be the
// exact token of value in the decoded input.
func String(raw []byte, value reflect.Value) {
	if len(raw) < 2 || raw[0] != '"' || !Active() {
		return
	}
	if callback := registered.Load(); callback != nil {
		literalSlow(callback, raw, raw, value, nil)
	}
}

// HasIndexedRoots reports whether the process has an indexed root. It is the
// gate of the string cache guard of encoding/json/v2 (plan encoding-json-v2,
// section 6.2, "String cache"): the guard calls SkipCache only when it is
// true. The runtime gate has the same value (the store changes both at the
// same time). With the gate off, the runtime hooks do not taint. It is
// inlinable: two loads, no call.
func HasIndexedRoots() bool { return hasValues() }

// SkipCache reports whether makeString of encoding/json/v2 must not use its
// string cache for the unquoted string bytes b (plan encoding-json-v2,
// section 6.2, "String cache"). Call it only when HasIndexedRoots is true.
// The runtime hooks taint string(b) when b has taint. The cache of a pooled
// decoder keeps that string for later decodes, in this request and in other
// requests. Thus a later decode of clean bytes could get a tainted string: a
// false source. When SkipCache is true, makeString returns string(b) and does
// not read or change the cache.
//
// The result is the store filter of b: it is never false for tainted bytes.
// No indexed root, or fewer than 2 bytes, gives false. A missing callback or
// a panic gives true (fail closed: the cost is one allocation, the result is
// correct).
//
//go:noinline
func SkipCache(b []byte) (skip bool) {
	if len(b) < 2 || !hasValues() {
		// The runtime hooks do not taint a string of fewer than 2 bytes,
		// and makeString does not cache it. With no indexed root, no bytes
		// have taint.
		return false
	}
	defer shield()
	skip = true
	if callback := registered.Load(); callback != nil {
		skip = callback.MayBeTainted(b)
	}
	return skip
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
	binding  atomic.Pointer[ReaderBinding]
	document atomic.Pointer[document]
	quoted   atomic.Pointer[quotedLiteral]
}

var registered atomic.Pointer[Callbacks]
var activeOwners atomic.Pointer[atomic.Uint64]
var activeValues atomic.Pointer[atomic.Int32]
var decoderStates [64]decoderSlot

// BindActiveValues replaces the process active-value counter (the number of
// indexed roots of the process store) and returns the previous counter.
func BindActiveValues(values *atomic.Int32) *atomic.Int32 { return activeValues.Swap(values) }

// BindActiveOwners replaces the process request-owner bitset and returns the previous bitset.
func BindActiveOwners(owners *atomic.Uint64) *atomic.Uint64 { return activeOwners.Swap(owners) }

// Register installs the JSON callbacks. It does nothing when a callback is
// nil.
func Register(callbacks Callbacks) {
	if callbacks.Literal == nil || callbacks.Owner == nil || callbacks.Clone == nil || callbacks.MayBeTainted == nil {
		return
	}
	registered.Store(&callbacks)
}
func active() bool    { owners := activeOwners.Load(); return owners != nil && owners.Load() != 0 }
func hasValues() bool { values := activeValues.Load(); return values != nil && values.Load() != 0 }

// Bind adds one binding depth to the slot of state until the matching Unbind.
// A new slot has no reader binding. A nested Bind keeps the reader binding of
// the outer BindDecoder.
func Bind(state any) bool {
	if !active() {
		return false
	}
	return addDecoderState(pointerOf(state)) != nil
}

// BindDecoder associates state with the reader binding of a v1 decoder until
// the matching Unbind (plan encoding-json-v2, section 6.7). Document then uses
// the token that NewDecoder captured in binding. It returns false, and binds
// nothing, when binding is not exclusive: then Document cannot propagate.
func BindDecoder(binding *ReaderBinding, state any) bool {
	if binding == nil || binding.state != bindingExclusive || !active() {
		return false
	}
	slot := addDecoderState(pointerOf(state))
	if slot == nil {
		return false
	}
	slot.binding.Store(binding)
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
		slot.binding.Store(nil)
		if slot.depth.Load() == 0 {
			slot.pointer.CompareAndSwap(pointer, 0)
		}
		return
	}
}

// Document publishes data, a value that the v1 decoder of state read from
// its reader. The decodeState.init aspect calls it, after the bytes of data
// flowed. It clones data for the owner that NewDecoder captured, only when
// the token of that owner is still valid (ReaderBinding.clone).
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
	binding := slot.binding.Load()
	if binding == nil || binding.state != bindingExclusive {
		return
	}
	clone := binding.clone(callback, data)
	if clone == nil {
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

// ownerSlow calls the Owner callback. A panic gives the zero token (not OK).
//
//go:noinline
func ownerSlow(callback *Callbacks, reader any) (token OwnerToken) {
	defer shield()
	return callback.Owner(reader)
}

// cloneSlow calls the Clone callback. A panic gives proven = false: the
// decoder fails closed.
//
//go:noinline
func cloneSlow(callback *Callbacks, reader any, token OwnerToken, data []byte) (clone []byte, proven bool) {
	defer shield()
	return callback.Clone(reader, token, data)
}

//go:noinline
func literalSlow(callback *Callbacks, document, item []byte, value reflect.Value, err error) {
	defer shield()
	callback.Literal(document, item, value, err)
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
			slot.binding.Store(nil)
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
