// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bridgetests_test

import (
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/stretchr/testify/require"
)

// activate makes the bridge see one active request and one indexed root,
// with the v1 decoder consumer installed (as the woven v1 variant does), so
// that Capture looks up the reader.
func activate(t *testing.T) {
	t.Helper()
	t.Cleanup(jsonbridge.SetV1ForTest(true))
	var owners atomic.Uint64
	owners.Store(1)
	previousOwners := jsonbridge.BindActiveOwners(&owners)
	var values atomic.Int32
	values.Store(1)
	previousValues := jsonbridge.BindActiveValues(&values)
	t.Cleanup(func() {
		jsonbridge.BindActiveOwners(previousOwners)
		jsonbridge.BindActiveValues(previousValues)
	})
}

// fakeCallbacks records the calls of the bridge. It registers itself, and
// restores the default callbacks of the tests at cleanup.
type fakeCallbacks struct {
	token       jsonbridge.OwnerToken
	clone       func(reader any, token jsonbridge.OwnerToken, data []byte) ([]byte, bool)
	ownerPanics bool

	ownerCalls, cloneCalls  int
	ownerReader, cloneInput any
	cloneToken              jsonbridge.OwnerToken
	literalDocument         []byte
	literalItem             []byte
	literalErr              error
	literalCalls            int
	filterCalls             int
	filterInput             []byte
	filterResult            bool
	filterPanics            bool
}

func register(t *testing.T, fake *fakeCallbacks) {
	t.Helper()
	jsonbridge.Register(jsonbridge.Callbacks{
		Literal: func(document, item []byte, _ reflect.Value, err error) {
			fake.literalCalls++
			fake.literalDocument, fake.literalItem, fake.literalErr = document, item, err
		},
		Owner: func(reader any) jsonbridge.OwnerToken {
			fake.ownerCalls++
			fake.ownerReader = reader
			if fake.ownerPanics {
				panic("owner")
			}
			return fake.token
		},
		Clone: func(reader any, token jsonbridge.OwnerToken, data []byte) ([]byte, bool) {
			fake.cloneCalls++
			fake.cloneInput, fake.cloneToken = reader, token
			if fake.clone == nil {
				return append([]byte(nil), data...), true
			}
			return fake.clone(reader, token, data)
		},
		MayBeTainted: func(data []byte) bool {
			fake.filterCalls++
			fake.filterInput = data
			if fake.filterPanics {
				panic("filter")
			}
			return fake.filterResult
		},
	})
}

// okToken returns a token with the store marker of the tests.
func okToken() jsonbridge.OwnerToken {
	return jsonbridge.OwnerToken{Store: storeMarker, Generation: 7, Index: 3, Entry: 2, OK: true}
}

var storeMarker = new(int)

// exclusiveBinding returns a binding that Capture made exclusive for reader.
func exclusiveBinding(t *testing.T, fake *fakeCallbacks, reader any) *jsonbridge.ReaderBinding {
	t.Helper()
	fake.token = okToken()
	binding := new(jsonbridge.ReaderBinding)
	binding.Capture(reader)
	require.Same(t, reader, fake.ownerReader)
	return binding
}

func TestRegisterIgnoresIncompleteCallbacks(t *testing.T) {
	activate(t)
	fake := &fakeCallbacks{}
	register(t, fake)
	jsonbridge.Register(jsonbridge.Callbacks{Literal: func([]byte, []byte, reflect.Value, error) {}})
	// All callbacks but MayBeTainted: also incomplete.
	jsonbridge.Register(jsonbridge.Callbacks{
		Literal: func([]byte, []byte, reflect.Value, error) {},
		Owner:   func(any) jsonbridge.OwnerToken { return jsonbridge.OwnerToken{} },
		Clone:   func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return nil, false },
	})
	binding := new(jsonbridge.ReaderBinding)
	binding.Capture(new(int))
	require.Equal(t, 1, fake.ownerCalls, "an incomplete set must not replace the callbacks")
}

func TestDecoderCallbacks(t *testing.T) {
	activate(t)
	original := []byte(`{"value":"attack"}`)
	clone := append([]byte(nil), original...)
	fake := &fakeCallbacks{clone: func(_ any, _ jsonbridge.OwnerToken, data []byte) ([]byte, bool) {
		return clone[:len(data)], true
	}}
	register(t, fake)
	state := new(int)
	reader := new(int)
	binding := exclusiveBinding(t, fake, reader)

	require.False(t, jsonbridge.Bind(nil))
	require.True(t, jsonbridge.BindDecoder(binding, state))
	jsonbridge.Document(state, original)
	require.Equal(t, 1, fake.cloneCalls)
	require.Same(t, reader, fake.cloneInput)
	require.Equal(t, okToken(), fake.cloneToken)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, nil, false)
	require.Equal(t, clone, fake.literalDocument)
	require.Equal(t, clone[9:17], fake.literalItem)
	require.Same(t, unsafe.SliceData(clone), unsafe.SliceData(fake.literalDocument))
	require.Same(t, unsafe.SliceData(clone[9:17]), unsafe.SliceData(fake.literalItem))

	// A nested direct-unmarshal binding must keep the reader binding of the
	// decoder.
	require.True(t, jsonbridge.Bind(state))
	jsonbridge.Document(state, original)
	require.Equal(t, 2, fake.cloneCalls)
	require.Same(t, reader, fake.cloneInput)
	jsonbridge.Unbind(state)
	jsonbridge.Unbind(state)

	// The final unbind releases the binding, the document, and the
	// callback eligibility.
	jsonbridge.Document(state, original)
	require.Equal(t, 2, fake.cloneCalls)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, nil, false)
	require.Same(t, unsafe.SliceData(original), unsafe.SliceData(fake.literalDocument))

	// A slot from Bind only has no reader binding.
	require.True(t, jsonbridge.Bind(state))
	jsonbridge.Document(state, original)
	require.Equal(t, 2, fake.cloneCalls)
	jsonbridge.Unbind(state)

	// A reused state binds only the new binding, and a failed publication
	// clears the document.
	cleanReader := new(int)
	cleanBinding := exclusiveBinding(t, fake, cleanReader)
	fake.clone = func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return nil, true }
	require.True(t, jsonbridge.BindDecoder(cleanBinding, state))
	jsonbridge.Document(state, original)
	require.Same(t, cleanReader, fake.cloneInput)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, errors.New("decode"), false)
	require.EqualError(t, fake.literalErr, "decode")
	require.Same(t, unsafe.SliceData(original), unsafe.SliceData(fake.literalDocument))
	jsonbridge.Unbind(state)
}

func TestDecoderCallbacksQuotedIdentityAndCleanup(t *testing.T) {
	activate(t)
	original := []byte(`{"a":"\"same\"","b":"\"same\""}`)
	clone := append([]byte(nil), original...)
	second := strings.LastIndex(string(original), `"\"same\""`)
	require.NotEqual(t, -1, second)
	fake := &fakeCallbacks{clone: func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return clone, true }}
	register(t, fake)
	state := new(int)
	reader := new(int)
	binding := exclusiveBinding(t, fake, reader)
	require.True(t, jsonbridge.BindDecoder(binding, state))
	jsonbridge.Document(state, original)
	jsonbridge.Quoted(state, original, second, second+len(`"\"same\""`), `"same"`)
	jsonbridge.Literal(state, original, []byte(`"same"`), reflect.Value{}, nil, true)
	require.Same(t, unsafe.SliceData(clone), unsafe.SliceData(fake.literalDocument))
	require.Same(t, unsafe.SliceData(clone[second:]), unsafe.SliceData(fake.literalItem))

	// A failed oversized publication clears the prior clone mapping, and
	// keeps the binding open.
	fake.clone = func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return nil, true }
	jsonbridge.Document(state, make([]byte, 1<<20))
	jsonbridge.Literal(state, original, original[second:second+len(`"\"same\""`)], reflect.Value{}, nil, false)
	require.Same(t, unsafe.SliceData(original), unsafe.SliceData(fake.literalDocument))
	jsonbridge.Unbind(state)
	require.True(t, jsonbridge.BindDecoder(binding, state), "a miss for one value must not close the binding")
	jsonbridge.Unbind(state)

	// Panicking callbacks are shielded. A panic in Clone closes the binding.
	jsonbridge.Register(jsonbridge.Callbacks{
		Literal: func([]byte, []byte, reflect.Value, error) { panic("literal") },
		Owner:   func(any) jsonbridge.OwnerToken { panic("owner") },
		Clone:   func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { panic("clone") },
		// MayBeTainted is necessary for a complete set.
		MayBeTainted: func([]byte) bool { panic("filter") },
	})
	require.True(t, jsonbridge.BindDecoder(binding, state))
	require.NotPanics(t, func() { jsonbridge.Document(state, original) })
	jsonbridge.Quoted(state, original, second, second+len(`"\"same\""`), `"same"`)
	require.NotPanics(t, func() { jsonbridge.Literal(state, original, []byte(`"same"`), reflect.Value{}, nil, true) })
	jsonbridge.Unbind(state)
	require.False(t, jsonbridge.BindDecoder(binding, state), "a panic in Clone must close the binding")

	fake = &fakeCallbacks{}
	register(t, fake)
	cleanReader := new(int)
	cleanBinding := exclusiveBinding(t, fake, cleanReader)
	fake.clone = func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return nil, true }
	require.True(t, jsonbridge.BindDecoder(cleanBinding, state))
	jsonbridge.Document(state, original)
	require.Same(t, cleanReader, fake.cloneInput)
	jsonbridge.Literal(state, original, original[second:second+len(`"\"same\""`)], reflect.Value{}, nil, true)
	require.Same(t, unsafe.SliceData(original), unsafe.SliceData(fake.literalDocument))
	jsonbridge.Unbind(state)
}

func TestDecoderCallbacksInactive(t *testing.T) {
	previousOwners := jsonbridge.BindActiveOwners(nil)
	previousValues := jsonbridge.BindActiveValues(nil)
	t.Cleanup(func() {
		jsonbridge.BindActiveOwners(previousOwners)
		jsonbridge.BindActiveValues(previousValues)
	})
	t.Cleanup(jsonbridge.SetV1ForTest(true))
	fake := &fakeCallbacks{token: okToken()}
	register(t, fake)
	state := new(int)
	require.False(t, jsonbridge.Bind(state))
	binding := new(jsonbridge.ReaderBinding)
	binding.Capture(new(int))
	require.Zero(t, fake.ownerCalls, "Capture must not look up a reader when no request is active")
	require.False(t, jsonbridge.BindDecoder(binding, state))
	jsonbridge.Document(state, []byte("inactive"))
	jsonbridge.Quoted(state, []byte(`"inactive"`), 0, 10, "inactive")
	jsonbridge.Literal(state, nil, nil, reflect.Value{}, nil, false)
	jsonbridge.String([]byte(`"inactive"`), reflect.Value{})
	fake.filterResult = true
	require.False(t, jsonbridge.HasIndexedRoots())
	require.False(t, jsonbridge.SkipCache([]byte("inactive")), "SkipCache must be false with no indexed root")
	require.False(t, jsonbridge.Active())
	require.Zero(t, fake.cloneCalls)
	require.Zero(t, fake.literalCalls)
	require.Zero(t, fake.filterCalls)
}

// TestCaptureNeedsAConsumer checks that Capture does no lookup, and does not
// allocate, while a request is active but no decoder consumer of the token
// is installed (Go 1.27 v2 variant before EnableV2). The binding stays
// "none": no Decode can use it.
func TestCaptureNeedsAConsumer(t *testing.T) {
	activate(t)
	t.Cleanup(jsonbridge.SetV1ForTest(false))
	t.Cleanup(jsonbridge.SetV2ForTest(false))
	fake := &fakeCallbacks{token: okToken()}
	register(t, fake)
	binding := new(jsonbridge.ReaderBinding)
	reader := any(new(int))
	require.Zero(t, testing.AllocsPerRun(100, func() { binding.Capture(reader) }))
	require.Zero(t, fake.ownerCalls, "Capture looked up a reader with no consumer of the token")
	require.False(t, jsonbridge.BindDecoder(binding, new(int)))

	// Control: each consumer makes Capture look up the reader.
	for name, enable := range map[string]func(bool) func(){
		"v1": jsonbridge.SetV1ForTest,
		"v2": jsonbridge.SetV2ForTest,
	} {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(enable(true))
			fake := &fakeCallbacks{token: okToken()}
			register(t, fake)
			binding := new(jsonbridge.ReaderBinding)
			binding.Capture(reader)
			require.Equal(t, 1, fake.ownerCalls)
			state := new(int)
			require.True(t, jsonbridge.BindDecoder(binding, state))
			jsonbridge.Unbind(state)
		})
	}
}

func TestCaptureStates(t *testing.T) {
	activate(t)
	restore := jsonbridge.SetV2ForTest(true)
	t.Cleanup(restore)
	value := []byte(`{"a":"b"}`)
	register(t, &fakeCallbacks{token: okToken()})
	require.NotPanics(t, func() { (*jsonbridge.ReaderBinding)(nil).Capture(new(int)) })
	for name, test := range map[string]struct {
		token       jsonbridge.OwnerToken
		reader      any
		ownerPanics bool
		exclusive   bool
	}{
		"exclusive owner":     {token: okToken(), reader: new(int), exclusive: true},
		"no owner":            {reader: new(int)},
		"token with no store": {token: jsonbridge.OwnerToken{Generation: 1, OK: true}, reader: new(int)},
		"nil reader":          {token: okToken()},
		"owner panics":        {token: okToken(), reader: new(int), ownerPanics: true},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeCallbacks{token: test.token, ownerPanics: test.ownerPanics}
			register(t, fake)
			binding := new(jsonbridge.ReaderBinding)
			require.NotPanics(t, func() { binding.Capture(test.reader) })
			got := jsonbridge.ReaderDocument(binding, value)
			state := new(int)
			bound := jsonbridge.BindDecoder(binding, state)
			if bound {
				jsonbridge.Unbind(state)
			}
			require.Equal(t, test.exclusive, bound)
			if test.exclusive {
				require.Equal(t, 1, fake.cloneCalls)
				require.NotSame(t, unsafe.SliceData(value), unsafe.SliceData(got))
				require.Equal(t, value, got)
				return
			}
			require.Zero(t, fake.cloneCalls, "a closed binding must not call Clone")
			require.Same(t, unsafe.SliceData(value), unsafe.SliceData(got))
		})
	}
}

// jsonValue has the shape of jsontext.Value: ReaderDocument is generic, so
// that the bridge does not import jsontext.
type jsonValue []byte

func TestReaderDocument(t *testing.T) {
	activate(t)
	value := jsonValue(`{"a":"b"}`)
	same := func(t *testing.T, got jsonValue) {
		t.Helper()
		require.Same(t, unsafe.SliceData(value), unsafe.SliceData(got), "ReaderDocument must return the original bytes")
	}

	t.Run("v2 flag off", func(t *testing.T) {
		restore := jsonbridge.SetV2ForTest(false)
		t.Cleanup(restore)
		fake := &fakeCallbacks{}
		register(t, fake)
		binding := exclusiveBinding(t, fake, new(int))
		same(t, jsonbridge.ReaderDocument(binding, value))
		require.Zero(t, fake.cloneCalls)
	})
	t.Run("nil and zero bindings", func(t *testing.T) {
		restore := jsonbridge.SetV2ForTest(true)
		t.Cleanup(restore)
		fake := &fakeCallbacks{}
		register(t, fake)
		same(t, jsonbridge.ReaderDocument(nil, value))
		same(t, jsonbridge.ReaderDocument(new(jsonbridge.ReaderBinding), value))
		require.Zero(t, fake.cloneCalls)
	})
	for name, test := range map[string]struct {
		clone     func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool)
		cloned    bool
		staysOpen bool
	}{
		"clone": {clone: func(_ any, _ jsonbridge.OwnerToken, data []byte) ([]byte, bool) {
			return append([]byte(nil), data...), true
		}, cloned: true, staysOpen: true},
		"bad token": {clone: func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return nil, false }},
		"bad token with a clone": {clone: func(_ any, _ jsonbridge.OwnerToken, data []byte) ([]byte, bool) {
			return append([]byte(nil), data...), false
		}},
		"oversized value": {clone: func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return nil, true }, staysOpen: true},
		"length mismatch": {clone: func(_ any, _ jsonbridge.OwnerToken, data []byte) ([]byte, bool) {
			return append([]byte(nil), data[1:]...), true
		}, staysOpen: true},
		"clone panics": {clone: func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { panic("clone") }},
	} {
		t.Run(name, func(t *testing.T) {
			restore := jsonbridge.SetV2ForTest(true)
			t.Cleanup(restore)
			fake := &fakeCallbacks{}
			register(t, fake)
			reader := new(int)
			binding := exclusiveBinding(t, fake, reader)
			fake.clone = test.clone
			var got jsonValue
			require.NotPanics(t, func() { got = jsonbridge.ReaderDocument(binding, value) })
			require.Equal(t, 1, fake.cloneCalls)
			require.Same(t, reader, fake.cloneInput)
			require.Equal(t, okToken(), fake.cloneToken)
			if test.cloned {
				require.Equal(t, value, got)
				require.NotSame(t, unsafe.SliceData(value), unsafe.SliceData(got))
			} else {
				same(t, got)
			}
			// A second value: an open binding calls Clone again, a closed
			// binding does not (the state is sticky).
			jsonbridge.ReaderDocument(binding, value)
			if test.staysOpen {
				require.Equal(t, 2, fake.cloneCalls)
			} else {
				require.Equal(t, 1, fake.cloneCalls)
				require.False(t, jsonbridge.BindDecoder(binding, new(int)))
			}
		})
	}
}

// TestReaderDocumentNeedsNoIndexedRoot checks that the clone is made when a
// request is active and the process has no indexed root: the body can be the
// first source of the request.
func TestReaderDocumentNeedsNoIndexedRoot(t *testing.T) {
	var owners atomic.Uint64
	owners.Store(1)
	previousOwners := jsonbridge.BindActiveOwners(&owners)
	var values atomic.Int32
	previousValues := jsonbridge.BindActiveValues(&values)
	t.Cleanup(func() {
		jsonbridge.BindActiveOwners(previousOwners)
		jsonbridge.BindActiveValues(previousValues)
	})
	restore := jsonbridge.SetV2ForTest(true)
	t.Cleanup(restore)
	fake := &fakeCallbacks{}
	register(t, fake)
	require.False(t, jsonbridge.Active())
	binding := exclusiveBinding(t, fake, new(int))
	value := []byte(`{"a":"b"}`)
	got := jsonbridge.ReaderDocument(binding, value)
	require.Equal(t, 1, fake.cloneCalls)
	require.NotSame(t, unsafe.SliceData(value), unsafe.SliceData(got))
	// String and SkipCache need an indexed root.
	jsonbridge.String([]byte(`"b"`), reflect.Value{})
	require.Zero(t, fake.literalCalls)
	fake.filterResult = true
	require.False(t, jsonbridge.SkipCache([]byte("bb")))
	require.Zero(t, fake.filterCalls)
}

// TestSkipCache checks the string cache guard of encoding/json/v2: with an
// indexed root, SkipCache returns the result of the MayBeTainted callback for
// b itself. A string of fewer than 2 bytes needs no check. A panic gives true
// (fail closed).
func TestSkipCache(t *testing.T) {
	var values atomic.Int32
	values.Store(1)
	previousValues := jsonbridge.BindActiveValues(&values)
	// SkipCache does not need an active request: the runtime gate is the
	// indexed-root counter only.
	previousOwners := jsonbridge.BindActiveOwners(nil)
	t.Cleanup(func() {
		jsonbridge.BindActiveOwners(previousOwners)
		jsonbridge.BindActiveValues(previousValues)
	})
	fake := &fakeCallbacks{}
	register(t, fake)
	require.True(t, jsonbridge.HasIndexedRoots())
	for _, b := range [][]byte{nil, {}, []byte("x")} {
		fake.filterResult = true
		require.False(t, jsonbridge.SkipCache(b))
	}
	require.Zero(t, fake.filterCalls, "a string of fewer than 2 bytes needs no filter check")

	b := []byte("attack")
	fake.filterResult = false
	require.False(t, jsonbridge.SkipCache(b))
	require.Equal(t, 1, fake.filterCalls)
	require.Same(t, unsafe.SliceData(b), unsafe.SliceData(fake.filterInput))
	require.Len(t, fake.filterInput, len(b))
	fake.filterResult = true
	require.True(t, jsonbridge.SkipCache(b))
	require.Equal(t, 2, fake.filterCalls)

	fake.filterPanics = true
	require.NotPanics(t, func() {
		require.True(t, jsonbridge.SkipCache(b), "a panic in the callback must fail closed")
	})

	values.Store(0)
	fake.filterPanics = false
	require.False(t, jsonbridge.HasIndexedRoots())
	require.False(t, jsonbridge.SkipCache(b), "the gate is off")
	require.Equal(t, 3, fake.filterCalls)
}

func TestString(t *testing.T) {
	activate(t)
	fake := &fakeCallbacks{}
	register(t, fake)
	destination := new(string)
	value := reflect.ValueOf(destination).Elem()
	for _, raw := range [][]byte{nil, []byte(`"`), []byte(`1`), []byte(`null`), []byte(`x"`)} {
		jsonbridge.String(raw, value)
	}
	require.Zero(t, fake.literalCalls, "String must ignore a token that is not a string")
	raw := []byte(`"attack"`)
	jsonbridge.String(raw, value)
	require.Equal(t, 1, fake.literalCalls)
	require.Same(t, unsafe.SliceData(raw), unsafe.SliceData(fake.literalDocument))
	require.Same(t, unsafe.SliceData(raw), unsafe.SliceData(fake.literalItem))
	require.NoError(t, fake.literalErr)
	require.True(t, jsonbridge.Active())

	jsonbridge.Register(jsonbridge.Callbacks{
		Literal: func([]byte, []byte, reflect.Value, error) { panic("literal") },
		Owner:   func(any) jsonbridge.OwnerToken { return jsonbridge.OwnerToken{} },
		Clone:   func(any, jsonbridge.OwnerToken, []byte) ([]byte, bool) { return nil, false },
		// MayBeTainted is necessary for a complete set.
		MayBeTainted: func([]byte) bool { return false },
	})
	require.NotPanics(t, func() { jsonbridge.String(raw, value) })
}

// sink makes the results escape, so that the allocation counts include them.
var sink jsonValue

func TestGateOffDoesNotAllocate(t *testing.T) {
	previousOwners := jsonbridge.BindActiveOwners(nil)
	previousValues := jsonbridge.BindActiveValues(nil)
	t.Cleanup(func() {
		jsonbridge.BindActiveOwners(previousOwners)
		jsonbridge.BindActiveValues(previousValues)
	})
	restore := jsonbridge.SetV2ForTest(true)
	t.Cleanup(restore)
	register(t, &fakeCallbacks{token: okToken()})
	binding := new(jsonbridge.ReaderBinding)
	state := new(int)
	reader := any(new(int))
	value := jsonValue(`{"a":"b"}`)
	raw := []byte(`"b"`)
	destination := reflect.ValueOf(new(string)).Elem()
	require.Zero(t, testing.AllocsPerRun(200, func() {
		binding.Capture(reader)
		sink = jsonbridge.ReaderDocument(binding, value)
		if jsonbridge.BindDecoder(binding, state) {
			jsonbridge.Unbind(state)
		}
		if jsonbridge.Bind(state) {
			jsonbridge.Unbind(state)
		}
		jsonbridge.Document(state, value)
		jsonbridge.String(raw, destination)
		_ = jsonbridge.HasIndexedRoots()
		_ = jsonbridge.SkipCache(raw)
		_ = jsonbridge.Active()
	}))
}

func TestReaderBindingSize(t *testing.T) {
	// The field that the aspect adds to json.Decoder: the reader, the store of
	// the token, the generation, the slot, the entry, and the state.
	require.Equal(t, uintptr(48), unsafe.Sizeof(jsonbridge.ReaderBinding{}))
}
