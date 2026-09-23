// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package jsonbridge_test

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

func TestDecoderCallbacks(t *testing.T) {
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

	original := []byte(`{"value":"attack"}`)
	clone := append([]byte(nil), original...)
	state := new(int)
	reader := new(int)
	var callbackReader any
	var documentCalls int
	var literalDocument, literalItem []byte
	var literalErr error
	jsonbridge.Register(
		func(reader any, data []byte) []byte {
			callbackReader = reader
			documentCalls++
			return clone[:len(data)]
		},
		func(document, item []byte, _ reflect.Value, err error) {
			literalDocument, literalItem, literalErr = document, item, err
		},
	)

	require.False(t, jsonbridge.Bind(nil, nil))
	require.True(t, jsonbridge.Bind(reader, state))
	jsonbridge.Document(state, original)
	require.Same(t, reader, callbackReader)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, nil, false)
	require.Equal(t, clone, literalDocument)
	require.Equal(t, clone[9:17], literalItem)
	require.Equal(t, unsafe.SliceData(clone), unsafe.SliceData(literalDocument))
	require.Equal(t, unsafe.SliceData(clone[9:17]), unsafe.SliceData(literalItem))

	// A nested direct-unmarshal binding must preserve the decoder's outer reader.
	require.True(t, jsonbridge.Bind(nil, state))
	jsonbridge.Document(state, original)
	require.Same(t, reader, callbackReader)
	jsonbridge.Unbind(state)
	jsonbridge.Unbind(state)

	// Final unbind releases the source, document, and callback eligibility.
	documentCalls = 0
	jsonbridge.Document(state, original)
	require.Zero(t, documentCalls)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, nil, false)
	require.Equal(t, unsafe.SliceData(original), unsafe.SliceData(literalDocument))

	// Reusing the state binds only the new reader and clears failed publication.
	cleanReader := new(int)
	require.True(t, jsonbridge.Bind(cleanReader, state))
	jsonbridge.Register(
		func(reader any, _ []byte) []byte { callbackReader = reader; return nil },
		func(document, item []byte, _ reflect.Value, err error) {
			literalDocument, literalItem, literalErr = document, item, err
		},
	)
	jsonbridge.Document(state, original)
	require.Same(t, cleanReader, callbackReader)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, errors.New("decode"), false)
	require.EqualError(t, literalErr, "decode")
	require.Equal(t, unsafe.SliceData(original), unsafe.SliceData(literalDocument))
	jsonbridge.Unbind(state)
}

func TestDecoderCallbacksQuotedIdentityAndCleanup(t *testing.T) {
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

	original := []byte(`{"a":"\"same\"","b":"\"same\""}`)
	clone := append([]byte(nil), original...)
	second := strings.LastIndex(string(original), `"\"same\""`)
	require.NotEqual(t, -1, second)
	state := new(int)
	reader := new(int)
	var literalDocument, literalItem []byte
	jsonbridge.Register(
		func(any, []byte) []byte { return clone },
		func(document, item []byte, _ reflect.Value, _ error) { literalDocument, literalItem = document, item },
	)
	require.True(t, jsonbridge.Bind(reader, state))
	jsonbridge.Document(state, original)
	jsonbridge.Quoted(state, original, second, second+len(`"\"same\""`), `"same"`)
	jsonbridge.Literal(state, original, []byte(`"same"`), reflect.Value{}, nil, true)
	require.Equal(t, unsafe.SliceData(clone), unsafe.SliceData(literalDocument))
	require.Equal(t, unsafe.SliceData(clone[second:]), unsafe.SliceData(literalItem))

	// A failed oversized publication clears the prior clone mapping.
	jsonbridge.Register(
		func(any, []byte) []byte { return nil },
		func(document, item []byte, _ reflect.Value, _ error) { literalDocument, literalItem = document, item },
	)
	jsonbridge.Document(state, make([]byte, 1<<20))
	jsonbridge.Literal(state, original, original[second:second+len(`"\"same\""`)], reflect.Value{}, nil, false)
	require.Equal(t, unsafe.SliceData(original), unsafe.SliceData(literalDocument))
	jsonbridge.Unbind(state)

	// Panicking callbacks are shielded and final unbind permits clean reuse.
	jsonbridge.Register(
		func(any, []byte) []byte { panic("document") },
		func([]byte, []byte, reflect.Value, error) { panic("literal") },
	)
	require.True(t, jsonbridge.Bind(reader, state))
	require.NotPanics(t, func() { jsonbridge.Document(state, original) })
	jsonbridge.Quoted(state, original, second, second+len(`"\"same\""`), `"same"`)
	require.NotPanics(t, func() { jsonbridge.Literal(state, original, []byte(`"same"`), reflect.Value{}, nil, true) })
	jsonbridge.Unbind(state)

	cleanReader := new(int)
	var callbackReader any
	jsonbridge.Register(
		func(reader any, _ []byte) []byte { callbackReader = reader; return nil },
		func(document, item []byte, _ reflect.Value, _ error) { literalDocument, literalItem = document, item },
	)
	require.True(t, jsonbridge.Bind(cleanReader, state))
	jsonbridge.Document(state, original)
	require.Same(t, cleanReader, callbackReader)
	jsonbridge.Literal(state, original, original[second:second+len(`"\"same\""`)], reflect.Value{}, nil, true)
	require.Equal(t, unsafe.SliceData(original), unsafe.SliceData(literalDocument))
	jsonbridge.Unbind(state)
}

func TestDecoderCallbacksInactive(t *testing.T) {
	previousOwners := jsonbridge.BindActiveOwners(nil)
	previousValues := jsonbridge.BindActiveValues(nil)
	t.Cleanup(func() {
		jsonbridge.BindActiveOwners(previousOwners)
		jsonbridge.BindActiveValues(previousValues)
	})
	state := new(int)
	require.False(t, jsonbridge.Bind(nil, state))
	jsonbridge.Document(state, []byte("inactive"))
	jsonbridge.Quoted(state, []byte(`"inactive"`), 0, 10, "inactive")
	jsonbridge.Literal(state, nil, nil, reflect.Value{}, nil, false)
}
