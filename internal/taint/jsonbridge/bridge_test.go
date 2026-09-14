// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package jsonbridge_test

import (
	"reflect"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/stretchr/testify/require"
)

func TestDecoderCallbacks(t *testing.T) {
	state := new(int)
	require.False(t, jsonbridge.Bind(nil, state))
	jsonbridge.Document(state, []byte("inactive"))
	jsonbridge.Literal(state, nil, nil, reflect.Value{}, nil)

	var owners atomic.Uint64
	owners.Store(1)
	jsonbridge.BindActiveOwners(&owners)
	var values atomic.Int32
	jsonbridge.BindActiveValues(&values)

	original := []byte(`{"value":"attack"}`)
	clone := append([]byte(nil), original...)
	var boundReader, boundState any
	var literalDocument, literalItem []byte
	var literalCalls int
	jsonbridge.Register(
		func(reader, state any) { boundReader, boundState = reader, state },
		func(_ any, data []byte) []byte { return clone[:len(data)] },
		func(document, item []byte, _ reflect.Value, err error) {
			require.NoError(t, err)
			literalDocument, literalItem = document, item
			literalCalls++
		},
	)

	require.False(t, jsonbridge.Bind(nil, nil))
	reader := new(int)
	require.True(t, jsonbridge.Bind(reader, state))
	require.Same(t, reader, boundReader)
	require.Same(t, state, boundState)
	jsonbridge.Document(state, original)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, nil)
	require.Zero(t, literalCalls, "literal callbacks require active tainted values")

	values.Store(1)
	jsonbridge.Literal(state, original, original[9:17], reflect.Value{}, nil)
	require.Equal(t, 1, literalCalls)
	require.Equal(t, clone, literalDocument)
	require.Equal(t, clone[9:17], literalItem)
	require.Equal(t, unsafe.SliceData(clone), unsafe.SliceData(literalDocument))
	require.Equal(t, unsafe.SliceData(clone[9:17]), unsafe.SliceData(literalItem))

	// A clone with a different length disables offset mapping.
	jsonbridge.Register(
		func(any, any) {},
		func(_ any, data []byte) []byte { return append([]byte(nil), data[:len(data)-1]...) },
		func(document, item []byte, _ reflect.Value, _ error) {
			literalDocument, literalItem = document, item
		},
	)
	jsonbridge.Document(state, original)
	item := original[1:4]
	jsonbridge.Literal(state, original, item, reflect.Value{}, nil)
	require.Equal(t, unsafe.SliceData(original), unsafe.SliceData(literalDocument))
	require.Equal(t, unsafe.SliceData(item), unsafe.SliceData(literalItem))

	// Nested decoder use keeps the state until the matching outer unbind.
	jsonbridge.Register(
		func(any, any) {},
		func(_ any, _ []byte) []byte { return clone },
		func(document, item []byte, _ reflect.Value, _ error) {
			literalDocument, literalItem = document, item
		},
	)
	jsonbridge.Document(state, original)
	require.True(t, jsonbridge.Bind(reader, state))
	jsonbridge.Unbind(state)
	jsonbridge.Literal(state, original, item, reflect.Value{}, nil)
	require.Equal(t, unsafe.SliceData(clone), unsafe.SliceData(literalDocument))
	jsonbridge.Unbind(state)
	jsonbridge.Literal(state, original, item, reflect.Value{}, nil)
	require.Equal(t, unsafe.SliceData(original), unsafe.SliceData(literalDocument))
	jsonbridge.Unbind(state)

	jsonbridge.Register(
		func(any, any) { panic("bind") },
		func(any, []byte) []byte { panic("document") },
		func([]byte, []byte, reflect.Value, error) { panic("literal") },
	)
	panicState := new(int)
	require.NotPanics(t, func() { require.True(t, jsonbridge.Bind(nil, panicState)) })
	require.NotPanics(t, func() { jsonbridge.Document(panicState, original) })
	require.NotPanics(t, func() { jsonbridge.Literal(panicState, original, item, reflect.Value{}, nil) })
	jsonbridge.Unbind(panicState)
}
