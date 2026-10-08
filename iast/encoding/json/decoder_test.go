// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

// The tests of this file check (*json.Decoder).Decode on all variants. On the
// v2 variant, the ReadValue wrapper of Decode gives each value to the
// exclusive owner of the reader. On the v1 variant, the Document path does the
// same.

// TestDecoderCleanReaderAfterTaintedReader checks that a decoder that gets a
// clean reader (*decoder = *json.NewDecoder(clean)) does not keep the owner
// of its earlier reader.
func TestDecoderCleanReaderAfterTaintedReader(t *testing.T) {
	requireWoven(t)
	ctx, scope := beginRequest(t)
	const data = `{"value":"tainted"}`
	decoder := json.NewDecoder(boundReader(t, ctx, data))
	requireBodySource(t, ctx, decodeOne(t, decoder), data)
	*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
	requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, []int{sourceCount(t, scope)})
}

// oneDocumentReader gives at most remaining bytes of reader, then io.EOF.
// Thus a decoder over it cannot read ahead into the next document.
type oneDocumentReader struct {
	reader    io.Reader
	remaining int
}

func (r *oneDocumentReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	read, err := r.reader.Read(p[:min(len(p), r.remaining)])
	r.remaining -= read
	return read, err
}

// TestDecoderNewDecoderForEachDocument checks ten decoders, one for each
// document, over one reader of the request. Each value has the source of its
// own document. The number of decoders has no limit.
func TestDecoderNewDecoderForEachDocument(t *testing.T) {
	requireWoven(t)
	ctx, scope := beginRequest(t)
	const count = 10
	data, values := documents("value", count)
	reader := &oneDocumentReader{reader: strings.NewReader(data)}
	require.True(t, request.BindReader(ctx, reader))
	sources := sourceCount(t, scope)
	for index, want := range values {
		document := `{"value":"` + want + `"}`
		reader.remaining = len(document)
		value := decodeOne(t, json.NewDecoder(reader))
		require.Equal(t, want, value)
		requireBodySource(t, ctx, value, document)
		if decoderPropagates {
			require.Equal(t, sources+index+1, sourceCount(t, scope))
		}
	}
}

// TestDecoderFailureThenCleanReader checks that a failed Decode does not give
// the owner of its reader to a later clean reader.
func TestDecoderFailureThenCleanReader(t *testing.T) {
	requireWoven(t)
	for name, data := range map[string]string{
		"syntax error":   `{"value":`,
		"semantic error": `{"value":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginRequest(t)
			decoder := json.NewDecoder(boundReader(t, ctx, data))
			var failed document
			require.Error(t, decoder.Decode(&failed))
			require.Empty(t, failed.Value)
			*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
			requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, []int{sourceCount(t, scope)})
		})
	}
}

// panicString panics in UnmarshalJSON.
type panicString string

func (*panicString) UnmarshalJSON([]byte) error { panic("json panic") }

// decodePanic decodes one document into a panicString field, and returns
// the value of the panic.
func decodePanic(decoder *json.Decoder) (recovered any) {
	defer func() { recovered = recover() }()
	var destination struct {
		Value panicString `json:"value"`
	}
	_ = decoder.Decode(&destination)
	return nil
}

// TestDecoderPanicThenCleanReader checks that the panic of a user method
// during Decode is not changed, and that the decoder does not give the owner
// of its reader to a later clean reader.
func TestDecoderPanicThenCleanReader(t *testing.T) {
	requireWoven(t)
	ctx, scope := beginRequest(t)
	decoder := json.NewDecoder(boundReader(t, ctx, `{"value":"panic"}`))
	require.Equal(t, "json panic", decodePanic(decoder))
	*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
	requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, []int{sourceCount(t, scope)})
}

// TestDecoderOversizedThenCleanReader checks that a value larger than the
// root limit is a miss, and that a later clean reader stays clean.
func TestDecoderOversizedThenCleanReader(t *testing.T) {
	requireWoven(t)
	ctx, scope := beginRequest(t)
	large := strings.Repeat("x", store.MaxRootBytes+1)
	decoder := json.NewDecoder(boundReader(t, ctx, `{"value":"`+large+`"}`))
	sources := []int{sourceCount(t, scope)}
	value := decodeOne(t, decoder)
	require.Equal(t, large, value)
	requireMiss(t, value, []*request.Scope{scope}, sources)
	*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
	requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, sources)
}

// TestDecoderBytesBufferReader checks a *bytes.Buffer reader. The v2
// NewDecoder hides it in a struct{ io.Reader } (v2_stream.go). The capture
// uses the argument of NewDecoder, thus the bound buffer keeps its identity.
func TestDecoderBytesBufferReader(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	const data = `{"value":"from-buffer"}`
	var buffer bytes.Buffer
	buffer.WriteString(data)
	require.True(t, request.BindReader(ctx, &buffer))
	value := decodeOne(t, json.NewDecoder(&buffer))
	require.Equal(t, "from-buffer", value)
	requireBodySource(t, ctx, value, data)
}

// TestDecoderSeveralDecodeCalls checks several Decode calls on one decoder.
// Each value has its own source. The v1 source value starts directly after
// the previous value, thus it can start with the whitespace between the
// values. The v2 source value starts at the first byte of the value.
func TestDecoderSeveralDecodeCalls(t *testing.T) {
	requireWoven(t)
	ctx, scope := beginRequest(t)
	decoder := json.NewDecoder(boundReader(t, ctx, `{"value":"first"} {"value":"second"}`+"\n"+`{"value":"third"}`))
	sources := sourceCount(t, scope)
	for index, want := range []struct{ value, source string }{
		{"first", `{"value":"first"}`},
		{"second", decoderLeadingWhitespace(" ") + `{"value":"second"}`},
		{"third", decoderLeadingWhitespace("\n") + `{"value":"third"}`},
	} {
		value := decodeOne(t, decoder)
		require.Equal(t, want.value, value)
		requireBodySource(t, ctx, value, want.source)
		if decoderPropagates {
			require.Equal(t, sources+index+1, sourceCount(t, scope))
		}
	}
	var end document
	require.ErrorIs(t, decoder.Decode(&end), io.EOF)
}

// decoderLeadingWhitespace returns whitespace when the source value of a
// Decode starts with the whitespace before the value on this variant.
func decoderLeadingWhitespace(whitespace string) string {
	if decoderSourceHasLeadingWhitespace {
		return whitespace
	}
	return ""
}

// TestDecoderNumber checks json.Number through Decode. On the v2 variant,
// (*Number).UnmarshalJSONFrom has a ReadValue call that the Decode hook must
// not change (TestV2ReadValueHookScope checks the woven code). The values
// and the errors are the same as with no request. The string field of the
// same value keeps its taint.
func TestDecoderNumber(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	const data = `{"number":-1.5e3,"quoted":"42","value":"from-a"} 7 "8" "x"`
	decoder := json.NewDecoder(boundReader(t, ctx, data))
	var object struct {
		Number json.Number `json:"number"`
		Quoted json.Number `json:"quoted"`
		Value  string      `json:"value"`
	}
	require.NoError(t, decoder.Decode(&object))
	require.Equal(t, json.Number("-1.5e3"), object.Number)
	require.Equal(t, json.Number("42"), object.Quoted)
	const first = `{"number":-1.5e3,"quoted":"42","value":"from-a"}`
	requireBodySource(t, ctx, object.Value, first)
	// A quoted number is a string token: the v1 Literal path and the v2
	// runtime hooks (string conversion of the tainted clone) taint it.
	requireBodySource(t, ctx, string(object.Quoted), first)
	// A number token: only the v2 runtime hooks taint it (the v1 decoder
	// decodes its clean buffer, and the Literal path takes only strings).
	require.Equal(t, decoderTaintsNumberTokens, taint.IsTaintedString(string(object.Number)))

	var number json.Number
	require.NoError(t, decoder.Decode(&number))
	require.Equal(t, json.Number("7"), number)
	require.NoError(t, decoder.Decode(&number))
	require.Equal(t, json.Number("8"), number)
	require.Error(t, decoder.Decode(&number), "a string that is not a number")

	useNumber := json.NewDecoder(boundReader(t, ctx, `{"n":12}`))
	useNumber.UseNumber()
	var values map[string]any
	require.NoError(t, useNumber.Decode(&values))
	require.Equal(t, map[string]any{"n": json.Number("12")}, values)
}

// TestDecoderClosedAfterForeignBind checks reader binding rule (f) (see the
// internal/taint/store package doc) at each Decode: request B binds the reader
// of request A (the root reader, or the reader under a bufio wrapper) after
// NewDecoder, and ends before Decode. The value is a miss, and the decoder is
// closed: a later Decode does not try to clone its value. Control: a rebind of
// the reader by A between NewDecoder and Decode keeps the values tainted.
func TestDecoderClosedAfterForeignBind(t *testing.T) {
	requireWoven(t)
	for name, wrap := range map[string]func(io.Reader) io.Reader{
		"root":  func(reader io.Reader) io.Reader { return reader },
		"bufio": func(reader io.Reader) io.Reader { return bufio.NewReaderSize(reader, 16) },
	} {
		t.Run(name, func(t *testing.T) {
			for _, foreign := range []bool{true, false} {
				ctxA, scopeA := beginRequest(t)
				ctxB, scopeB := beginRequest(t)
				const first, second = `{"value":"first"}`, `{"value":"second"}`
				body := &oneDocumentReader{reader: strings.NewReader(first + second), remaining: len(first)}
				require.True(t, request.BindReader(ctxA, body))
				decoder := json.NewDecoder(wrap(body))
				if foreign {
					require.True(t, request.BindReader(ctxB, body))
					scopeB.Finish()
				} else {
					require.True(t, request.BindReader(ctxA, body))
				}
				before := []int{sourceCount(t, scopeA)}
				value := decodeOne(t, decoder)
				require.Equal(t, "first", value)
				if !foreign {
					requireBodySource(t, ctxA, value, first)
				} else {
					requireMiss(t, value, []*request.Scope{scopeA}, before)
				}

				clones := countClones(t)
				body.remaining = len(second)
				value = decodeOne(t, decoder)
				require.Equal(t, "second", value)
				if !foreign {
					requireBodySource(t, ctxA, value, second)
					require.Equal(t, int32(1), clones.Load(), "an open decoder must clone each value")
					continue
				}
				requireMiss(t, value, []*request.Scope{scopeA}, before)
				require.Zero(t, clones.Load(), "the decoder is not closed: it tried to clone a value")
			}
		})
	}
}

// countClones registers JSON bridge callbacks that count the Clone calls,
// until the end of the test.
func countClones(t *testing.T) *atomic.Int32 {
	t.Helper()
	var clones atomic.Int32
	counting := callbacks()
	clone := counting.Clone
	counting.Clone = func(reader any, token jsonbridge.OwnerToken, data []byte) ([]byte, bool) {
		clones.Add(1)
		return clone(reader, token, data)
	}
	jsonbridge.Register(counting)
	t.Cleanup(func() { jsonbridge.Register(callbacks()) })
	return &clones
}
