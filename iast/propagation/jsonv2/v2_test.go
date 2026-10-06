// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2 && go1.27

package jsonv2_test

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/stretchr/testify/require"
)

// The tests of this file use the packages encoding/json/v2 and jsontext
// directly: they exist only with GOEXPERIMENT=jsonv2 (and the module language
// version (go1.26) gives access to them only in files with go1.27 or later).

// jsontext.AppendUnquote (jsonwire.AppendUnquote): the appended bytes of a
// tainted raw string are coarse (also with no escape: it is new memory), and
// the derived entry gives the source. A clean raw string clears the old bits
// of a reused destination. The bytes before len(dst) do not change.
func TestAppendUnquoteBits(t *testing.T) {
	_, a := begin(t)
	raw := paramBytes(t, a, "q", `"a\nb"`)
	out, err := jsontext.AppendUnquote(nil, raw)
	require.NoError(t, err)
	require.Equal(t, "a\nb", string(out))
	require.Equal(t, [][2]int{{0, 3}}, rangesBytes(out))
	require.Equal(t, []string{"0-3=" + paramLabel("q")}, attributedBytes(t, a, out))

	verbatim := paramBytes(t, a, "v", `"plain"`)
	out, err = jsontext.AppendUnquote(nil, verbatim)
	require.NoError(t, err)
	require.Equal(t, [][2]int{{0, 5}}, rangesBytes(out))

	// A reused destination: a clean prefix, and a tail with old bits.
	dst := heapBytes("prefix" + noise(26))
	require.True(t, heapbits.SetBytes(dst[6:]))
	out, err = jsontext.AppendUnquote(dst[:6], heapBytes(`"c\td"`))
	require.NoError(t, err)
	require.Equal(t, unsafe.SliceData(dst), unsafe.SliceData(out), "the test needs the same memory")
	require.Equal(t, "prefixc\td", string(out))
	require.Empty(t, rangesBytes(out))
	require.Equal(t, [][2]int{{9, 32}}, rangesBytes(dst), "the bytes after the result keep their bits")

	// A tainted prefix keeps its bits; the appended bytes are coarse.
	out, err = jsontext.AppendUnquote(paramBytes(t, a, "p", "pre"), raw)
	require.NoError(t, err)
	require.Equal(t, "prea\nb", string(out))
	require.Equal(t, [][2]int{{0, 6}}, rangesBytes(out))
	require.Equal(t, []string{"0-3=" + paramLabel("p"), "3-6=" + paramLabel("q")}, attributedBytes(t, a, out))
}

// Direct users of encoding/json/v2 get the same propagation.
func TestV2Unmarshal(t *testing.T) {
	_, a := begin(t)
	data, err := io.ReadAll(newBody(t, a, `{"name":"robert","Meta":{"k1":"v\u00e9"},"Any":["x1"]}`, 0))
	require.NoError(t, err)
	var v user
	require.NoError(t, jsonv2.Unmarshal(data, &v))
	for _, s := range []string{v.Name, v.Meta["k1"], v.Any.([]any)[0].(string)} {
		require.Equal(t, [][2]int{{0, len(s)}}, rangesString(s), "%q", s)
		require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len(s), bodyLabel)}, attributed(t, a, s))
	}

	// UnmarshalRead uses a pooled streaming decoder: its buffer is reused.
	for range 3 {
		var w user
		require.NoError(t, jsonv2.UnmarshalRead(newBody(t, a, `{"name":"body-`+noise(5000)+`"}`, 700), &w))
		require.Equal(t, [][2]int{{0, len(w.Name)}}, rangesString(w.Name))
		var c user
		require.NoError(t, jsonv2.UnmarshalRead(bytes.NewReader(heapBytes(`{"name":"clean-`+noise(5000)+`"}`)), &c))
		require.Empty(t, rangesString(c.Name))
	}
}

// jsontext.Decoder: the values of ReadValue alias the buffer of the decoder,
// with the bits of the reads.
func TestJSONTextDecoder(t *testing.T) {
	_, a := begin(t)
	decoder := jsontext.NewDecoder(newScripted(t, a,
		[]seg{{`["clean-000", "`, false}, {`tainted`, true}},
		[]seg{{`", "clean-001"]`, false}},
	))
	tok, err := decoder.ReadToken()
	require.NoError(t, err)
	require.Equal(t, jsontext.BeginArray.Kind(), tok.Kind())
	var got [][][2]int
	for decoder.PeekKind() != ']' {
		v, err := decoder.ReadValue()
		require.NoError(t, err)
		got = append(got, rangesBytes(v))
	}
	require.Equal(t, [][][2]int{nil, {{1, 8}}, nil}, got)
}
