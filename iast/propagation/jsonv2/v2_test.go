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
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
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

// commaOne gives the bytes ',' and '1' in turn, one byte for each Read (never
// io.EOF). It does not allocate.
type commaOne struct{ i int }

func (r *commaOne) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = ",1"[r.i%2]
	r.i++
	return 1, nil
}

// decoderWithTaintedTail returns a jsontext.Decoder that read a tainted
// string of about 45 KiB from the request body (in an array), and alias: all
// of the decoder buffer (the string is at its start). The next
// fetch slides the buffer: the next delegated Read (from next) writes the
// start of the buffer, with the old bits in the tail.
func decoderWithTaintedTail(t *testing.T, a request.Analysis, next io.Reader) (*jsontext.Decoder, []byte) {
	t.Helper()
	const size = 45000
	decoder := jsontext.NewDecoder(io.MultiReader(newBody(t, a, `["`+noise(size)+`"`, 0), next))
	tok, err := decoder.ReadToken()
	require.NoError(t, err)
	require.Equal(t, jsontext.BeginArray.Kind(), tok.Kind())
	v, err := decoder.ReadValue()
	require.NoError(t, err)
	require.Len(t, v, size+2)
	// The slide of fetch removed '[': v starts at buffer offset 0, and its
	// capacity stops at its end. The unread buffer starts after v and has the
	// capacity of the rest of the buffer. The read rule applies only to a
	// destination of 64 KiB or less: the next delegated Read gets all of the
	// buffer (64 KiB).
	u := decoder.UnreadBuffer()
	require.Equal(t, unsafe.Add(unsafe.Pointer(unsafe.SliceData(v)), len(v)), unsafe.Pointer(unsafe.SliceData(u)))
	require.Equal(t, 64<<10, len(v)+cap(u), "the test needs a 64 KiB decoder buffer")
	alias := unsafe.Slice(unsafe.SliceData(v), 64<<10)
	require.Equal(t, [][2]int{{0, size + 2}}, rangesBytes(alias))
	return decoder, alias
}

// Plan section 6.2, read rule of (*decoderState).fetch: no allocation. Each
// ReadValue below gives 1-byte delegated reads into the 64 KiB buffer with a
// tainted tail. (A heap copy of the bits for each read allocated 64 KiB for
// each byte read.)
func TestJSONTextReadRuleNoAllocation(t *testing.T) {
	_, a := begin(t)
	decoder, alias := decoderWithTaintedTail(t, a, &commaOne{})
	var failures int
	allocs := testing.AllocsPerRun(10, func() {
		for range 100 {
			if v, err := decoder.ReadValue(); err != nil || string(v) != "1" {
				failures++
			}
		}
	})
	require.Zero(t, failures)
	require.Zero(t, allocs, "the read rule must not allocate")
	// The reads wrote the first bytes of the buffer with clean data. The tail
	// keeps its bits.
	got := rangesBytes(alias)
	require.Len(t, got, 1)
	require.Less(t, got[0][0], 8)
	require.Equal(t, 45002, got[0][1], "the tainted tail keeps its bits")
	require.Equal(t, []string{fmt.Sprintf("%d-45002=%s", got[0][0], bodyLabel)}, attributedBytes(t, a, alias[:45002]))
}

// Plan section 6.2, read rule of (*decoderState).fetch with more than 16
// tainted runs in the buffer: the snapshot keeps the first 16 runs. All of
// the buffer is cleared before the read, and only the saved runs get their
// bits again in the part that the read did not write: the runs from the 17th
// lose their bits (taint loss only), and a written byte never keeps its old
// bits (no stale taint).
func TestJSONTextReadRuleManyRuns(t *testing.T) {
	// setup gives a decoder whose buffer (alias) has 20 tainted runs of 10
	// bytes at offsets 0, 100, ..., 1900. The next delegated read gives next
	// (one Read).
	setup := func(t *testing.T, next string) (*jsontext.Decoder, []byte) {
		t.Helper()
		_, a := begin(t)
		decoder, alias := decoderWithTaintedTail(t, a, strings.NewReader(heapString(next)))
		heapbits.ClearBytes(alias)
		for i := range 20 {
			require.True(t, heapbits.SetBytes(alias[100*i:100*i+10]))
		}
		require.Len(t, rangesBytes(alias), 20)
		return decoder, alias
	}

	t.Run("short read", func(t *testing.T) {
		decoder, alias := setup(t, `,1]`)
		v, err := decoder.ReadValue()
		require.NoError(t, err)
		require.Equal(t, "1", string(v))
		require.Empty(t, rangesBytes(v))
		// The read wrote the bytes [0, 3).
		want := [][2]int{{3, 10}}
		for i := 1; i < 16; i++ {
			want = append(want, [2]int{100 * i, 100*i + 10})
		}
		require.Equal(t, want, rangesBytes(alias), "clean written prefix, the saved runs of the tail")
	})
	t.Run("read after the 17th run start", func(t *testing.T) {
		long := `,"` + strings.Repeat("c", 1650) + `"]`
		decoder, alias := setup(t, long)
		v, err := decoder.ReadValue()
		require.NoError(t, err)
		require.Equal(t, `"`+strings.Repeat("c", 1650)+`"`, string(v))
		require.Empty(t, rangesBytes(alias), "no stale taint on the written bytes, taint loss on the tail")
	})
}
