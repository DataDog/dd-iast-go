// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package jsonv2_test

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/stretchr/testify/require"
)

// The tests of this file are the json tests of iast/propagation/stream
// (step 8b), with no build constraint: with GOEXPERIMENT=jsonv2 (the default
// from Go 1.27), the hooks of this package make them pass; without it, the v1
// hooks of iast/propagation/stream do. Thus the two variants give the same
// results (json_variant_test.go has the tests that differ).

type user struct {
	Pad  string `json:"pad"`
	Name string `json:"name"`
	ID   string `json:"id,string"`
	Tags []string
	Meta map[string]string
	Any  any
}

// Plan section 9.1 item 4: an 8 KiB JSON body; the sink uses only a field
// after byte 4096. The Decoder reads in small chunks: the slide and the
// growth of its buffer keep the bits.
func TestJSONDecoderLargeBody(t *testing.T) {
	for _, chunk := range []int{0, 100, 512, 1000} {
		t.Run(fmt.Sprintf("chunk=%d", chunk), func(t *testing.T) {
			_, a := begin(t)
			pad := noise(8000)
			data := `{"pad":"` + pad + `","name":"robert'); drop table x;--"}`
			var v user
			require.NoError(t, json.NewDecoder(newBody(t, a, data, chunk)).Decode(&v))
			require.Equal(t, "robert'); drop table x;--", v.Name)
			require.Equal(t, [][2]int{{0, len(v.Name)}}, rangesString(v.Name))
			require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len(v.Name), bodyLabel)}, attributed(t, a, v.Name))
			require.Equal(t, pad, v.Pad)
			require.Equal(t, [][2]int{{0, len(pad)}}, rangesString(v.Pad))
		})
	}
}

// json.Unmarshal of a tainted body: struct fields, slices, maps (keys and
// values) and interface values keep the bits of their bytes.
func TestJSONUnmarshalShapes(t *testing.T) {
	_, a := begin(t)
	data, err := io.ReadAll(newBody(t, a, `{"name":"robert","Tags":["a1","b2"],"Meta":{"k1":"v1"},"Any":{"xz":["y1"]}}`, 0))
	require.NoError(t, err)
	var v user
	require.NoError(t, json.Unmarshal(data, &v))
	for _, s := range []string{v.Name, v.Tags[0], v.Tags[1], v.Meta["k1"], v.Any.(map[string]any)["xz"].([]any)[0].(string)} {
		require.Equal(t, [][2]int{{0, len(s)}}, rangesString(s), "%q", s)
		require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len(s), bodyLabel)}, attributed(t, a, s))
	}
	for k := range v.Meta {
		require.Equal(t, [][2]int{{0, 2}}, rangesString(k))
	}
	for k := range v.Any.(map[string]any) {
		require.Equal(t, [][2]int{{0, 2}}, rangesString(k))
	}
}

// Plan section 6.3: a string with escapes is new memory (v1 unquoteBytes,
// v2 jsonwire.AppendUnquote): it is tainted as a whole, and the derived entry
// gives the source.
func TestJSONEscapedStringIsCoarse(t *testing.T) {
	requireCoarseUnquote(t)
	for name, decode := range map[string]func(t *testing.T, data string, v any) error{
		"Unmarshal": func(t *testing.T, data string, v any) error {
			_, a := begin(t)
			b, err := io.ReadAll(newBody(t, a, data, 0))
			require.NoError(t, err)
			return json.Unmarshal(b, v)
		},
		"Decoder": func(t *testing.T, data string, v any) error {
			_, a := begin(t)
			return json.NewDecoder(newBody(t, a, data, 7)).Decode(v)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var v user
			require.NoError(t, decode(t, `{"name":"rob\nert\u00e9\"'"}`, &v))
			require.Equal(t, "rob\nert\u00e9\"'", v.Name)
			require.Equal(t, [][2]int{{0, len(v.Name)}}, rangesString(v.Name))
		})
	}
	// The derived entry: attribution of the decoded value.
	_, a := begin(t)
	var v user
	require.NoError(t, json.NewDecoder(newBody(t, a, `{"name":"a\tb"}`, 0)).Decode(&v))
	require.Equal(t, []string{"0-3=" + bodyLabel}, attributed(t, a, v.Name))
}

// Plan section 6.2 (critic minor 11): ",string" fields keep the taint, also
// when the string-to-slice propagation of the runtime is off.
func TestJSONStringOption(t *testing.T) {
	requireCoarseUnquote(t)
	for _, s2s := range []bool{true, false} {
		t.Run(fmt.Sprintf("string-to-slice=%v", s2s), func(t *testing.T) {
			_, a := begin(t)
			old := propbridge.StringToSlice()
			propbridge.SetStringToSlice(s2s)
			t.Cleanup(func() { propbridge.SetStringToSlice(old) })
			var v user
			require.NoError(t, json.NewDecoder(newBody(t, a, `{"id":"\"robert\""}`, 0)).Decode(&v))
			require.Equal(t, "robert", v.ID)
			require.Equal(t, [][2]int{{0, 6}}, rangesString(v.ID))
			require.Equal(t, []string{"0-6=" + bodyLabel}, attributed(t, a, v.ID))
		})
	}
}

// switchReader reads from r; the test can change r between two reads
// (a retarget). Each read gives at most one document.
type switchReader struct {
	r     io.Reader
	chunk int
}

func (s *switchReader) Read(p []byte) (int, error) {
	if s.chunk > 0 && len(p) > s.chunk {
		p = p[:s.chunk]
	}
	return s.r.Read(p)
}

// Plan section 9.1 item 5 (PR #39 TestDecoderRetargetBetweenTwoDecodes): a
// retarget of the reader of a Decoder between two Decode calls keeps the
// first value tainted; the later values are clean (no false finding: the
// read rule clears the old bits of the reused buffer).
func TestJSONDecoderReuseAndRetarget(t *testing.T) {
	_, a := begin(t)
	const doc = `{"name":"from-a-000"}`
	r := &switchReader{r: newBody(t, a, doc, 0), chunk: len(doc)}
	decoder := json.NewDecoder(r)
	var first user
	require.NoError(t, decoder.Decode(&first))
	require.Equal(t, "from-a-000", first.Name)
	require.Equal(t, []string{"0-10=" + bodyLabel}, attributed(t, a, first.Name))

	clean := heapString(`{"name":"clean-001"}{"name":"clean-002"}`)
	r.r = strings.NewReader(clean)
	for _, want := range []string{"clean-001", "clean-002"} {
		var v user
		require.NoError(t, decoder.Decode(&v))
		require.Equal(t, want, v.Name)
		require.Empty(t, rangesString(v.Name), "%q", v.Name)
	}
	require.Equal(t, []string{"0-10=" + bodyLabel}, attributed(t, a, first.Name))
}

// A stream of values: values from the body are tainted, values from a clean
// reader after it are clean, also when the Decoder buffer slides and grows.
func TestJSONDecoderStream(t *testing.T) {
	_, a := begin(t)
	var body strings.Builder
	for i := range 50 {
		fmt.Fprintf(&body, `{"name":"body-%03d-%s"} `, i, noise(20))
	}
	var cleanDocs strings.Builder
	for i := range 50 {
		fmt.Fprintf(&cleanDocs, `{"name":"clean-%03d"} `, i)
	}
	decoder := json.NewDecoder(io.MultiReader(newBody(t, a, body.String(), 33), strings.NewReader(heapString(cleanDocs.String()))))
	for i := range 100 {
		var v user
		require.NoError(t, decoder.Decode(&v))
		if i < 50 {
			require.Equal(t, [][2]int{{0, len(v.Name)}}, rangesString(v.Name), "%d %q", i, v.Name)
		} else {
			require.Empty(t, rangesString(v.Name), "%d %q", i, v.Name)
		}
	}
}

// Port of PR #39 TestDecoderOversizedValueThenValidValue: a value larger
// than the body copy (64 KiB) keeps its bits, but its bytes after 64 KiB are
// foreign at the sink; the next value is tainted.
func TestJSONDecoderOversizedValueThenValidValue(t *testing.T) {
	_, a := begin(t)
	large := `{"name":"` + noise(70000) + `"}`
	decoder := json.NewDecoder(newBody(t, a, large+`{"name":"small"}`, 0))
	var v user
	require.NoError(t, decoder.Decode(&v))
	require.Len(t, v.Name, 70000)
	require.Equal(t, [][2]int{{0, 70000}}, rangesString(v.Name))
	require.NoError(t, decoder.Decode(&v))
	require.Equal(t, "small", v.Name)
	require.Equal(t, [][2]int{{0, 5}}, rangesString(v.Name))
}

// Clean input stays clean.
func TestJSONCleanInput(t *testing.T) {
	_, a := begin(t)
	_ = param(t, a, "q", "robert")
	var v user
	require.NoError(t, json.Unmarshal(heapBytes(`{"name":"a\nb","id":"\"x\"","Tags":["t"]}`), &v))
	require.Empty(t, rangesString(v.Name))
	require.Empty(t, rangesString(v.ID))
	require.Empty(t, rangesString(v.Tags[0]))
}

// The slide of the buffer (v1 refill, v2 fetch) moves the unread bytes to the
// start of the buffer: their bits move with them (the bytes at the start had
// different bits).
func TestJSONDecoderRefillSlide(t *testing.T) {
	_, a := begin(t)
	decoder := json.NewDecoder(newScripted(t, a,
		[]seg{{`{"name":"clean-value-000"} {"name":"`, false}, {"robert", true}},
		[]seg{{`"}`, false}},
	))
	var v user
	require.NoError(t, decoder.Decode(&v))
	require.Empty(t, rangesString(v.Name))
	require.NoError(t, decoder.Decode(&v))
	require.Equal(t, "robert", v.Name)
	require.Equal(t, [][2]int{{0, 6}}, rangesString(v.Name))
	require.Equal(t, []string{"0-6=" + bodyLabel}, attributed(t, a, v.Name))
}
