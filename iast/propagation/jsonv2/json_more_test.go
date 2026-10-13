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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// More tests with no build constraint (the two variants give the same
// results). They cover the paths of the v2 implementation that the tests of
// json_test.go do not use.

// The v2 decoder keeps a cache of strings across the pooled Unmarshal calls
// (makeString). A tainted value must not get a clean string of the cache, and
// a clean value must not get a tainted string of an earlier call.
func TestJSONStringCache(t *testing.T) {
	_, a := begin(t)
	const doc = `{"name":"cached-value","Tags":["cached-value"]}`
	tainted := func() []byte {
		b, err := io.ReadAll(newBody(t, a, doc, 0))
		require.NoError(t, err)
		return b
	}
	for i, input := range [][]byte{heapBytes(doc), tainted(), heapBytes(doc), tainted(), tainted(), heapBytes(doc)} {
		isTainted := len(rangesBytes(input)) > 0
		var v user
		require.NoError(t, json.Unmarshal(input, &v))
		for _, s := range []string{v.Name, v.Tags[0]} {
			require.Equal(t, "cached-value", s)
			if isTainted {
				require.Equal(t, [][2]int{{0, len(s)}}, rangesString(s), "input %d", i)
				require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len(s), bodyLabel)}, attributed(t, a, s), "input %d", i)
			} else {
				require.Empty(t, rangesString(s), "input %d", i)
			}
		}
	}
}

// The same with concurrent decoders (the pool shares the decoders and their
// caches between goroutines). Run with -race.
func TestJSONStringCacheConcurrent(t *testing.T) {
	_, a := begin(t)
	const doc = `{"name":"shared-value"}`
	body, err := io.ReadAll(newBody(t, a, doc, 0))
	require.NoError(t, err)
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				input := heapBytes(doc)
				if (g+i)%2 == 0 {
					input = body
				}
				isTainted := (g+i)%2 == 0
				var v user
				if err := json.Unmarshal(input, &v); err != nil {
					errs <- err.Error()
					return
				}
				if got := len(rangesString(v.Name)) > 0; got != isTainted {
					errs <- fmt.Sprintf("goroutine %d, call %d: tainted=%v, want %v", g, i, got, isTainted)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// (*json.Decoder).Token returns the strings of the stream with their bits.
func TestJSONDecoderToken(t *testing.T) {
	requireCoarseUnquote(t)
	_, a := begin(t)
	decoder := json.NewDecoder(newBody(t, a, `{"key":["value","a\tb",12]}`, 5))
	var strs []string
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if s, ok := tok.(string); ok {
			strs = append(strs, s)
		}
	}
	require.Equal(t, []string{"key", "value", "a\tb"}, strs)
	for _, s := range strs {
		require.Equal(t, [][2]int{{0, len(s)}}, rangesString(s), "%q", s)
		require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len(s), bodyLabel)}, attributed(t, a, s))
	}
}

// A ",string" value with escapes in its inner string is coarse.
func TestJSONStringOptionEscaped(t *testing.T) {
	requireCoarseUnquote(t)
	_, a := begin(t)
	var v user
	require.NoError(t, json.NewDecoder(newBody(t, a, `{"id":"\"rob\\nert\""}`, 0)).Decode(&v))
	require.Equal(t, "rob\nert", v.ID)
	require.Equal(t, [][2]int{{0, len(v.ID)}}, rangesString(v.ID))
	require.Equal(t, []string{"0-7=" + bodyLabel}, attributed(t, a, v.ID))
}

// A document with a mix of escaped and plain strings, from a tainted body
// and then from a clean reader, in the same Decoder: each string gets the
// bits of its own input.
func TestJSONDecoderEscapedThenClean(t *testing.T) {
	requireCoarseUnquote(t)
	_, a := begin(t)
	tainted := `{"name":"a\"b","Tags":["plain","e\u00e9"]}`
	clean := heapString(`{"name":"c\"d","Tags":["plain","f\u00e9"]}`)
	decoder := json.NewDecoder(io.MultiReader(newBody(t, a, tainted, 9), strings.NewReader(clean)))
	var v user
	require.NoError(t, decoder.Decode(&v))
	for _, s := range []string{v.Name, v.Tags[0], v.Tags[1]} {
		require.Equal(t, [][2]int{{0, len(s)}}, rangesString(s), "%q", s)
	}
	v = user{}
	require.NoError(t, decoder.Decode(&v))
	require.Equal(t, "c\"d", v.Name)
	for _, s := range []string{v.Name, v.Tags[0], v.Tags[1]} {
		require.Empty(t, rangesString(s), "%q", s)
	}
}

// An invalid document returns an error, and does not panic.
func TestJSONInvalidInput(t *testing.T) {
	_, a := begin(t)
	for _, doc := range []string{`{"name":"a\x"}`, `{"name":"a`, `{"name":"\ud800"}`, `{"name":12}`, `[`} {
		var v user
		b, err := io.ReadAll(newBody(t, a, doc, 0))
		require.NoError(t, err)
		_ = json.Unmarshal(b, &v)
		_ = json.NewDecoder(newBody(t, a, doc, 3)).Decode(&v)
	}
}
