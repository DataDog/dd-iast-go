// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"context"
	"encoding/json"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

// The tests of this file check json.Unmarshal of tainted bytes. On the v1
// variant, the decodeState aspects propagate. On the v2 variant, the
// wrapper of the default string unmarshaler of encoding/json/v2 propagates.
// The expected results are the same on all variants, except for map keys and
// interface{} strings (unmarshalTaintsKeysAndAny; see "JSON decoding" in the
// README).

// bodySource is the source of the tainted documents of these tests.
var bodySource = taint.Source{Origin: taint.OriginHttpRequestBody, Name: "unmarshal"}

// requireCoarseTaint checks that value has exactly one range, on all of its
// bytes, with the body source and the source value document (one coarse range
// for each decoded string).
func requireCoarseTaint(t *testing.T, ctx context.Context, value, document string) {
	t.Helper()
	var found []taint.Range
	taint.VisitString(ctx, value, func(r taint.Range) bool {
		found = append(found, r)
		return true
	})
	require.Equal(t, []taint.Range{{
		Start:  0,
		Length: uint32(len(value)),
		Source: taint.SourceValue{Source: bodySource, Value: document},
	}}, found, "the ranges of %q", value)
}

// requireClean checks that value has no taint.
func requireClean(t *testing.T, value string) {
	t.Helper()
	require.False(t, taint.IsTaintedString(value), "the value %q is tainted", value)
}

// taintedWindow returns a managed copy of document that has taint only in
// [low, high). A wrong raw token of a decoded string then gives a wrong
// result.
func taintedWindow(t *testing.T, ctx context.Context, document string, low, high int) []byte {
	t.Helper()
	whole := taint.TaintBytes(ctx, bodySource, []byte(document))
	require.True(t, taint.IsTaintedBytes(whole))
	active := request.ActiveStore()
	require.NotNil(t, active)
	key, ok := store.BytesKey(whole)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, active.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	owner, ok := entry.Handle(active)
	require.True(t, ok)
	length := uint32(len(document))
	var head, window ranges.Set
	require.True(t, ranges.Clear(&head, entry.Ranges.Limit(), &entry.Ranges, length, 0, uint32(low)).Valid)
	require.True(t, ranges.Clear(&window, entry.Ranges.Limit(), &head, length, uint32(high), length).Valid)
	// A byte loop from the clean constant: a copy of whole would also copy
	// the taint of whole (the runtime hooks).
	clone := make([]byte, len(document))
	for index := range len(document) {
		clone[index] = document[index]
	}
	_, ok = owner.AdoptBytes(clone, &window)
	require.True(t, ok)
	return clone
}

type unmarshalNamed string

type unmarshalNested struct {
	Value string `json:"value"`
}

// TestUnmarshalPropagatesDestinationClasses checks that a string of each
// destination class gets the taint of its raw token.
func TestUnmarshalPropagatesDestinationClasses(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	document := `{"field":"f-attack","named":"n-attack","slice":["s0-attack","s1-attack"],` +
		`"array":["a0-attack","a1-attack"],"pointer":"p-attack","map":{"key":"m-attack"},` +
		`"nested":{"value":"nested-attack"},"deep":[{"key":{"value":"deep-attack"}}],` +
		`"escaped":"e-\u0041\n\"x\"","tagged":"\"t-attack\"","verbatim":"v-attack"}`
	var destination struct {
		Field    string                        `json:"field"`
		Named    unmarshalNamed                `json:"named"`
		Slice    []string                      `json:"slice"`
		Array    [2]string                     `json:"array"`
		Pointer  *string                       `json:"pointer"`
		Map      map[string]string             `json:"map"`
		Nested   unmarshalNested               `json:"nested"`
		Deep     []map[string]*unmarshalNested `json:"deep"`
		Escaped  string                        `json:"escaped"`
		Tagged   unmarshalNamed                `json:"tagged,string"`
		Verbatim string                        `json:"verbatim"`
	}
	tainted := taint.TaintBytes(ctx, bodySource, []byte(document))
	require.NoError(t, json.Unmarshal(tainted, &destination))

	require.NotNil(t, destination.Pointer)
	require.Len(t, destination.Deep, 1)
	require.NotNil(t, destination.Deep[0]["key"])
	for name, test := range map[string]struct{ got, want string }{
		"struct field":      {destination.Field, "f-attack"},
		"named type":        {string(destination.Named), "n-attack"},
		"slice element 0":   {destination.Slice[0], "s0-attack"},
		"slice element 1":   {destination.Slice[1], "s1-attack"},
		"array element 0":   {destination.Array[0], "a0-attack"},
		"array element 1":   {destination.Array[1], "a1-attack"},
		"pointer":           {*destination.Pointer, "p-attack"},
		"typed map value":   {destination.Map["key"], "m-attack"},
		"nested struct":     {destination.Nested.Value, "nested-attack"},
		"deep nested value": {destination.Deep[0]["key"].Value, "deep-attack"},
		"escapes":           {destination.Escaped, "e-A\n\"x\""},
		",string":           {string(destination.Tagged), "t-attack"},
		"verbatim":          {destination.Verbatim, "v-attack"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.want, test.got)
			requireCoarseTaint(t, ctx, test.got, document)
		})
	}
}

// TestUnmarshalUsesTheRawTokenOfEachString checks that each string gets the
// taint of its own raw token, not of a token next to it (the string wrapper
// must do no read after ReadValue). Only one token of the document is tainted.
func TestUnmarshalUsesTheRawTokenOfEachString(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	const document = `{"a":"x-value","b":"y-value","c":"\"z-value\"","d":["w-value"]}`
	for _, token := range []string{`"x-value"`, `"y-value"`, `"\"z-value\""`, `"w-value"`} {
		t.Run(token, func(t *testing.T) {
			low := strings.Index(document, token)
			require.Positive(t, low)
			tainted := taintedWindow(t, ctx, document, low, low+len(token))
			var destination struct {
				A string   `json:"a"`
				B string   `json:"b"`
				C string   `json:"c,string"`
				D []string `json:"d"`
			}
			require.NoError(t, json.Unmarshal(tainted, &destination))
			require.Len(t, destination.D, 1)
			for _, value := range []struct {
				got, token string
			}{
				{destination.A, `"x-value"`},
				{destination.B, `"y-value"`},
				{destination.C, `"\"z-value\""`},
				{destination.D[0], `"w-value"`},
			} {
				require.Equal(t, value.token == token, taint.IsTaintedString(value.got), "the value %q (token %s)", value.got, value.token)
			}
		})
	}
}

// TestUnmarshalStringTagInnerNull checks the ,string rule: a ,string value
// whose inner token is null (plain or escaped) does not change the
// destination, and does not taint it. A ,string value that is equal to the
// string that the destination holds already gets the taint of its token.
func TestUnmarshalStringTagInnerNull(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	for name, document := range map[string]string{
		"plain":       `{"value":"null"}`,
		"escaped":     `{"value":"\u006eull"}`,
		"all escaped": `{"value":"\u006e\u0075\u006c\u006c"}`,
	} {
		t.Run(name, func(t *testing.T) {
			destination := struct {
				Value string `json:"value,string"`
			}{Value: "unchanged"}
			require.NoError(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(document)), &destination))
			require.Equal(t, "unchanged", destination.Value)
			requireClean(t, destination.Value)
		})
	}
	t.Run("same value", func(t *testing.T) {
		const document = `{"value":"\"same\""}`
		destination := struct {
			Value string `json:"value,string"`
		}{Value: "same"}
		require.NoError(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(document)), &destination))
		require.Equal(t, "same", destination.Value)
		requireCoarseTaint(t, ctx, destination.Value, document)
	})
	t.Run("string null", func(t *testing.T) {
		// Without the ,string option, "null" is a string.
		const document = `{"value":"null"}`
		destination := struct {
			Value string `json:"value"`
		}{Value: "unchanged"}
		require.NoError(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(document)), &destination))
		require.Equal(t, "null", destination.Value)
		requireCoarseTaint(t, ctx, destination.Value, document)
	})
	t.Run("json null", func(t *testing.T) {
		destination := struct {
			Value string `json:"value"`
		}{Value: "unchanged"}
		require.NoError(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(`{"value":null}`)), &destination))
		require.Equal(t, "unchanged", destination.Value)
		requireClean(t, destination.Value)
	})
}

type unmarshalCustomJSON string

// UnmarshalJSON sets a constant: a conversion of data would get the taint of
// data from the runtime hooks, not from the JSON aspects.
func (c *unmarshalCustomJSON) UnmarshalJSON([]byte) error {
	*c = "custom-json"
	return nil
}

type unmarshalCustomText string

// UnmarshalText sets a constant, as UnmarshalJSON of unmarshalCustomJSON.
func (c *unmarshalCustomText) UnmarshalText([]byte) error {
	*c = "custom-text"
	return nil
}

// TestUnmarshalFailedConversionsDoNotPropagate checks that a string whose own
// conversion fails gets no taint, and that the other strings of the document
// keep their own taint (propagation is per string, with no whole-document
// staging).
func TestUnmarshalFailedConversionsDoNotPropagate(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	type pair struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	t.Run("semantic error after a valid string", func(t *testing.T) {
		const document = `{"a":"x-value","b":1}`
		destination := pair{B: "unchanged"}
		require.Error(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(document)), &destination))
		require.Equal(t, pair{A: "x-value", B: "unchanged"}, destination)
		requireCoarseTaint(t, ctx, destination.A, document)
		requireClean(t, destination.B)
	})
	t.Run("semantic error before a valid string", func(t *testing.T) {
		const document = `{"a":1,"b":"y-value"}`
		destination := pair{A: "unchanged"}
		require.Error(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(document)), &destination))
		require.Equal(t, pair{A: "unchanged", B: "y-value"}, destination)
		requireClean(t, destination.A)
		requireCoarseTaint(t, ctx, destination.B, document)
	})
	t.Run("syntax error", func(t *testing.T) {
		destination := pair{A: "unchanged", B: "unchanged"}
		require.Error(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(`{"a":"x-value","b":`)), &destination))
		requireClean(t, destination.A)
		requireClean(t, destination.B)
	})
	t.Run(",string with a number", func(t *testing.T) {
		destination := struct {
			Value string `json:"value,string"`
		}{Value: "unchanged"}
		require.Error(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(`{"value":"123"}`)), &destination))
		require.Equal(t, "unchanged", destination.Value)
		requireClean(t, destination.Value)
	})
	t.Run("custom unmarshalers", func(t *testing.T) {
		var destination struct {
			JSON unmarshalCustomJSON `json:"json"`
			Text unmarshalCustomText `json:"text"`
		}
		require.NoError(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(`{"json":"j-value","text":"t-value"}`)), &destination))
		require.Equal(t, unmarshalCustomJSON("custom-json"), destination.JSON)
		require.Equal(t, unmarshalCustomText("custom-text"), destination.Text)
		requireClean(t, string(destination.JSON))
		requireClean(t, string(destination.Text))
	})
}

// TestUnmarshalKeysAndInterfaceValues checks that, on the v2 variant,
// map keys and interface{} strings get the taint of their exact token. The
// JSON aspects of the v1 variant keep them clean.
func TestUnmarshalKeysAndInterfaceValues(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	// Each key and interface{} string has an escape. On the v1 variant, the
	// runtime hooks taint a verbatim key or interface{} string of tainted
	// bytes (a conversion of the input bytes), but not an unquoted copy.
	const document = `{"typed":{"k\u002dattack":"v-attack"},"any":{"ak\u002dattack":"av\u002dattack","l\u0069st":["al\u002dattack"]},"single":"as\u002dattack"}`
	var destination struct {
		Typed  map[string]string `json:"typed"`
		Any    map[string]any    `json:"any"`
		Single any               `json:"single"`
	}
	require.NoError(t, json.Unmarshal(taint.TaintBytes(ctx, bodySource, []byte(document)), &destination))
	require.Equal(t, "v-attack", destination.Typed["k-attack"])
	requireCoarseTaint(t, ctx, destination.Typed["k-attack"], document)

	check := func(value string) {
		t.Helper()
		if unmarshalTaintsKeysAndAny {
			requireCoarseTaint(t, ctx, value, document)
		} else {
			requireClean(t, value)
		}
	}
	for key := range destination.Typed {
		check(key)
	}
	for key, value := range destination.Any {
		check(key)
		if list, ok := value.([]any); ok {
			require.Equal(t, []any{"al-attack"}, list)
			check(list[0].(string))
			continue
		}
		require.Equal(t, "av-attack", value)
		check(value.(string))
	}
	require.Equal(t, "as-attack", destination.Single)
	check(destination.Single.(string))
}

// TestUnmarshalKeysAndInterfaceValuesUseTheirOwnToken checks the v2 coverage of
// map keys and interface{} strings with one tainted token at a time: on the v2
// variant, the escaped map key or interface{} string of that token gets its
// taint, and the other keys and strings stay clean. On the v1 variant, only the
// typed map values get taint.
func TestUnmarshalKeysAndInterfaceValuesUseTheirOwnToken(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	// Each string has an escape: the runtime hooks do not taint an unquoted
	// copy (see TestUnmarshalKeysAndInterfaceValues).
	const document = `{"typed":{"k\u002d1":"v\u002d1","k\u002d2":"v\u002d2"},` +
		`"any":{"a\u002d1":"x\u002d1","l\u0069st":["y\u002d1",{"n\u002d1":"z\u002d1"}]}}`
	tokens := []struct {
		token, decoded string
		// typedValue: a typed map value gets taint on all variants.
		typedValue bool
	}{
		{`"k\u002d1"`, "k-1", false},
		{`"v\u002d1"`, "v-1", true},
		{`"k\u002d2"`, "k-2", false},
		{`"v\u002d2"`, "v-2", true},
		{`"a\u002d1"`, "a-1", false},
		{`"x\u002d1"`, "x-1", false},
		{`"l\u0069st"`, "list", false},
		{`"y\u002d1"`, "y-1", false},
		{`"n\u002d1"`, "n-1", false},
		{`"z\u002d1"`, "z-1", false},
	}
	for _, selected := range tokens {
		t.Run(selected.token, func(t *testing.T) {
			low := strings.Index(document, selected.token)
			require.Positive(t, low)
			tainted := taintedWindow(t, ctx, document, low, low+len(selected.token))
			var destination struct {
				Typed map[string]string `json:"typed"`
				Any   map[string]any    `json:"any"`
			}
			require.NoError(t, json.Unmarshal(tainted, &destination))

			// The decoded strings, by their decoded form. A key is the
			// string of the map key.
			decoded := map[string]string{}
			for key, value := range destination.Typed {
				decoded[key], decoded[value] = key, value
			}
			for key := range destination.Any {
				decoded[key] = key
			}
			decoded["x-1"] = destination.Any["a-1"].(string)
			list := destination.Any["list"].([]any)
			require.Len(t, list, 2)
			decoded["y-1"] = list[0].(string)
			for key, value := range list[1].(map[string]any) {
				decoded[key], decoded[value.(string)] = key, value.(string)
			}
			require.Len(t, decoded, len(tokens))

			for _, item := range tokens {
				got, ok := decoded[item.decoded]
				require.True(t, ok, "no decoded string %q", item.decoded)
				if item.token == selected.token && (item.typedValue || unmarshalTaintsKeysAndAny) {
					requireCoarseTaint(t, ctx, got, document)
				} else {
					requireClean(t, got)
				}
			}
		})
	}
}

// cacheRuns makes the strings of each attempt of the string cache tests new
// strings (also with -count): the string cache must not hold them yet.
var cacheRuns atomic.Int32

// cacheAttempts is the maximum number of attempts of a string cache test. An
// attempt is valid only when the three decodes of the attempt used the same
// string cache. sync.Pool can drop the pooled decoder (the race detector
// drops 1 Put in 4, and a GC can drop the pool), and two strings can use the
// same slot of the cache. Then the test tries again with new strings.
const cacheAttempts = 50

// cacheMode is one way to decode strings with encoding/json or
// encoding/json/v2.
type cacheMode struct {
	// document returns a document with the strings probe and value. An empty
	// string does not go into the string cache.
	document func(probe, value string) string
	// decode decodes document, and returns its probe and value strings.
	decode func(t *testing.T, document []byte) (probe, value string)
}

// objectDocument is the document of an object mode.
func objectDocument(probe, value string) string {
	return `{"probe":"` + probe + `","value":"` + value + `"}`
}

// legacyTyped decodes a struct with json.Unmarshal: the string arshaler on
// the v2 variant, literalStore on the v1 variant.
var legacyTyped = cacheMode{document: objectDocument, decode: func(t *testing.T, document []byte) (string, string) {
	t.Helper()
	var destination struct {
		Probe string `json:"probe"`
		Value string `json:"value"`
	}
	require.NoError(t, json.Unmarshal(document, &destination))
	return destination.Probe, destination.Value
}}

// requireCacheKeepsRequestsApart checks that the string cache of a pooled
// decoder gives no taint to a later request, and checks the string cache guard.
// The decoder of encoding/json/v2 keeps a string cache across Unmarshal calls.
// While request A is live:
//
//  1. a decode of clean bytes puts the string probe in the cache;
//  2. request A decodes tainted bytes of the string value with the mode
//     tainted;
//  3. request B decodes clean bytes of probe and value with the mode clean.
//
// The decode 3 must give a clean value: it must not get the tainted string of
// request A from the cache. When the probe string of the decode 3 is the
// string of the decode 1, the decode 3 used the cache of the decode 1. With
// one P and no GC, the decode 2 then used the same pooled decoder:
// sync.Pool.Get gives the private item of the P first, and the decode 1 put
// the decoder there. (A GC moves the pool to its victim cache: then the
// decode 2 can get a different decoder, and the decode 3 can get the decoder
// of the decode 1 from the victim cache.) On the v1 variant, the decoder has no string cache: one attempt is
// sufficient.
func requireCacheKeepsRequestsApart(t *testing.T, tainted, clean cacheMode) {
	t.Helper()
	// One P and no GC (see above). Restore the old values at the end of the
	// test.
	previousProcs := runtime.GOMAXPROCS(1)
	previousGC := debug.SetGCPercent(-1)
	t.Cleanup(func() {
		debug.SetGCPercent(previousGC)
		runtime.GOMAXPROCS(previousProcs)
	})
	ctxA, _ := beginRequest(t)
	ctxB, scopeB := beginRequest(t)
	_ = taint.TaintString(ctxB, bodySource, "other value")
	for range cacheAttempts {
		run := strconv.Itoa(int(cacheRuns.Add(1)))
		probe, value := "probe-"+run, "cached-"+run

		first, _ := clean.decode(t, []byte(clean.document(probe, "")))
		require.Equal(t, probe, first)

		taintedProbe, taintedValue := tainted.decode(t, taint.TaintBytes(ctxA, bodySource, []byte(tainted.document("", value))))
		require.Empty(t, taintedProbe)
		require.Equal(t, value, taintedValue)
		// The runtime hooks or the JSON aspects taint the string of
		// request A. Then the string cache can keep a tainted string.
		require.True(t, taint.IsTaintedString(taintedValue), "the value of request A is not tainted")

		last, got := clean.decode(t, []byte(clean.document(probe, value)))
		require.Equal(t, probe, last)
		require.Equal(t, value, got)
		if unmarshalHasStringCache && unsafe.StringData(first) != unsafe.StringData(last) {
			// The decode 3 did not use the cache of the decode 1.
			continue
		}
		requireClean(t, got)
		require.Equal(t, 1, sourceCount(t, scopeB), "request B must get no source of request A")
		return
	}
	t.Fatalf("no attempt of %d used one string cache for the three decodes", cacheAttempts)
}

// TestUnmarshalStringCacheKeepsRequestsApart checks the string cache guard
// with json.Unmarshal of a struct. The tests of the direct encoding/json/v2
// modes are in unmarshal_v2_test.go.
func TestUnmarshalStringCacheKeepsRequestsApart(t *testing.T) {
	requireWoven(t)
	requireCacheKeepsRequestsApart(t, legacyTyped, legacyTyped)
}

// TestUnmarshalGateDoesNotCallTheBridge checks the cheap gate of the string
// wrapper: with no active request, or with an active request and no indexed
// root, the Literal callback does not run.
func TestUnmarshalGateDoesNotCallTheBridge(t *testing.T) {
	requireWoven(t)
	var calls atomic.Int32
	counting := callbacks()
	literal := counting.Literal
	counting.Literal = func(document, item []byte, value reflect.Value, err error) {
		calls.Add(1)
		literal(document, item, value, err)
	}
	jsonbridge.Register(counting)
	t.Cleanup(func() { jsonbridge.Register(callbacks()) })

	var destination document
	require.NoError(t, json.Unmarshal([]byte(`{"value":"no request"}`), &destination))
	require.Zero(t, calls.Load())

	ctx, scope := beginRequest(t)
	require.NoError(t, json.Unmarshal([]byte(`{"value":"no root"}`), &destination))
	require.Zero(t, calls.Load())

	// Control: with an indexed root, the callback runs, also for clean bytes.
	_ = taint.TaintString(ctx, bodySource, "other value")
	require.NoError(t, json.Unmarshal([]byte(`{"value":"clean"}`), &destination))
	require.Positive(t, calls.Load())
	requireClean(t, destination.Value)
	require.Equal(t, 1, sourceCount(t, scope))
}

// unmarshalAllocationDocument has a string field, a ,string field, and a
// slice of strings.
const unmarshalAllocationDocument = `{"value":"v-value","tagged":"\"t-value\"","list":["l0","l1"]}`

type unmarshalAllocationDestination struct {
	Value  string   `json:"value"`
	Tagged string   `json:"tagged,string"`
	List   []string `json:"list"`
}

// unmarshalAllocations returns the allocations of one json.Unmarshal of
// document.
func unmarshalAllocations(t *testing.T, document []byte) float64 {
	t.Helper()
	return testing.AllocsPerRun(200, func() {
		var destination unmarshalAllocationDestination
		if err := json.Unmarshal(document, &destination); err != nil {
			t.Fatal(err)
		}
	})
}

// TestUnmarshalCleanAllocations checks the allocations of json.Unmarshal of
// clean bytes. With the gate off (no active request, or an active request
// with no indexed root), the count is the count with no request. With the
// gate open (an active request that has an indexed root), the v2 wrapper adds
// no allocation: the string cache keeps the clean strings, and the inner-null
// test of the ,string field uses a stack buffer.
func TestUnmarshalCleanAllocations(t *testing.T) {
	requireWoven(t)
	if raceEnabled {
		// json.Unmarshal takes its decoder from a sync.Pool, and the race
		// detector makes sync.Pool drop items at random.
		t.Skip("the allocation count of json.Unmarshal is not stable with the race detector")
	}
	document := []byte(unmarshalAllocationDocument)
	inactive := unmarshalAllocations(t, document)
	require.Equal(t, float64(unmarshalCleanAllocations), inactive, "no request: the count of the unwoven build")

	ctx, _ := beginRequest(t)
	require.False(t, jsonbridge.Active())
	require.Equal(t, inactive, unmarshalAllocations(t, document), "the gate is off")

	_ = taint.TaintString(ctx, bodySource, "other value")
	require.True(t, jsonbridge.Active())
	require.Equal(t, inactive+activeStringTagAllocations, unmarshalAllocations(t, document), "the gate is open")
}

// TestUnmarshalAllocationBaseline pins the allocations of json.Unmarshal of
// clean bytes with no active request, in the unwoven and in the woven build
// (unmarshalCleanAllocations). Thus TestUnmarshalCleanAllocations compares
// the woven build with the unwoven build, not only with itself.
func TestUnmarshalAllocationBaseline(t *testing.T) {
	if raceEnabled {
		t.Skip("the allocation count of json.Unmarshal is not stable with the race detector")
	}
	require.Equal(t, float64(unmarshalCleanAllocations), unmarshalAllocations(t, []byte(unmarshalAllocationDocument)))
}

// BenchmarkUnmarshalStringsInactive measures json.Unmarshal of strings with no
// active request. Compare the allocations of an unwoven and of a woven run.
func BenchmarkUnmarshalStringsInactive(b *testing.B) {
	document := []byte(unmarshalAllocationDocument)
	b.ReportAllocs()
	for b.Loop() {
		var destination unmarshalAllocationDestination
		if err := json.Unmarshal(document, &destination); err != nil {
			b.Fatal(err)
		}
	}
}
