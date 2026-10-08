// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanJSONReaderChainDoesNotReport(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, _ *http.Request) {
		reader := bytes.NewReader([]byte(`{"quoted":"\"customers\""}`))
		chain, err := testapp.BuildJSONChain(reader)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, testapp.JSONName("customers"), chain.Document.Quoted)
		assert.Equal(t, "SELECT id FROM customers", chain.Query)
		assertChainRanges(t, ctx, chain.Query, nil)
		_, err = db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, nil)
	require.Empty(t, event.Vulnerabilities)
	require.Empty(t, event.Sources)
}

func TestUnsupportedJSONValueDoesNotInventSinkProvenance(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, _ *http.Request) {
		document := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody}, []byte(`{"value":"secret"}`))
		var destination struct {
			Value customString `json:"value"`
		}
		if !assert.NoError(t, json.Unmarshal(document, &destination)) {
			return
		}
		assert.Equal(t, customString("sanitized"), destination.Value)
		chain := testapp.BuildSQLChain("id!", string(destination.Value))
		assert.Equal(t, "SELECT id FROM sanitized", chain.Query)
		assertChainRanges(t, ctx, chain.Query, nil)
		_, err := db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, nil)
	require.Empty(t, event.Vulnerabilities)
}

func TestRepeatedJSONLiteralsKeepSeparateSourcesAndMarks(t *testing.T) {
	requireWoven(t)
	requestEvent(t, func(ctx context.Context, _ *http.Request) {
		first := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "first"}, []byte(`"same"`))
		second := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "second"}, []byte(`"same"`))
		active := request.ActiveStore()
		key, ok := store.BytesKey(first)
		if !assert.True(t, ok) {
			return
		}
		var snapshot store.Snapshot
		if !assert.True(t, active.Lookup(key, &snapshot)) {
			return
		}
		entry, ok := snapshot.At(0)
		if !assert.True(t, ok) {
			return
		}
		owner, ok := entry.Handle(active)
		if !assert.True(t, ok) {
			return
		}
		var marked ranges.Set
		if !assert.True(t, ranges.MarkAll(&marked, &entry.Ranges, taint.VulnerabilityTypeSqlInjection).Valid) {
			return
		}
		first = bytes.Clone(first)
		_, ok = owner.AdoptBytes(first, &marked)
		if !assert.True(t, ok) {
			return
		}
		var secureMarks taint.Marks
		taint.VisitBytes(ctx, first, func(found taint.Range) bool {
			secureMarks = found.Marks
			return false
		})
		assert.True(t, secureMarks.Has(taint.VulnerabilityTypeSqlInjection))

		decoded, err := testapp.DecodeRepeatedJSON(first, second)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, testapp.JSONName("same"), decoded.First)
		assert.Equal(t, "same", decoded.Second)
		assertChainRanges(t, ctx, string(decoded.First), []taint.Range{{
			Length: 4,
			Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "first"},
				Value:  `"same"`,
			},
			Marks: secureMarks,
		}})
		assertChainRanges(t, ctx, decoded.Second, []taint.Range{{
			Length: 4,
			Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "second"},
				Value:  `"same"`,
			},
		}})
	}, nil)
}

// jsonModes are the two ways of the tests below to decode the request body:
// io.ReadAll and json.Unmarshal, or json.NewDecoder(r.Body).Decode.
var jsonModes = []string{"unmarshal", "decoder"}

// decodeBody decodes the body of r into destination with mode.
func decodeBody(mode string, r *http.Request, destination any) error {
	if mode == "decoder" {
		return json.NewDecoder(r.Body).Decode(destination)
	}
	document, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(document, destination)
}

// bodyEvent sends a POST request with body, runs operation in its handler,
// and returns the event of the request.
func bodyEvent(t *testing.T, body string, operation func(context.Context, *http.Request)) model.Event {
	t.Helper()
	incoming, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://iast.test/", strings.NewReader(body))
	require.NoError(t, err)
	return captureRequestEvent(t, operation, incoming)
}

// TestJSONNullFormsKeepTheDestination checks that a JSON null (merge
// semantics) and a ,string value whose inner token is null, in plain and in
// escaped form, keep the old destination and add no taint. The same results
// apply to all variants.
func TestJSONNullFormsKeepTheDestination(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	for _, test := range []struct {
		name, document string
		stringTag      bool
	}{
		{name: "null", document: `{"value":null}`},
		{name: ",string null", document: `{"value":null}`, stringTag: true},
		{name: ",string inner null", document: `{"value":"null"}`, stringTag: true},
		{name: ",string escaped inner null", document: `{"value":"\u006eull"}`, stringTag: true},
		{name: ",string all escaped inner null", document: `{"value":"\u006e\u0075\u006c\u006c"}`, stringTag: true},
	} {
		for _, mode := range jsonModes {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				event := bodyEvent(t, test.document, func(ctx context.Context, r *http.Request) {
					plain := struct {
						Value string `json:"value"`
					}{Value: "unchanged"}
					tagged := struct {
						Value string `json:"value,string"`
					}{Value: "unchanged"}
					destination, value := any(&plain), &plain.Value
					if test.stringTag {
						destination, value = &tagged, &tagged.Value
					}
					if !assert.NoError(t, decodeBody(mode, r, destination)) {
						return
					}
					assert.Equal(t, "unchanged", *value)
					assertChainRanges(t, ctx, *value, nil)
					_, err := db.ExecContext(ctx, testapp.BuildTableQuery(*value))
					assert.NoError(t, err)
				})
				requireSQLFindings(t, event, 0, "")
			})
		}
	}
}

// TestJSONStringTagEqualToTheHeldStringPropagates checks that a ,string value
// that is equal to the string that the destination holds already gets the
// taint of its token. A clean decode first puts the string in the
// destination (and in the string cache of the v2 decoder).
func TestJSONStringTagEqualToTheHeldStringPropagates(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"value":"\"same\""}`
	for _, mode := range jsonModes {
		t.Run(mode, func(t *testing.T) {
			event := bodyEvent(t, document, func(ctx context.Context, r *http.Request) {
				var destination struct {
					Value string `json:"value,string"`
				}
				if !assert.NoError(t, json.Unmarshal([]byte(document), &destination)) {
					return
				}
				assert.Equal(t, "same", destination.Value)
				assertChainRanges(t, ctx, destination.Value, nil)
				if !assert.NoError(t, decodeBody(mode, r, &destination)) {
					return
				}
				assert.Equal(t, "same", destination.Value)
				assertChainRanges(t, ctx, destination.Value, bodyRange(len("same"), document))
				_, err := db.ExecContext(ctx, testapp.BuildTableQuery(destination.Value))
				assert.NoError(t, err)
			})
			requireSQLFindings(t, event, 1, document)
		})
	}
}

// cacheRuns makes the strings of each attempt of
// TestJSONStringCacheKeepsRequestsApart new strings (also with -count): the
// string cache must not hold them yet.
var cacheRuns atomic.Int32

// cacheAttempts is the maximum number of attempts of
// TestJSONStringCacheKeepsRequestsApart. An attempt is valid only when its
// three decodes used the same string cache. sync.Pool can drop the pooled
// decoder (the race detector drops some Put calls, and a GC can drop the
// pool), and two strings can use the same slot of the cache. Then the test
// tries again with new strings.
const cacheAttempts = 50

// TestJSONStringCacheKeepsRequestsApart checks the string cache of the v2
// decoder across two live requests: a later request must not get the taint
// of a cached string:
//
//  1. request B decodes clean bytes, and the string probe goes into the cache;
//  2. request A decodes tainted bytes of the string value;
//  3. request B decodes clean bytes of probe and value.
//
// The decode 3 must give a clean value: request B must not get the tainted
// string of request A from the cache. When the probe string of the decode 3
// is the string of the decode 1, the decode 3 used the cache of the decode 1.
// With one P and no GC, the decode 2 then used the same pooled decoder. On
// the v1 variant, the decoder has no string cache: one attempt is
// sufficient.
func TestJSONStringCacheKeepsRequestsApart(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	previousProcs := runtime.GOMAXPROCS(1)
	previousGC := debug.SetGCPercent(-1)
	t.Cleanup(func() {
		debug.SetGCPercent(previousGC)
		runtime.GOMAXPROCS(previousProcs)
	})
	type pair struct {
		Probe string `json:"probe"`
		Value string `json:"value"`
	}
	document := func(probe, value string) string { return `{"probe":"` + probe + `","value":"` + value + `"}` }
	decode := func(document []byte) (destination pair) {
		assert.NoError(t, json.Unmarshal(document, &destination))
		return destination
	}

	live := newLiveServer(t)
	requestA := live.start("a", "")
	requestB := live.start("b", "")
	sourcesB := requestB.sourceCount()
	reused := false
	for attempt := range cacheAttempts {
		run := strconv.Itoa(int(cacheRuns.Add(1)))
		probe, value := "probe-"+run, "cached-"+run
		var first, tainted, last pair
		requestB.do(func() { first = decode([]byte(document(probe, ""))) })
		requestA.do(func() {
			tainted = decode(taint.TaintBytes(requestA.ctx, taint.Source{Origin: taint.OriginHttpRequestBody}, []byte(document("", value))))
		})
		requestB.do(func() { last = decode([]byte(document(probe, value))) })
		require.Equal(t, probe, first.Probe)
		require.Equal(t, value, tainted.Value)
		require.True(t, taint.IsTaintedString(tainted.Value), "the value of request A is not tainted")
		require.Equal(t, pair{Probe: probe, Value: value}, last)
		if unmarshalHasStringCache && unsafe.StringData(first.Probe) != unsafe.StringData(last.Probe) {
			// The decode 3 did not use the cache of the decode 1.
			continue
		}
		reused = true
		t.Logf("attempt %d used one string cache for the three decodes", attempt+1)
		assertNoTaint(t, last.Value)
		requestB.do(func() { requestB.sink(db, last.Value) })
		require.Equal(t, sourcesB, requestB.sourceCount(), "request B got a source")
		break
	}
	requestA.end()
	requestB.end()
	require.True(t, reused, "no attempt of %d used one string cache for the three decodes", cacheAttempts)
	requireSQLFindings(t, requestA.event(), 0, "")
	requireSQLFindings(t, requestB.event(), 0, "")
}

type textString string

// UnmarshalText sets a constant: a conversion of its input would get the
// taint of the input from the runtime hooks, not from the JSON aspects.
func (value *textString) UnmarshalText([]byte) error { *value = "sanitized_text"; return nil }

// TestJSONCustomUnmarshalersStayClean checks that the results of a custom
// UnmarshalJSON and UnmarshalText method get no taint, with both decode
// modes.
func TestJSONCustomUnmarshalersStayClean(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"json":"secret_json","text":"secret_text"}`
	for _, mode := range jsonModes {
		t.Run(mode, func(t *testing.T) {
			event := bodyEvent(t, document, func(ctx context.Context, r *http.Request) {
				var destination struct {
					JSON customString `json:"json"`
					Text textString   `json:"text"`
				}
				if !assert.NoError(t, decodeBody(mode, r, &destination)) {
					return
				}
				assert.Equal(t, customString("sanitized"), destination.JSON)
				assert.Equal(t, textString("sanitized_text"), destination.Text)
				for _, value := range []string{string(destination.JSON), string(destination.Text)} {
					assertChainRanges(t, ctx, value, nil)
					_, err := db.ExecContext(ctx, testapp.BuildTableQuery(value))
					assert.NoError(t, err)
				}
			})
			requireSQLFindings(t, event, 0, "")
		})
	}
}

// TestJSONSemanticErrorKeepsEarlierStrings checks a valid string member
// followed by a semantic error (a number into a string field): the decode
// returns the error, the earlier string is tainted, and the failed field is
// not changed (propagation is per string, with no whole-document staging).
func TestJSONSemanticErrorKeepsEarlierStrings(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"a":"x_value","b":1}`
	for _, mode := range jsonModes {
		t.Run(mode, func(t *testing.T) {
			event := bodyEvent(t, document, func(ctx context.Context, r *http.Request) {
				destination := struct {
					A string `json:"a"`
					B string `json:"b"`
				}{B: "unchanged"}
				var typeError *json.UnmarshalTypeError
				assert.ErrorAs(t, decodeBody(mode, r, &destination), &typeError)
				assert.Equal(t, "x_value", destination.A)
				assert.Equal(t, "unchanged", destination.B)
				assertChainRanges(t, ctx, destination.A, bodyRange(len("x_value"), document))
				assertChainRanges(t, ctx, destination.B, nil)
				for _, value := range []string{destination.A, destination.B} {
					_, err := db.ExecContext(ctx, testapp.BuildTableQuery(value))
					assert.NoError(t, err)
				}
			})
			requireSQLFindings(t, event, 1, document)
		})
	}
}
