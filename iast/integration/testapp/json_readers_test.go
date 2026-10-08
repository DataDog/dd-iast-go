// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests of this file check json.Decoder on the readers of HTTP request
// bodies (see "Request body readers" in the README). The decoder
// attributes a value only to the one exclusive owner of its reader. All
// other cases are a miss: the value has no taint, no request gets a source,
// and no request reports a finding. The expected results are the same on
// all variants of encoding/json. Only the source value can differ
// (decoderSourcePrefix).

// jsonValue is the destination of the decoded documents of these tests.
type jsonValue struct {
	Value string `json:"value"`
}

// decodeValue decodes one document with decoder, and returns its value.
func decodeValue(t *testing.T, decoder *json.Decoder) string {
	t.Helper()
	var destination jsonValue
	assert.NoError(t, decoder.Decode(&destination))
	return destination.Value
}

// valueDocuments returns count documents with the values prefix-000 and up.
func valueDocuments(prefix string, count int) (documents, values []string) {
	for index := range count {
		values = append(values, fmt.Sprintf("%s_%03d", prefix, index))
		documents = append(documents, fmt.Sprintf(`{"value":%q}`, values[index]))
	}
	return documents, values
}

// chunkReader returns at most size bytes for each Read.
type chunkReader struct {
	reader io.Reader
	size   int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	return r.reader.Read(p[:min(len(p), r.size)])
}

// requireNoFindings checks that each request has no finding and no source.
func requireNoFindings(t *testing.T, requests ...*liveRequest) {
	t.Helper()
	for _, request := range requests {
		event := request.event()
		require.Empty(t, event.Vulnerabilities, "the request %s has a finding", request.name)
		require.Empty(t, event.Sources, "the request %s has a source", request.name)
	}
}

// TestJSONDecoderFirstSourceIsTheBody checks that the decoder works when the
// body is the first source of the request: the request scope has only a
// reader binding on the body, and the process has no indexed root before
// the Decode.
func TestJSONDecoderFirstSourceIsTheBody(t *testing.T) {
	requireWoven(t)
	ctx, scope, created := taintrequest.Begin(context.Background())
	require.True(t, created)
	defer scope.Finish()
	require.True(t, scope.Active())
	const document = `{"value":"from_body"}`
	body := strings.NewReader(document)
	require.True(t, taintrequest.BindReader(ctx, body))
	active := taintrequest.ActiveStore()
	require.NotNil(t, active)
	// The requests of the other tests end before their client gets the
	// response, but wait for a short time to be sure.
	require.Eventually(t, func() bool { return active.IndexedRoots().Load() == 0 }, liveTimeout, time.Millisecond,
		"the process has an indexed root before the Decode")
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	require.Zero(t, analysis.SourceCount())

	var destination jsonValue
	require.NoError(t, json.NewDecoder(body).Decode(&destination))
	require.Equal(t, "from_body", destination.Value)
	assertChainRanges(t, ctx, destination.Value, bodyRange(len(destination.Value), document))
	require.Equal(t, 1, analysis.SourceCount())
	require.Positive(t, active.IndexedRoots().Load(), "the clone of the value is an indexed root")
}

// TestJSONDecoderMoreLoopOverBody checks a More loop over a JSON array of
// 100 objects from one bound body: the string of each item is tainted with
// the body source of the item.
func TestJSONDecoderMoreLoopOverBody(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	documents, values := valueDocuments("item", 100)
	event := bodyEvent(t, "["+strings.Join(documents, ",")+"]", func(ctx context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		token, err := decoder.Token()
		assert.NoError(t, err)
		assert.Equal(t, json.Delim('['), token)
		index := 0
		last := ""
		for decoder.More() && index < len(values) {
			value := decodeValue(t, decoder)
			assert.Equal(t, values[index], value)
			assertChainRanges(t, ctx, value, bodyRange(len(value), documents[index]))
			last = value
			index++
		}
		assert.Equal(t, len(values), index)
		_, err = db.ExecContext(ctx, testapp.BuildTableQuery(last))
		assert.NoError(t, err)
	})
	requireSQLFindings(t, event, 1, documents[len(documents)-1])
}

// TestJSONDecoderValueAcrossBufferRefills checks one 20 KiB document from a
// reader that gives 7 bytes for each Read: the decoder fills its buffer many
// times for one value, and the value is tainted.
func TestJSONDecoderValueAcrossBufferRefills(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	large := strings.Repeat("0123456789abcdef", 20<<10/16)
	document := `{"value":"` + large + `"}`
	event := bodyEvent(t, document, func(ctx context.Context, r *http.Request) {
		chunks := &chunkReader{reader: r.Body, size: 7}
		// A custom reader has no binding. The test binds it as an
		// instrumented wrapper with one input does.
		taintrequest.PropagateReader(r.Body, chunks)
		value := decodeValue(t, json.NewDecoder(chunks))
		assert.Equal(t, large, value)
		assertChainRanges(t, ctx, value, bodyRange(len(value), document))
		_, err := db.ExecContext(ctx, testapp.BuildTableQuery(value))
		assert.NoError(t, err)
	})
	require.Len(t, event.Vulnerabilities, 1)
	require.Equal(t, 1, countType(event, constants.VulnerabilityTypeSqlInjection))
	require.Len(t, event.Sources, 1)
	// The event truncates the source value.
	require.Equal(t, constants.OriginHttpRequestBody, event.Sources[0].Origin)
}

// TestJSONDecoderReusedAcrossRequests checks a decoder that request A makes
// on its body. A decodes one value, and the decoder has buffered the second
// value. Then request B decodes the second value. The value is never
// attributed to B: it is a miss when A ended, and it goes to A while A is
// live.
func TestJSONDecoderReusedAcrossRequests(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const first, second = `{"value":"first"}`, `{"value":"second"}`
	for _, aLive := range []bool{false, true} {
		name := "A ended"
		if aLive {
			name = "A live"
		}
		t.Run(name, func(t *testing.T) {
			live := newLiveServer(t)
			requestB := live.start("b", "")
			requestA := live.start("a", first+second)
			sourcesB := requestB.sourceCount()
			var decoder *json.Decoder
			var firstValue string
			requestA.do(func() {
				decoder = json.NewDecoder(requestA.r.Body)
				firstValue = decodeValue(t, decoder)
				assertChainRanges(t, requestA.ctx, firstValue, bodyRange(len(firstValue), first))
				buffered, err := io.ReadAll(decoder.Buffered())
				assert.NoError(t, err)
				assert.Equal(t, second, string(buffered), "the decoder must buffer the second value")
				requestA.sink(db, firstValue)
			})
			require.Equal(t, "first", firstValue)
			if !aLive {
				requestA.end()
			}

			var secondValue string
			requestB.do(func() {
				secondValue = decodeValue(t, decoder)
				assertChainRanges(t, requestB.ctx, secondValue, nil)
				requestB.sink(db, secondValue)
			})
			require.Equal(t, "second", secondValue)
			require.Equal(t, sourcesB, requestB.sourceCount(), "the value was attributed to request B")
			if aLive {
				requestA.do(func() {
					assertChainRanges(t, requestA.ctx, secondValue, bodyRange(len(secondValue), second))
					requestA.sink(db, secondValue)
				})
				requestA.end()
			} else {
				assertNoTaint(t, secondValue)
			}
			requestB.end()

			requireNoFindings(t, requestB)
			event := requestA.event()
			if !aLive {
				requireSQLFindings(t, event, 1, first)
				return
			}
			require.Len(t, event.Vulnerabilities, 2)
			require.Equal(t, 2, countType(event, constants.VulnerabilityTypeSqlInjection))
			require.ElementsMatch(t, []model.Source{
				model.NewSourceString(constants.OriginHttpRequestBody, "", first),
				model.NewSourceString(constants.OriginHttpRequestBody, "", second),
			}, event.Sources)
			assertSourcesReferenced(t, event)
		})
	}
}

// TestJSONDecoderTwoOwners checks that a reader with the bytes of two live
// requests is a miss for both.
func TestJSONDecoderTwoOwners(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	t.Run("MultiReader of the two bodies", func(t *testing.T) {
		live := newLiveServer(t)
		requestA := live.start("a", `{"value":"from_a"}`)
		requestB := live.start("b", `{"value":"from_b"}`)
		sourcesA, sourcesB := requestA.sourceCount(), requestB.sourceCount()
		var values []string
		requestB.do(func() {
			decoder := json.NewDecoder(io.MultiReader(requestA.r.Body, requestB.r.Body))
			values = append(values, decodeValue(t, decoder), decodeValue(t, decoder))
			for _, value := range values {
				requestB.sink(db, value)
			}
		})
		require.Equal(t, []string{"from_a", "from_b"}, values)
		requestA.do(func() {
			for _, value := range values {
				requestA.sink(db, value)
			}
		})
		for _, value := range values {
			assertNoTaint(t, value)
		}
		require.Equal(t, sourcesA, requestA.sourceCount())
		require.Equal(t, sourcesB, requestB.sourceCount())
		requestA.end()
		requestB.end()
		requireNoFindings(t, requestA, requestB)
	})
	t.Run("second owner binds the reader after NewDecoder", func(t *testing.T) {
		const first = `{"value":"first"}`
		live := newLiveServer(t)
		requestA := live.start("a", first+`{"value":"second"}`)
		requestB := live.start("b", "")
		sourcesB := requestB.sourceCount()
		var decoder *json.Decoder
		var firstValue, secondValue string
		requestA.do(func() {
			decoder = json.NewDecoder(requestA.r.Body)
			firstValue = decodeValue(t, decoder)
			assertChainRanges(t, requestA.ctx, firstValue, bodyRange(len(firstValue), first))
			requestA.sink(db, firstValue)
		})
		require.Equal(t, "first", firstValue)
		requestB.do(func() {
			assert.True(t, taintrequest.BindReader(requestB.ctx, requestA.r.Body))
		})
		sourcesA := requestA.sourceCount()
		requestA.do(func() {
			secondValue = decodeValue(t, decoder)
			requestA.sink(db, secondValue)
		})
		require.Equal(t, "second", secondValue)
		assertNoTaint(t, secondValue)
		require.Equal(t, sourcesA, requestA.sourceCount())
		require.Equal(t, sourcesB, requestB.sourceCount())
		requestA.end()
		requestB.end()
		requireSQLFindings(t, requestA.event(), 1, first)
		requireNoFindings(t, requestB)
	})
}

// TestJSONDecoderMultiReaderInputs checks the io.MultiReader rules: a
// MultiReader of more than 8 inputs, or with a clean input, is a miss. A
// MultiReader of the body only (the control) keeps the taint.
func TestJSONDecoderMultiReaderInputs(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	t.Run("8+1 inputs of two requests", func(t *testing.T) {
		live := newLiveServer(t)
		requestA := live.start("a", `{"value":"from_a"}`)
		requestB := live.start("b", `{"value":"from_b"}`)
		sourcesA, sourcesB := requestA.sourceCount(), requestB.sourceCount()
		var decoder *json.Decoder
		var fromA, fromB string
		requestB.do(func() {
			inputs := make([]io.Reader, 0, 9)
			for range 7 {
				inputs = append(inputs, strings.NewReader(" "))
			}
			inputs = append(inputs, requestA.r.Body, requestB.r.Body)
			decoder = json.NewDecoder(io.MultiReader(inputs...))
			fromA = decodeValue(t, decoder)
			requestB.sink(db, fromA)
		})
		requestA.do(func() {
			fromB = decodeValue(t, decoder)
			requestA.sink(db, fromA)
			requestA.sink(db, fromB)
		})
		requestB.do(func() { requestB.sink(db, fromB) })
		require.Equal(t, "from_a", fromA)
		require.Equal(t, "from_b", fromB)
		assertNoTaint(t, fromA)
		assertNoTaint(t, fromB)
		require.Equal(t, sourcesA, requestA.sourceCount())
		require.Equal(t, sourcesB, requestB.sourceCount())
		requestA.end()
		requestB.end()
		requireNoFindings(t, requestA, requestB)
	})
	for name, test := range map[string]struct {
		build     func(body io.Reader) io.Reader
		propagate bool
	}{
		"body only (control)": {build: func(body io.Reader) io.Reader { return io.MultiReader(body) }, propagate: true},
		"clean prefix": {build: func(body io.Reader) io.Reader {
			return io.MultiReader(bytes.NewReader([]byte(" ")), body)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			const document = `{"value":"from_a"}`
			live := newLiveServer(t)
			requestA := live.start("a", document)
			sourcesA := requestA.sourceCount()
			var value string
			requestA.do(func() {
				value = decodeValue(t, json.NewDecoder(test.build(requestA.r.Body)))
				requestA.sink(db, value)
			})
			require.Equal(t, "from_a", value)
			if !test.propagate {
				assertNoTaint(t, value)
				require.Equal(t, sourcesA, requestA.sourceCount())
			}
			requestA.end()
			if test.propagate {
				requireSQLFindings(t, requestA.event(), 1, document)
				return
			}
			requireNoFindings(t, requestA)
		})
	}
}

// TestJSONDecoderContendedLookup checks that an incomplete reader lookup (a
// contended lock) is a miss: at NewDecoder, all values miss; at the second
// Decode, the second value and all later values miss (one failed proof
// closes the decoder).
func TestJSONDecoderContendedLookup(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	documents, values := valueDocuments("item", 3)
	body := strings.Join(documents, "")
	t.Run("at NewDecoder", func(t *testing.T) {
		event := bodyEvent(t, body, func(ctx context.Context, r *http.Request) {
			restore := taintrequest.SetIncompleteReaderLookupsForTest()
			decoder := json.NewDecoder(r.Body)
			restore()
			for _, want := range values {
				value := decodeValue(t, decoder)
				assert.Equal(t, want, value)
				assertNoTaint(t, value)
				_, err := db.ExecContext(ctx, testapp.BuildTableQuery(value))
				assert.NoError(t, err)
			}
		})
		requireSQLFindings(t, event, 0, "")
	})
	t.Run("at the second Decode", func(t *testing.T) {
		event := bodyEvent(t, body, func(ctx context.Context, r *http.Request) {
			decoder := json.NewDecoder(r.Body)
			for index, want := range values {
				restore := func() {}
				if index == 1 {
					restore = taintrequest.SetIncompleteReaderLookupsForTest()
				}
				value := decodeValue(t, decoder)
				restore()
				assert.Equal(t, want, value)
				if index == 0 {
					assertChainRanges(t, ctx, value, bodyRange(len(value), documents[0]))
				} else {
					assertNoTaint(t, value)
				}
				_, err := db.ExecContext(ctx, testapp.BuildTableQuery(value))
				assert.NoError(t, err)
			}
		})
		requireSQLFindings(t, event, 1, documents[0])
	})
}

// TestJSONDecoderPooledReaderReset checks the pool pattern: request A makes a
// bufio.Reader of its body, and request B resets it to its own body or to clean
// bytes while A is live. The Read guard removes the exclusivity of A (see
// "Request body readers" in the README), thus the Decode in B is a miss: no new
// source in A, no source in B.
func TestJSONDecoderPooledReaderReset(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	for _, target := range []string{"body of B", "clean"} {
		t.Run(target, func(t *testing.T) {
			live := newLiveServer(t)
			requestA := live.start("a", `{"value":"from_a"}`)
			requestB := live.start("b", `{"value":"from_b"}`)
			var buffered *bufio.Reader
			requestA.do(func() { buffered = bufio.NewReader(requestA.r.Body) })
			sourcesA, sourcesB := requestA.sourceCount(), requestB.sourceCount()
			var value string
			requestB.do(func() {
				if target == "clean" {
					buffered.Reset(strings.NewReader(`{"value":"from_b"}`))
				} else {
					buffered.Reset(requestB.r.Body)
				}
				value = decodeValue(t, json.NewDecoder(buffered))
				requestB.sink(db, value)
			})
			requestA.do(func() { requestA.sink(db, value) })
			require.Equal(t, "from_b", value)
			assertNoTaint(t, value)
			require.Equal(t, sourcesA, requestA.sourceCount())
			require.Equal(t, sourcesB, requestB.sourceCount())
			requestA.end()
			requestB.end()
			requireNoFindings(t, requestA, requestB)
		})
	}
}

// TestJSONDecoderWrappersKeepTaint checks the readers that keep the exclusive
// binding of the body (the Read guard keeps io.LimitReader and bufio.NewReader
// exclusive): the value is tainted with the body source, and the request
// reports the finding.
func TestJSONDecoderWrappersKeepTaint(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	for name, wrap := range map[string]func(w http.ResponseWriter, body io.ReadCloser) io.Reader{
		"MaxBytesReader": func(w http.ResponseWriter, body io.ReadCloser) io.Reader {
			return http.MaxBytesReader(w, body, 1<<20)
		},
		"TeeReader": func(_ http.ResponseWriter, body io.ReadCloser) io.Reader {
			return io.TeeReader(body, new(bytes.Buffer))
		},
		"TeeReader of MaxBytesReader": func(w http.ResponseWriter, body io.ReadCloser) io.Reader {
			return io.TeeReader(http.MaxBytesReader(w, body, 1<<20), new(bytes.Buffer))
		},
		"bufio.NewReader": func(_ http.ResponseWriter, body io.ReadCloser) io.Reader {
			return bufio.NewReader(body)
		},
		"LimitReader": func(_ http.ResponseWriter, body io.ReadCloser) io.Reader {
			return io.LimitReader(body, 1<<20)
		},
	} {
		t.Run(name, func(t *testing.T) {
			const document = `{"value":"wrapped"}`
			live := newLiveServer(t)
			request := live.start("a", document)
			var value string
			request.do(func() {
				value = decodeValue(t, json.NewDecoder(wrap(request.w, request.r.Body)))
				assertChainRanges(t, request.ctx, value, bodyRange(len(value), document))
				request.sink(db, value)
			})
			require.Equal(t, "wrapped", value)
			request.end()
			requireSQLFindings(t, request.event(), 1, document)
		})
	}
}

// TestJSONDecoderGzipBodyIsMiss checks a documented miss: a gzip.Reader has
// no reader binding, thus its values have no taint.
func TestJSONDecoderGzipBodyIsMiss(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err := writer.Write([]byte(`{"value":"compressed"}`))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	event := bodyEvent(t, compressed.String(), func(ctx context.Context, r *http.Request) {
		reader, err := gzip.NewReader(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		value := decodeValue(t, json.NewDecoder(reader))
		assert.Equal(t, "compressed", value)
		assertNoTaint(t, value)
		_, err = db.ExecContext(ctx, testapp.BuildTableQuery(value))
		assert.NoError(t, err)
	})
	requireSQLFindings(t, event, 0, "")
}

// TestJSONDecoderNDJSONSourceValues checks the source value of each Decode
// of an NDJSON body. The v2 source value is the value only; the v1 source
// value starts with the newline before the second value
// (decoderSourcePrefix). The strings have two bytes: the taint store does
// not taint a value of less than two bytes (internal/taint/store/root.go).
func TestJSONDecoderNDJSONSourceValues(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const first, second = `{"a":"x1"}`, `{"a":"y1"}`
	secondSource := decoderSourcePrefix("\n") + second
	event := bodyEvent(t, first+"\n"+second, func(ctx context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		for _, want := range []struct{ value, source string }{{"x1", first}, {"y1", secondSource}} {
			var destination struct {
				A string `json:"a"`
			}
			if !assert.NoError(t, decoder.Decode(&destination)) {
				return
			}
			assert.Equal(t, want.value, destination.A)
			assertChainRanges(t, ctx, destination.A, bodyRange(len(destination.A), want.source))
			_, err := db.ExecContext(ctx, testapp.BuildTableQuery(destination.A))
			assert.NoError(t, err)
		}
	})
	require.Len(t, event.Vulnerabilities, 2)
	require.Equal(t, 2, countType(event, constants.VulnerabilityTypeSqlInjection))
	require.ElementsMatch(t, []model.Source{
		model.NewSourceString(constants.OriginHttpRequestBody, "", first),
		model.NewSourceString(constants.OriginHttpRequestBody, "", secondSource),
	}, event.Sources)
	assertSourcesReferenced(t, event)
}

// TestJSONDecoderNumberTokens checks a json.Number from a number token of
// the body. On the v2 variant, it is tainted with the body source (the
// string conversion of the tainted clone). On the v1 variant, it is clean
// (decoderTaintsNumberTokens).
func TestJSONDecoderNumberTokens(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"number":12345}`
	event := bodyEvent(t, document, func(ctx context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		var destination struct {
			Number json.Number `json:"number"`
		}
		if !assert.NoError(t, decoder.Decode(&destination)) {
			return
		}
		value := destination.Number.String()
		assert.Equal(t, "12345", value)
		if decoderTaintsNumberTokens {
			assert.True(t, taint.VisitString(ctx, value, func(found taint.Range) bool {
				assert.Equal(t, taint.OriginHttpRequestBody, found.Source.Origin)
				assert.Equal(t, document, found.Source.Value)
				return true
			}), "the number is not tainted")
		} else {
			assertNoTaint(t, value)
		}
		_, err := db.ExecContext(ctx, testapp.BuildTableQuery(value))
		assert.NoError(t, err)
	})
	if !decoderTaintsNumberTokens {
		requireSQLFindings(t, event, 0, "")
		return
	}
	// The SQL analyzer redacts a number literal, thus the event does not
	// keep the source value.
	require.Len(t, event.Vulnerabilities, 1)
	require.Equal(t, 1, countType(event, constants.VulnerabilityTypeSqlInjection))
	require.Len(t, event.Sources, 1)
	require.Equal(t, constants.OriginHttpRequestBody, event.Sources[0].Origin)
	assertSourcesReferenced(t, event)
}
