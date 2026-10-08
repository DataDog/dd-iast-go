// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The tests of this file check the Decode consumer of the reader binding rules
// (see the internal/taint/store package doc): NewDecoder takes the owner token
// of its reader BEFORE the first byte flows, and each Decode revalidates the
// token (rule (f)) before it attributes a value. A miss is never attributed
// to any request. The tests run on all variants: on the v2 variant, the
// ReadValue wrapper of Decode uses the same token.

func requireWoven(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
}

func beginRequest(t *testing.T) (context.Context, *request.Scope) {
	t.Helper()
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	return ctx, scope
}

// boundReader returns a reader of data that is bound exclusively to the
// request of ctx, as the HTTP entry binds a request body.
func boundReader(t *testing.T, ctx context.Context, data string) *strings.Reader {
	t.Helper()
	reader := strings.NewReader(data)
	require.True(t, request.BindReader(ctx, reader))
	return reader
}

// sourceCount returns the number of sources of the request of scope.
func sourceCount(t *testing.T, scope *request.Scope) int {
	t.Helper()
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	return analysis.SourceCount()
}

type document struct {
	Value string `json:"value"`
}

// decodeOne decodes one document with decoder.
func decodeOne(t *testing.T, decoder *json.Decoder) string {
	t.Helper()
	var destination document
	require.NoError(t, decoder.Decode(&destination))
	return destination.Value
}

// requireMiss checks that value has no taint, and that no scope of scopes got
// a source after the counts of before.
func requireMiss(t *testing.T, value string, scopes []*request.Scope, before []int) {
	t.Helper()
	require.False(t, taint.IsTaintedString(value), "the value %q is tainted", value)
	for index, scope := range scopes {
		if analysis, ok := scope.Analysis(); ok {
			require.Equal(t, before[index], analysis.SourceCount(), "request %d got a source", index)
		}
	}
}

// requireBodySource checks that value has the body source of the request of
// ctx, when the decoder propagates on this variant.
func requireBodySource(t *testing.T, ctx context.Context, value, wantSource string) {
	t.Helper()
	if !decoderPropagates {
		require.False(t, taint.IsTaintedString(value))
		return
	}
	source := ""
	taint.VisitString(ctx, value, func(found taint.Range) bool {
		if found.Source.Origin == taint.OriginHttpRequestBody {
			source = found.Source.Value
		}
		return false
	})
	require.Equal(t, wantSource, source, "the value %q has not the body source of the request", value)
}

// TestDecoderMultiReaderOfTwoRequestsIsMiss checks that when the reader of the
// decoder is bound to two live requests, no request gets the bytes. (An older
// version gave the bytes to each bound request.)
func TestDecoderMultiReaderOfTwoRequestsIsMiss(t *testing.T) {
	requireWoven(t)
	ctxA, scopeA := beginRequest(t)
	ctxB, scopeB := beginRequest(t)
	bodyA := boundReader(t, ctxA, `{"value":"from-a"}`)
	bodyB := boundReader(t, ctxB, `{"value":"from-b"}`)
	decoder := json.NewDecoder(io.MultiReader(bodyA, bodyB))
	scopes := []*request.Scope{scopeA, scopeB}
	before := []int{sourceCount(t, scopeA), sourceCount(t, scopeB)}
	requireMiss(t, decodeOne(t, decoder), scopes, before)
	requireMiss(t, decodeOne(t, decoder), scopes, before)
}

func TestDecoderMultiReaderInputs(t *testing.T) {
	requireWoven(t)
	for name, test := range map[string]struct {
		build     func(body io.Reader) io.Reader
		propagate bool
	}{
		"one input (control)": {build: func(body io.Reader) io.Reader { return io.MultiReader(body) }, propagate: true},
		"clean first input": {build: func(body io.Reader) io.Reader {
			return io.MultiReader(strings.NewReader(" "), body)
		}},
		"empty clean input": {build: func(body io.Reader) io.Reader {
			return io.MultiReader(strings.NewReader(""), body)
		}},
		"nine inputs": {build: func(body io.Reader) io.Reader {
			empty := func() io.Reader { return io.MultiReader() }
			return io.MultiReader(body, empty(), empty(), empty(), empty(), empty(), empty(), empty(), empty())
		}},
	} {
		t.Run(name, func(t *testing.T) {
			ctxA, scopeA := beginRequest(t)
			_, scopeB := beginRequest(t)
			const data = `{"value":"from-a"}`
			body := boundReader(t, ctxA, data)
			before := []int{sourceCount(t, scopeA), sourceCount(t, scopeB)}
			value := decodeOne(t, json.NewDecoder(test.build(body)))
			require.Equal(t, "from-a", value)
			if test.propagate {
				requireBodySource(t, ctxA, value, data)
				require.Zero(t, sourceCount(t, scopeB))
				return
			}
			requireMiss(t, value, []*request.Scope{scopeA, scopeB}, before)
		})
	}
}

// chunkReader returns at most size bytes for each Read, and calls onRead
// (when it is not nil) before each Read.
type chunkReader struct {
	reader io.Reader
	size   int
	onRead func()
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.onRead != nil {
		r.onRead()
	}
	return r.reader.Read(p[:min(len(p), r.size)])
}

// documents returns count documents with the values prefix-000 and up.
func documents(prefix string, count int) (body string, values []string) {
	var builder strings.Builder
	for index := range count {
		values = append(values, fmt.Sprintf("%s-%03d", prefix, index))
		fmt.Fprintf(&builder, `{"value":%q}`, values[index])
	}
	return builder.String(), values
}

func TestDecoderContendedLookupIsMiss(t *testing.T) {
	requireWoven(t)
	t.Run("at NewDecoder", func(t *testing.T) {
		ctx, scope := beginRequest(t)
		body := boundReader(t, ctx, `{"value":"first"}{"value":"second"}`)
		restore := request.SetIncompleteReaderLookupsForTest()
		t.Cleanup(restore)
		decoder := json.NewDecoder(body)
		restore()
		before := []int{sourceCount(t, scope)}
		requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, before)
		requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, before)
	})
	t.Run("at the second Decode", func(t *testing.T) {
		ctx, scope := beginRequest(t)
		data, values := documents("item", 3)
		chunks := &chunkReader{reader: strings.NewReader(data), size: len(`{"value":"item-000"}`)}
		require.True(t, request.BindReader(ctx, chunks))
		decoder := json.NewDecoder(chunks)
		requireBodySource(t, ctx, decodeOne(t, decoder), `{"value":"item-000"}`)
		restore := request.SetIncompleteReaderLookupsForTest()
		t.Cleanup(restore)
		before := []int{sourceCount(t, scope)}
		requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, before)
		restore()
		// One failed proof closes the decoder for good.
		value := decodeOne(t, decoder)
		require.Equal(t, values[2], value)
		requireMiss(t, value, []*request.Scope{scope}, before)
	})
}

func TestDecoderMadeWithNoActiveRequestIsMiss(t *testing.T) {
	requireWoven(t)
	if request.ActiveStore() != nil {
		t.Skip("a request is active")
	}
	reader := strings.NewReader(`{"value":"late"}`)
	decoder := json.NewDecoder(reader)
	ctx, scope := beginRequest(t)
	require.True(t, request.BindReader(ctx, reader))
	requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, []int{sourceCount(t, scope)})
}

// TestDecoderBoundAfterNewDecoderIsMiss checks rule (f) at Decode: a second
// owner that binds the reader after NewDecoder and ends before Decode makes
// the value a miss. A reader that gets its only binding after NewDecoder is
// a miss too.
func TestDecoderBoundAfterNewDecoderIsMiss(t *testing.T) {
	requireWoven(t)
	for name, wrap := range map[string]func(io.Reader) io.Reader{
		"root":  func(reader io.Reader) io.Reader { return reader },
		"bufio": func(reader io.Reader) io.Reader { return bufio.NewReaderSize(reader, 16) },
	} {
		t.Run(name+"/second owner ended before Decode", func(t *testing.T) {
			ctxA, scopeA := beginRequest(t)
			ctxB, scopeB := beginRequest(t)
			body := boundReader(t, ctxA, `{"value":"from-a"}`)
			decoder := json.NewDecoder(wrap(body))
			require.True(t, request.BindReader(ctxB, body))
			scopeB.Finish()
			requireMiss(t, decodeOne(t, decoder), []*request.Scope{scopeA}, []int{sourceCount(t, scopeA)})
		})
		t.Run(name+"/own rebind keeps the taint", func(t *testing.T) {
			ctxA, _ := beginRequest(t)
			const data = `{"value":"from-a"}`
			body := boundReader(t, ctxA, data)
			decoder := json.NewDecoder(wrap(body))
			require.True(t, request.BindReader(ctxA, body))
			requireBodySource(t, ctxA, decodeOne(t, decoder), data)
		})
	}
	t.Run("only binding after NewDecoder", func(t *testing.T) {
		ctx, scope := beginRequest(t)
		reader := strings.NewReader(`{"value":"late"}`)
		decoder := json.NewDecoder(reader)
		require.True(t, request.BindReader(ctx, reader))
		requireMiss(t, decodeOne(t, decoder), []*request.Scope{scope}, []int{sourceCount(t, scope)})
	})
}

// retargets returns six retargets of the guarded wrappers. Each builds a
// guarded wrapper over body, and returns a function that retargets it to other.
func retargets() map[string]func(body io.Reader) (wrapper io.Reader, retarget func(other io.Reader)) {
	limited := func(body io.Reader) *io.LimitedReader { return io.LimitReader(body, 1<<20).(*io.LimitedReader) }
	return map[string]func(body io.Reader) (io.Reader, func(io.Reader)){
		"lr.R = other": func(body io.Reader) (io.Reader, func(io.Reader)) {
			lr := limited(body)
			return lr, func(other io.Reader) { lr.R = other }
		},
		"*lr = LimitedReader{other}": func(body io.Reader) (io.Reader, func(io.Reader)) {
			lr := limited(body)
			return lr, func(other io.Reader) { *lr = io.LimitedReader{R: other, N: 1 << 20} }
		},
		"br.Reset(other)": func(body io.Reader) (io.Reader, func(io.Reader)) {
			br := bufio.NewReaderSize(body, 16)
			return br, func(other io.Reader) { br.Reset(other) }
		},
		"*br = *bufio.NewReader(other)": func(body io.Reader) (io.Reader, func(io.Reader)) {
			br := bufio.NewReaderSize(body, 16)
			return br, func(other io.Reader) { *br = *bufio.NewReader(other) }
		},
	}
}

// TestDecoderRetargetAfterBindIsMiss checks each retarget of retargets through
// json.NewDecoder(w).Decode: the new target is clean or the body of a live
// request B. The value is a miss: no new source in A, no source in B.
func TestDecoderRetargetAfterBindIsMiss(t *testing.T) {
	requireWoven(t)
	for name, build := range retargets() {
		for _, target := range []string{"clean", "body of B"} {
			t.Run(name+"/"+target, func(t *testing.T) {
				ctxA, scopeA := beginRequest(t)
				ctxB, scopeB := beginRequest(t)
				body := boundReader(t, ctxA, `{"value":"from-a"}`)
				wrapper, retarget := build(body)
				var other io.Reader = strings.NewReader(`{"value":"other"}`)
				if target == "body of B" {
					other = boundReader(t, ctxB, `{"value":"other"}`)
				}
				before := []int{sourceCount(t, scopeA), sourceCount(t, scopeB)}
				// NewDecoder takes the token before the retarget: no byte of
				// the new target flowed yet.
				decoder := json.NewDecoder(wrapper)
				retarget(other)
				value := decodeOne(t, decoder)
				require.Equal(t, "other", value)
				requireMiss(t, value, []*request.Scope{scopeA, scopeB}, before)
			})
		}
	}
}

// TestDecoderRetargetBetweenTwoDecodes checks that a retarget between two
// Decode calls keeps the first value tainted, and makes all later values a
// miss. The reader gives one document for each Read, so that each Decode
// reads from the wrapper.
func TestDecoderRetargetBetweenTwoDecodes(t *testing.T) {
	requireWoven(t)
	for name, build := range retargets() {
		t.Run(name, func(t *testing.T) {
			ctxA, scopeA := beginRequest(t)
			data, _ := documents("from-a", 1)
			chunks := &chunkReader{reader: strings.NewReader(data), size: len(data)}
			require.True(t, request.BindReader(ctxA, chunks))
			wrapper, retarget := build(chunks)
			decoder := json.NewDecoder(wrapper)
			first := decodeOne(t, decoder)
			require.Equal(t, "from-a-000", first)
			requireBodySource(t, ctxA, first, data)

			cleanData, values := documents("clean", 2)
			retarget(&chunkReader{reader: strings.NewReader(cleanData), size: len(`{"value":"clean-000"}`)})
			before := []int{sourceCount(t, scopeA)}
			for _, want := range values {
				value := decodeOne(t, decoder)
				require.Equal(t, want, value)
				requireMiss(t, value, []*request.Scope{scopeA}, before)
			}
			requireBodySource(t, ctxA, first, data)
		})
	}
}

func TestDecoderLimitReaderOfRetargetedBufioIsMiss(t *testing.T) {
	requireWoven(t)
	ctxA, scopeA := beginRequest(t)
	body := boundReader(t, ctxA, `{"value":"from-a"}`)
	buffered := bufio.NewReaderSize(body, 16)
	decoder := json.NewDecoder(io.LimitReader(buffered, 1<<20))
	buffered.Reset(strings.NewReader(`{"value":"clean"}`))
	value := decodeOne(t, decoder)
	require.Equal(t, "clean", value)
	requireMiss(t, value, []*request.Scope{scopeA}, []int{sourceCount(t, scopeA)})
}

// guardedWrappers returns the wrappers of the "normal use" tests: each keeps
// an exclusive binding while it is not retargeted.
func guardedWrappers() map[string]func(io.Reader) io.Reader {
	return map[string]func(io.Reader) io.Reader{
		"bufio":            func(body io.Reader) io.Reader { return bufio.NewReader(body) },
		"limit":            func(body io.Reader) io.Reader { return io.LimitReader(body, 1<<20) },
		"limit over bufio": func(body io.Reader) io.Reader { return io.LimitReader(bufio.NewReader(body), 1<<20) },
	}
}

// TestDecoderMoreLoopThroughGuardedWrappers checks that normal use keeps the
// taint: the string of EVERY item of a More loop over 100 objects is tainted
// with the body source.
func TestDecoderMoreLoopThroughGuardedWrappers(t *testing.T) {
	requireWoven(t)
	for name, wrap := range guardedWrappers() {
		t.Run(name, func(t *testing.T) {
			ctx, scope := beginRequest(t)
			items, values := documents("item", 100)
			items = strings.ReplaceAll(items, "}{", "},{")
			body := boundReader(t, ctx, "["+items+"]")
			decoder := json.NewDecoder(wrap(body))
			token, err := decoder.Token()
			require.NoError(t, err)
			require.Equal(t, json.Delim('['), token)
			index := 0
			for decoder.More() {
				value := decodeOne(t, decoder)
				require.Equal(t, values[index], value)
				if decoderPropagates {
					require.True(t, taint.VisitString(ctx, value, func(found taint.Range) bool {
						require.Equal(t, taint.OriginHttpRequestBody, found.Source.Origin)
						require.Contains(t, found.Source.Value, value)
						return false
					}), "item %d is not tainted", index)
				} else {
					require.False(t, taint.IsTaintedString(value))
				}
				index++
			}
			require.Equal(t, 100, index)
			if decoderPropagates {
				require.Equal(t, 100, sourceCount(t, scope))
			}
		})
	}
}

// TestDecoderResetNilAfterLastDecode checks that a Reset with no Read after
// it (the pool Put pattern) does not remove the taint of the earlier values.
func TestDecoderResetNilAfterLastDecode(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	const data = `{"value":"from-a"}`
	body := boundReader(t, ctx, data)
	buffered := bufio.NewReader(body)
	value := decodeOne(t, json.NewDecoder(buffered))
	buffered.Reset(nil)
	requireBodySource(t, ctx, value, data)
}

// noRequestSink makes the decoders escape, so that the allocation counts of
// the woven and of the unwoven build are the same.
var noRequestSink *json.Decoder

// TestNewDecoderGateOffDoesNotAllocate checks that the NewDecoder capture adds
// no allocation when no request is active.
func TestNewDecoderGateOffDoesNotAllocate(t *testing.T) {
	if request.ActiveStore() != nil {
		t.Skip("a request is active")
	}
	reader := strings.NewReader(`{"value":"clean"}`)
	require.Equal(t, float64(newDecoderAllocations), testing.AllocsPerRun(200, func() {
		noRequestSink = json.NewDecoder(reader)
	}))
}

// TestNewDecoderLooksUpOnlyForAConsumer checks that NewDecoder looks up the
// owner of its reader only when Decode can use the token. Each variant installs
// a consumer: the v1 Document path (EnableV1), or the v2 Decode path
// (EnableV2). Thus NewDecoder does one lookup on each variant. A request is
// active and the reader is bound, thus with no consumer, only the consumer gate
// can stop the lookup. With no consumer, NewDecoder adds no allocation.
func TestNewDecoderLooksUpOnlyForAConsumer(t *testing.T) {
	requireWoven(t)
	ctx, _ := beginRequest(t)
	reader := boundReader(t, ctx, `{"value":"from-a"}`)
	var lookups atomic.Int32
	counting := callbacks()
	owner := counting.Owner
	counting.Owner = func(reader any) jsonbridge.OwnerToken {
		lookups.Add(1)
		return owner(reader)
	}
	jsonbridge.Register(counting)
	t.Cleanup(func() { jsonbridge.Register(callbacks()) })

	noRequestSink = json.NewDecoder(reader)
	require.Equal(t, int32(1), lookups.Load(), "NewDecoder must take the owner token for the Decode of this variant")

	restoreV1 := jsonbridge.SetV1ForTest(false)
	t.Cleanup(restoreV1)
	restoreV2 := jsonbridge.SetV2ForTest(false)
	t.Cleanup(restoreV2)
	lookups.Store(0)
	noRequestSink = json.NewDecoder(reader)
	require.Zero(t, lookups.Load(), "NewDecoder looked up the reader, but no Decode uses the token")
	require.Equal(t, float64(newDecoderAllocations), testing.AllocsPerRun(200, func() {
		noRequestSink = json.NewDecoder(reader)
	}))
	require.Zero(t, lookups.Load())
}

// decodeResult is the result of a Decode in another goroutine.
type decodeResult struct {
	value string
	err   error
}

// decodeIn decodes one document with decoder in a new goroutine (the
// goroutine of request B), after it received the decoder through a channel.
// The test goroutine waits for the result: no Decode is concurrent.
func decodeIn(decoder *json.Decoder) decodeResult {
	decoders := make(chan *json.Decoder)
	results := make(chan decodeResult)
	go func() {
		received := <-decoders
		var destination document
		err := received.Decode(&destination)
		results <- decodeResult{value: destination.Value, err: err}
	}()
	decoders <- decoder
	return <-results
}

// TestDecoderHandedToAnotherRequest checks that a decoder made in request A
// and given to request B through a channel attributes its values only to the
// exclusive owner of its reader (A), never to B. A decoded the first value,
// and the decoder has buffered the second one. When A ends, or when B binds
// the reader, the value that B decodes is a miss.
func TestDecoderHandedToAnotherRequest(t *testing.T) {
	requireWoven(t)
	for name, test := range map[string]struct {
		change func(t *testing.T, scopeA *request.Scope, ctxB context.Context, body io.Reader)
		miss   bool
	}{
		"A still owns the bytes": {change: func(*testing.T, *request.Scope, context.Context, io.Reader) {}},
		"A ended": {change: func(_ *testing.T, scopeA *request.Scope, _ context.Context, _ io.Reader) {
			scopeA.Finish()
		}, miss: true},
		"B binds the reader": {change: func(t *testing.T, _ *request.Scope, ctxB context.Context, body io.Reader) {
			require.True(t, request.BindReader(ctxB, body))
		}, miss: true},
	} {
		t.Run(name, func(t *testing.T) {
			ctxA, scopeA := beginRequest(t)
			ctxB, scopeB := beginRequest(t)
			const first, second = `{"value":"first"}`, `{"value":"second"}`
			body := boundReader(t, ctxA, first+second)
			decoder := json.NewDecoder(body)
			value := decodeOne(t, decoder)
			require.Equal(t, "first", value)
			requireBodySource(t, ctxA, value, first)
			test.change(t, scopeA, ctxB, body)

			before := []int{sourceCount(t, scopeB)}
			scopes := []*request.Scope{scopeB}
			if _, ok := scopeA.Analysis(); ok {
				before = append(before, sourceCount(t, scopeA))
				scopes = append(scopes, scopeA)
			}
			result := decodeIn(decoder)
			require.NoError(t, result.err)
			require.Equal(t, "second", result.value)
			require.Zero(t, sourceCount(t, scopeB), "the value was attributed to request B")
			if test.miss {
				requireMiss(t, result.value, scopes, before)
				return
			}
			// The v1 source value keeps the bytes that the decoder buffered
			// before the value.
			requireBodySource(t, ctxA, result.value, second)
		})
	}
}

// ownerCounters returns the loss counters of the exclusive owner of reader.
func ownerCounters(t *testing.T, reader any) store.Counters {
	t.Helper()
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count, complete := store.LookupReaderValue(request.ActiveStore(), reader, refs[:])
	require.True(t, complete)
	require.Equal(t, 1, count)
	owner, ok := refs[0].Handle()
	require.True(t, ok)
	return owner.Counters()
}

// TestDecoderOversizedValueThenValidValue checks that a value larger than
// the root limit is a miss with one bytes drop for the owner, and that it
// does not close the decoder: the next valid value is tainted.
func TestDecoderOversizedValueThenValidValue(t *testing.T) {
	requireWoven(t)
	ctx, scope := beginRequest(t)
	large := `{"value":"` + strings.Repeat("x", store.MaxRootBytes) + `"}`
	const small = `{"value":"small"}`
	body := boundReader(t, ctx, large+small)
	decoder := json.NewDecoder(body)
	drops := ownerCounters(t, body).Bytes
	sources := sourceCount(t, scope)

	value := decodeOne(t, decoder)
	require.Len(t, value, store.MaxRootBytes)
	requireMiss(t, value, []*request.Scope{scope}, []int{sources})
	wantDrops := drops
	if decoderPropagates {
		wantDrops++
	}
	require.Equal(t, wantDrops, ownerCounters(t, body).Bytes, "the oversized value must count one bytes drop")

	value = decodeOne(t, decoder)
	require.Equal(t, "small", value)
	requireBodySource(t, ctx, value, small)
	if decoderPropagates {
		require.Equal(t, sources+1, sourceCount(t, scope))
	}
	require.Equal(t, wantDrops, ownerCounters(t, body).Bytes)
}
