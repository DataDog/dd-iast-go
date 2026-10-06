// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// These tests use the real heap taint bits: they need a woven runtime.

func requireBits(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if !heapbits.Enabled() {
		t.Skip("the heap taint bits are not supported on this platform")
	}
}

func beginActive(t *testing.T) (*request.Scope, request.Analysis) {
	t.Helper()
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = request.MaxAnalyses
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	return scope, analysis
}

var escape atomic.Pointer[[]byte]

// heapCopy returns a heap copy of the parts with their bits, as the runtime
// concatenation hook does.
func heapCopy(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, n)
	escape.Store(&out)
	at := 0
	for _, p := range parts {
		copy(out[at:], p)
		if len(p) != 0 {
			heapbits.Copy(unsafe.Pointer(&out[at]), unsafe.Pointer(&p[0]), uintptr(len(p)))
		}
		at += len(p)
	}
	return out
}

func addr(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

func attributed(t *testing.T, a request.Analysis, value []byte) []string {
	t.Helper()
	var r request.Attribution
	a.AttributeBytes(value, &r)
	var out []string
	for i := 0; i < r.N; i++ {
		s := r.Segments[i]
		label := "foreign"
		if source, ok := r.Source(i); ok {
			label = source.Origin.String() + ":" + source.Name
		}
		out = append(out, fmt.Sprintf("%d-%d=%s", s.Start, s.Start+s.Length, label))
	}
	return out
}

func TestWovenFirstActivationTurnsTheGateOn(t *testing.T) {
	requireBits(t)
	beginActive(t)
	require.True(t, heapbits.Live())
}

func TestWovenBodyReadThroughBridge(t *testing.T) {
	requireBits(t)
	_, analysis := beginActive(t)
	body := new(struct{ state [32]byte })
	other := new(struct{ state [32]byte })
	require.True(t, analysis.RegisterBody(unsafe.Pointer(body)))

	buffer := bytes.Repeat([]byte{0}, 512)
	escape.Store(&buffer)
	n := copy(buffer, `{"name":"robert'); drop table x;--"}`)
	propbridge.BodyRead(uintptr(unsafe.Pointer(other)), addr(buffer), uintptr(n))
	require.False(t, heapbits.AnyBytes(buffer[:n]), "the body of a different object is not tainted")
	propbridge.BodyRead(uintptr(unsafe.Pointer(body)), addr(buffer), uintptr(n))
	runtime.KeepAlive(body)
	runtime.KeepAlive(other)
	require.True(t, heapbits.AnyBytes(buffer[:n]))
	require.False(t, heapbits.AnyBytes(buffer[n:]))

	field := buffer[9 : n-2]
	query := heapCopy([]byte("SELECT * FROM users WHERE name = '"), field, []byte("'"))
	require.Equal(t, []string{"34-59=http.request.body:"}, attributed(t, analysis, query))
	source, ok := analysis.Source(request.BodySourceID)
	require.True(t, ok)
	require.Equal(t, string(buffer[:n]), source.Value)
}

func TestWovenDerivedThroughBridge(t *testing.T) {
	requireBits(t)
	_, analysis := beginActive(t)
	value, ok := analysis.TaintBytes(constants.OriginHttpRequestParameter, "q", []byte("select"))
	require.True(t, ok)
	out := bytes.ToUpper(value) // not hooked here: the test does the work of the hook
	escape.Store(&out)
	require.True(t, heapbits.SetBytes(out))
	propbridge.Derived(addr(out), uintptr(len(out)), addr(value), uintptr(len(value)), propbridge.Positional)
	runtime.KeepAlive(out)
	runtime.KeepAlive(value)
	require.Equal(t, []string{"0-6=http.request.parameter:q"}, attributed(t, analysis, out))
	copied := heapCopy([]byte("x "), out[1:4])
	require.Equal(t, []string{"2-5=http.request.parameter:q"}, attributed(t, analysis, copied))
}

// TestWovenConcurrentRequests: 4 workers run 50 requests each. Each sink
// call is one call (with the bounded retries of an own access, no retry
// in the test): the test checks the first-call outcome for each owner, and
// bounds the miss rate.
func TestWovenConcurrentRequests(t *testing.T) {
	requireBits(t)
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = request.MaxAnalyses
	alphabets := []string{"abcdef", "ghijkl", "mnopqr", "stuvwx"}
	const rounds = 50
	type outcome struct {
		// unset: Set or Copy dropped the taint, or the query has stale
		// bits (the storage of the bits was in use by a different
		// goroutine: the bits do not wait).
		unset int
		// attributed and attributeMissed: first AttributeBytes call of
		// the owner (own access). A miss is a busy drop: the bits are
		// exact, thus only the slot lock can make the call fail.
		attributed, attributeMissed int
		// taintedMissed: first IsTaintedBytes call (a scan of all the
		// owners: one attempt for each owner).
		taintedMissed int
	}
	outcomes := make([]outcome, len(alphabets))
	var wait sync.WaitGroup
	failures := make(chan string, 1024)
	drops := request.OwnBusyDrops()
	for worker, alphabet := range alphabets {
		wait.Add(1)
		go func() {
			defer wait.Done()
			o := &outcomes[worker]
			for i := 0; i < rounds; i++ {
				_, scope, _ := request.Begin(context.Background())
				analysis, ok := scope.Analysis()
				if !ok {
					failures <- "no analysis"
					return
				}
				name := fmt.Sprintf("w%d", worker)
				value, ok := analysis.TaintBytes(constants.OriginHttpRequestParameter, name, []byte(alphabet))
				query := heapCopy([]byte("SELECT "), value, []byte(" ;"))
				p, n := unsafe.Pointer(&query[0]), uintptr(len(query))
				if !ok || heapbits.Next(p, n, 0) != 7 || heapbits.NextClean(p, n, 7) != 13 || heapbits.Next(p, n, 13) != n {
					o.unset++
					scope.Finish()
					continue
				}
				var r request.Attribution
				// The reason of a miss is the result of this call: the
				// process-wide OwnBusyDrops can change because of a
				// different worker.
				if attributed, busy := request.AttributeBytesBusy(analysis, query, &r); !attributed {
					o.attributeMissed++
					if !busy {
						failures <- fmt.Sprintf("worker %d: attribution missed, but not by a busy drop", worker)
					}
				} else if source, _ := r.Source(0); r.Attributed != 1 || r.N != 1 || source.Name != name || r.Segments[0].Start != 7 || r.Segments[0].Length != 6 {
					failures <- fmt.Sprintf("worker %d: wrong attribution %d %q", worker, r.N, source.Name)
				} else {
					o.attributed++
				}
				if !request.IsTaintedBytes(query) {
					o.taintedMissed++
				}
				scope.Finish()
				if request.IsTaintedBytes(value) {
					// Another worker can hold equal bytes only if the
					// alphabets overlap; they do not.
					failures <- "IsTainted is true after Finish"
				}
			}
		}()
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	t.Logf("outcomes %+v, own busy drops %d", outcomes, request.OwnBusyDrops()-drops)
	for worker, o := range outcomes {
		calls := rounds - o.unset
		require.Positive(t, o.attributed, "worker %d: no first-call attribution", worker)
		// The own access retries: a miss is rare (0 to 3 of 50 with
		// -race). Bound the rate at 20%.
		require.LessOrEqual(t, 5*o.attributeMissed, calls, "worker %d: first-call attribution misses %d of %d", worker, o.attributeMissed, calls)
		// A scan has one attempt for each owner, and the other workers scan
		// all the owners at the same time (about 20% of misses, 50% with
		// -race): bound the rate at 80%.
		require.LessOrEqual(t, 5*o.taintedMissed, 4*calls, "worker %d: first-call IsTainted misses %d of %d", worker, o.taintedMissed, calls)
		require.LessOrEqual(t, 2*o.unset, rounds, "worker %d: taint dropped %d of %d", worker, o.unset, rounds)
	}
}

// sinkString keeps a string on the heap.
var sinkString atomic.Pointer[string]

// TestWovenRuntimeRuneCallback: with the runtime hooks of iast/runtime, the
// rune conversions call the derived callback, so that the bytes of
// string([]rune(s)) are attributed to the source of s, also for invalid
// UTF-8 (each invalid byte becomes U+FFFD, which no content match can find).
func TestWovenRuntimeRuneCallback(t *testing.T) {
	requireBits(t)
	_, analysis := beginActive(t)
	value, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "q", "\xff\xfe")
	require.True(t, ok)
	prefix := []byte("id=")
	escape.Store(&prefix)
	joined := string(prefix) + value
	sinkString.Store(&joined)
	// requireBits skips when the target does not support the bits: here
	// the runtime hooks must be woven (the root package imports
	// iast/runtime), thus a missing bit is a failure, not a skip.
	require.True(t, heapbits.AnyString(joined), "the runtime concatenation hook did not propagate the bits")
	runes := []rune(joined)
	text := string(runes)
	sinkString.Store(&text)
	require.Equal(t, "id=\uFFFD\uFFFD", text)
	var r request.Attribution
	require.True(t, analysis.AttributeString(text, &r))
	require.Equal(t, 1, r.N)
	require.Equal(t, uint32(3), r.Segments[0].Start)
	require.Equal(t, uint32(6), r.Segments[0].Length)
	source, _ := r.Source(0)
	require.Equal(t, "\xff\xfe", source.Value)
}

// TestWovenRuntimeConcatAttribution: a real runtime concatenation (no
// manual copy of the bits) gives a sink value that the request attributes
// to its source.
func TestWovenRuntimeConcatAttribution(t *testing.T) {
	requireBits(t)
	_, analysis := beginActive(t)
	value, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "name", "robert'--")
	require.True(t, ok)
	prefix := []byte("SELECT * FROM users WHERE name = '")
	escape.Store(&prefix)
	query := string(prefix) + value + "'"
	sinkString.Store(&query)
	require.True(t, heapbits.AnyString(query), "the runtime concatenation hook did not propagate the bits")
	var r request.Attribution
	require.True(t, analysis.AttributeString(query, &r))
	require.Equal(t, 1, r.N)
	require.Equal(t, uint32(len(prefix)), r.Segments[0].Start)
	require.Equal(t, uint32(len(value)), r.Segments[0].Length)
	source, ok := r.Source(0)
	require.True(t, ok)
	require.Equal(t, "name", source.Name)
	require.True(t, request.IsTaintedString(query))
}
