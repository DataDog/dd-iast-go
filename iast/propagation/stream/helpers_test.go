// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package stream_test

import (
	"context"
	"fmt"
	"runtime"
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

// The behavior tests use the real heap taint bits: they need the woven
// runtime and the hooks of this package.

func requireBits(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if !heapbits.Enabled() {
		t.Skip("the heap taint bits are not supported on this platform")
	}
}

// begin starts an active request and returns its analysis. Finish runs at the
// end of the test.
func begin(t *testing.T) (*request.Scope, request.Analysis) {
	t.Helper()
	requireBits(t)
	enabled, sampling, maxConcurrent := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = enabled, sampling, maxConcurrent
	})
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = request.MaxAnalyses
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	require.True(t, heapbits.Live())
	return scope, analysis
}

// heapString returns a heap copy of s with no taint bits.
func heapString(s string) string {
	b := make([]byte, len(s))
	copy(b, s)
	sink.Store(&b)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// heapBytes returns a heap copy of s with no taint bits.
func heapBytes(s string) []byte {
	b := make([]byte, len(s))
	copy(b, s)
	sink.Store(&b)
	return b
}

var sink atomic.Pointer[[]byte]

// param taints value as the request parameter name.
func param(t *testing.T, a request.Analysis, name, value string) string {
	t.Helper()
	s, ok := a.TaintString(constants.OriginHttpRequestParameter, name, heapString(value))
	require.True(t, ok)
	require.Equal(t, [][2]int{{0, len(value)}}, rangesString(s))
	return s
}

// paramBytes taints value as the request parameter name.
func paramBytes(t *testing.T, a request.Analysis, name, value string) []byte {
	t.Helper()
	b, ok := a.TaintBytes(constants.OriginHttpRequestParameter, name, heapBytes(value))
	require.True(t, ok)
	require.Equal(t, [][2]int{{0, len(value)}}, rangesBytes(b))
	return b
}

// ranges returns the tainted ranges [start, end) of the n bytes at p.
func ranges(p unsafe.Pointer, n uintptr) [][2]int {
	var out [][2]int
	for off := heapbits.Next(p, n, 0); off < n; {
		end := heapbits.NextClean(p, n, off)
		out = append(out, [2]int{int(off), int(end)})
		off = heapbits.Next(p, n, end)
	}
	runtime.KeepAlive(p)
	return out
}

func rangesString(s string) [][2]int {
	return ranges(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)))
}

func rangesBytes(b []byte) [][2]int {
	return ranges(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)))
}

// attributed returns the segments of the attribution of value for a, as
// "start-end=origin:name" (or "=foreign").
func attributed(t *testing.T, a request.Analysis, value string) []string {
	t.Helper()
	var r request.Attribution
	a.AttributeString(value, &r)
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

func attributedBytes(t *testing.T, a request.Analysis, value []byte) []string {
	t.Helper()
	return attributed(t, a, unsafe.String(unsafe.SliceData(value), len(value)))
}

// body is a request body reader: it reads data in chunks of at most chunk
// bytes (0: no limit), and reports each read to propbridge, as the body hook
// of net/http does. The analysis taints the bytes of a registered body.
type body struct {
	data  []byte
	off   int
	chunk int
	reads int
	// eof: the last read returns the data with io.EOF.
	eof bool
}

// newBody returns a body registered with a.
func newBody(t *testing.T, a request.Analysis, data string, chunk int) *body {
	t.Helper()
	b := &body{data: []byte(data), chunk: chunk}
	require.True(t, a.RegisterBody(unsafe.Pointer(b)))
	return b
}

func (b *body) Read(p []byte) (int, error) {
	b.reads++
	if b.off >= len(b.data) {
		return 0, errEOF
	}
	n := len(p)
	if b.chunk > 0 && n > b.chunk {
		n = b.chunk
	}
	n = copy(p[:n], b.data[b.off:])
	b.off += n
	if n > 0 {
		propbridge.BodyRead(uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(&p[0])), uintptr(n))
		runtime.KeepAlive(b)
		runtime.KeepAlive(p)
	}
	if b.eof && b.off >= len(b.data) {
		return n, errEOF
	}
	return n, nil
}

// bodyLabel is the attribution label of the request body.
var bodyLabel = constants.OriginHttpRequestBody.String() + ":"

// paramLabel is the attribution label of the request parameter name.
func paramLabel(name string) string {
	return constants.OriginHttpRequestParameter.String() + ":" + name
}

// seg is a part of a scripted read: clean bytes, or bytes of the body.
type seg struct {
	s     string
	taint bool
}

// scripted gives one read for each element of reads (each read writes its
// parts in order), then io.EOF. The tainted parts come from a registered
// body, thus they have the bits of the body.
type scripted struct {
	body  *body
	reads [][]seg
}

// newScripted returns a scripted reader with a body registered with a.
func newScripted(t *testing.T, a request.Analysis, reads ...[]seg) *scripted {
	t.Helper()
	var data []byte
	for _, r := range reads {
		for _, s := range r {
			if s.taint {
				data = append(data, s.s...)
			}
		}
	}
	return &scripted{body: newBody(t, a, string(data), 0), reads: reads}
}

func (r *scripted) Read(p []byte) (int, error) {
	if len(r.reads) == 0 {
		return 0, errEOF
	}
	n := 0
	for _, s := range r.reads[0] {
		if s.taint {
			m, _ := r.body.Read(p[n : n+len(s.s)])
			n += m
		} else {
			n += copy(p[n:], s.s)
		}
	}
	r.reads = r.reads[1:]
	return n, nil
}
