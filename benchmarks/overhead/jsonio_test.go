// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead_test

// The benchmarks of this file are the JSON and IO overhead workloads. The
// runner runs each one in the control build and in the IAST build. The names of
// the sub-benchmarks give the state:
//
//   - inactive: no request is active in the process.
//   - active: one clean request is active for all the iterations. The
//     readers have no binding, thus no value is tainted.
//   - request: each iteration begins a request, binds the readers to it,
//     runs the workload, and finishes the request. The control build does
//     the same calls, thus the delta is the cost of the aspects only.
//
// The Read guard benchmarks use three states: (a) no live guard; (b) one live
// guard on another reader; (c) the reader itself is guarded.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	// The bootstrap aspect of iast/encoding/json does not match a test main.
	// Thus this import links the package, and its init registers the JSON
	// callbacks (owner lookup, clone, taint). Without it, the IAST build
	// does not propagate JSON taint.
	_ "github.com/DataDog/dd-iast-go/iast/encoding/json"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

var (
	resultRecord jsonRecord
	resultSmall  jsonSmall
	resultCount  int
)

// jsonRecord is the JSON workload with 20 string fields.
type jsonRecord struct {
	F01 string `json:"f01"`
	F02 string `json:"f02"`
	F03 string `json:"f03"`
	F04 string `json:"f04"`
	F05 string `json:"f05"`
	F06 string `json:"f06"`
	F07 string `json:"f07"`
	F08 string `json:"f08"`
	F09 string `json:"f09"`
	F10 string `json:"f10"`
	F11 string `json:"f11"`
	F12 string `json:"f12"`
	F13 string `json:"f13"`
	F14 string `json:"f14"`
	F15 string `json:"f15"`
	F16 string `json:"f16"`
	F17 string `json:"f17"`
	F18 string `json:"f18"`
	F19 string `json:"f19"`
	F20 string `json:"f20"`
}

type jsonSmall struct {
	Name string `json:"name"`
}

var (
	jsonRecordDocument = recordDocument()
	jsonSmallDocument  = []byte(`{"name":"Ada Lovelace"}`)
	jsonArrayDocument  = arrayDocument(100)
)

func recordDocument() []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for field := 1; field <= 20; field++ {
		if field > 1 {
			buffer.WriteByte(',')
		}
		fmt.Fprintf(&buffer, `"f%02d":"value number %02d"`, field, field)
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func arrayDocument(items int) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for item := range items {
		if item > 0 {
			buffer.WriteByte(',')
		}
		fmt.Fprintf(&buffer, `{"name":"item %03d"}`, item)
	}
	buffer.WriteByte(']')
	return buffer.Bytes()
}

// iastBuild reports whether this is the IAST build of the runner. Only the
// IAST build adds the __dd_iast_binding field to json.Decoder. The
// telemetry counter is not a correct signal: the import of
// iast/encoding/json increments it also in the control build.
var iastBuild = sync.OnceValue(func() bool {
	_, found := reflect.TypeFor[json.Decoder]().FieldByName("__dd_iast_binding")
	return found
})

// enableRequests makes request.Begin create active requests until the end of
// the benchmark.
func enableRequests(b *testing.B) {
	b.Helper()
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	b.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})
}

// activeRequest begins one request that stays active until the end of the
// benchmark.
func activeRequest(b *testing.B) context.Context {
	b.Helper()
	enableRequests(b)
	ctx, scope, created := request.Begin(context.Background())
	if !created || scope == nil {
		b.Fatal("the benchmark did not create a request scope")
	}
	if _, active := scope.Analysis(); !active {
		b.Fatal("the request scope is not active")
	}
	b.Cleanup(scope.Finish)
	return ctx
}

// beginRequest begins one request for one iteration. The caller must call
// finish.
func beginRequest(b *testing.B) (ctx context.Context, finish func()) {
	ctx, scope, created := request.Begin(context.Background())
	if !created || scope == nil {
		b.Fatal("the benchmark did not create a request scope")
	}
	return ctx, scope.Finish
}

func BenchmarkJSONUnmarshal20(b *testing.B) {
	run := func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var destination jsonRecord
			if err := json.Unmarshal(jsonRecordDocument, &destination); err != nil {
				b.Fatal(err)
			}
			resultRecord = destination
		}
	}
	b.Run("inactive", run)
	b.Run("active", func(b *testing.B) {
		activeRequest(b)
		run(b)
	})
}

func BenchmarkJSONDecoder20(b *testing.B) {
	decode := func(b *testing.B, reader io.Reader) {
		var destination jsonRecord
		if err := json.NewDecoder(reader).Decode(&destination); err != nil {
			b.Fatal(err)
		}
		resultRecord = destination
	}
	direct := func(b *testing.B) {
		body := bytes.NewReader(nil)
		b.ReportAllocs()
		for b.Loop() {
			body.Reset(jsonRecordDocument)
			decode(b, body)
		}
	}
	// The macro check: the decoder reads through bufio.NewReader(body), as many
	// handlers do with r.Body.
	buffered := func(b *testing.B) {
		body := bytes.NewReader(nil)
		b.ReportAllocs()
		for b.Loop() {
			body.Reset(jsonRecordDocument)
			decode(b, bufio.NewReader(body))
		}
	}
	b.Run("inactive", direct)
	b.Run("active", func(b *testing.B) {
		activeRequest(b)
		direct(b)
	})
	b.Run("inactive-bufio", buffered)
	b.Run("active-bufio", func(b *testing.B) {
		activeRequest(b)
		buffered(b)
	})
	// The body is bound to the request, as r.Body is: the decoded strings are
	// tainted in the IAST build.
	b.Run("request-bufio", func(b *testing.B) {
		enableRequests(b)
		body := bytes.NewReader(nil)
		// One check before the measured loop: in the IAST build, the
		// decoded strings of a bound body are tainted.
		ctx, finish := beginRequest(b)
		body.Reset(jsonRecordDocument)
		request.BindReader(ctx, body)
		decode(b, bufio.NewReader(body))
		if iastBuild() && !taint.IsTaintedString(resultRecord.F20) {
			b.Fatal("the last decoded field is not tainted")
		}
		finish()
		b.ReportAllocs()
		for b.Loop() {
			ctx, finish := beginRequest(b)
			body.Reset(jsonRecordDocument)
			request.BindReader(ctx, body)
			decode(b, bufio.NewReader(body))
			finish()
		}
	})
}

// BenchmarkJSONDecoderSmall measures NewDecoder and one Decode of a small
// body (two reader lookups in the IAST build on Go 1.27).
func BenchmarkJSONDecoderSmall(b *testing.B) {
	decode := func(b *testing.B, reader io.Reader) {
		var destination jsonSmall
		if err := json.NewDecoder(reader).Decode(&destination); err != nil {
			b.Fatal(err)
		}
		resultSmall = destination
	}
	direct := func(b *testing.B) {
		body := bytes.NewReader(nil)
		b.ReportAllocs()
		for b.Loop() {
			body.Reset(jsonSmallDocument)
			decode(b, body)
		}
	}
	b.Run("inactive", direct)
	b.Run("active", func(b *testing.B) {
		activeRequest(b)
		direct(b)
	})
	b.Run("request", func(b *testing.B) {
		enableRequests(b)
		body := bytes.NewReader(nil)
		// One check before the measured loop: in the IAST build, the
		// decoded string of a bound body is tainted.
		ctx, finish := beginRequest(b)
		body.Reset(jsonSmallDocument)
		request.BindReader(ctx, body)
		decode(b, body)
		if iastBuild() && !taint.IsTaintedString(resultSmall.Name) {
			b.Fatal("the decoded field is not tainted")
		}
		finish()
		b.ReportAllocs()
		for b.Loop() {
			ctx, finish := beginRequest(b)
			body.Reset(jsonSmallDocument)
			request.BindReader(ctx, body)
			decode(b, body)
			finish()
		}
	})
}

// BenchmarkJSONDecoderMore100 measures a More loop over an array of 100
// objects (one reader lookup for each item in the IAST build on Go 1.27).
// In the active state, the body has no binding, thus the decoder has no
// token and the Decode calls do no owner check. In the request state, the
// body is bound before NewDecoder, thus each Decode checks the owner of the
// token and the decoded strings are tainted in the IAST build.
func BenchmarkJSONDecoderMore100(b *testing.B) {
	decodeAll := func(b *testing.B, body io.Reader) {
		decoder := json.NewDecoder(body)
		if _, err := decoder.Token(); err != nil {
			b.Fatal(err)
		}
		items := 0
		for decoder.More() {
			var destination jsonSmall
			if err := decoder.Decode(&destination); err != nil {
				b.Fatal(err)
			}
			resultSmall = destination
			items++
		}
		if items != 100 {
			b.Fatalf("decoded %d items, want 100", items)
		}
		resultCount = items
	}
	run := func(b *testing.B) {
		body := bytes.NewReader(nil)
		b.ReportAllocs()
		for b.Loop() {
			body.Reset(jsonArrayDocument)
			decodeAll(b, body)
		}
	}
	b.Run("inactive", run)
	b.Run("active", func(b *testing.B) {
		activeRequest(b)
		run(b)
	})
	b.Run("request", func(b *testing.B) {
		enableRequests(b)
		body := bytes.NewReader(nil)
		// One check before the measured loop: in the IAST build, the
		// decoded strings of a bound body are tainted.
		ctx, finish := beginRequest(b)
		body.Reset(jsonArrayDocument)
		request.BindReader(ctx, body)
		decodeAll(b, body)
		if iastBuild() && !taint.IsTaintedString(resultSmall.Name) {
			b.Fatal("the last decoded item is not tainted")
		}
		finish()
		b.ReportAllocs()
		for b.Loop() {
			ctx, finish := beginRequest(b)
			body.Reset(jsonArrayDocument)
			request.BindReader(ctx, body)
			decodeAll(b, body)
			finish()
		}
	})
}

// BenchmarkIOMultiReader measures io.MultiReader of 2 and of 8 readers. In
// the request state, all the inputs are bound to the request.
func BenchmarkIOMultiReader(b *testing.B) {
	for _, inputs := range []int{2, 8} {
		readers := make([]io.Reader, inputs)
		for index := range readers {
			readers[index] = strings.NewReader("part")
		}
		b.Run(fmt.Sprintf("%d/inactive", inputs), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				resultReader = io.MultiReader(readers...)
			}
		})
		b.Run(fmt.Sprintf("%d/request", inputs), func(b *testing.B) {
			enableRequests(b)
			b.ReportAllocs()
			for b.Loop() {
				ctx, finish := beginRequest(b)
				for _, reader := range readers {
					request.BindReader(ctx, reader)
				}
				resultReader = io.MultiReader(readers...)
				finish()
			}
		})
	}
}

var resultReader io.Reader

// BenchmarkIOReadAll1KiB measures io.ReadAll of a 1 KiB reader. In the
// active state, the reader has no binding (the first lookup only). In the
// request state, it is bound to the request (the token, the second lookup,
// and the adoption of the result).
func BenchmarkIOReadAll1KiB(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 1024)
	run := func(b *testing.B) {
		body := bytes.NewReader(nil)
		b.ReportAllocs()
		for b.Loop() {
			body.Reset(data)
			read, err := io.ReadAll(body)
			if err != nil {
				b.Fatal(err)
			}
			resultBytes = read
		}
	}
	b.Run("inactive", run)
	b.Run("active", func(b *testing.B) {
		activeRequest(b)
		run(b)
	})
	b.Run("request", func(b *testing.B) {
		enableRequests(b)
		body := bytes.NewReader(nil)
		b.ReportAllocs()
		for b.Loop() {
			ctx, finish := beginRequest(b)
			body.Reset(data)
			request.BindReader(ctx, body)
			read, err := io.ReadAll(body)
			if err != nil {
				b.Fatal(err)
			}
			resultBytes = read
			finish()
		}
	})
}

// endlessReader gives len(p) bytes for each Read. It does not write p, thus
// the benchmark measures the wrapper, not the input. It is not zero-sized,
// thus request.BindReader can bind it.
type endlessReader struct{ _ byte }

func (*endlessReader) Read(p []byte) (int, error) { return len(p), nil }

// BenchmarkReadGuard measures (*bufio.Reader).Read and (*io.LimitedReader).Read
// in the three states of the Read guard (see the top of this file).
func BenchmarkReadGuard(b *testing.B) {
	wrappers := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{"bufio", func(input io.Reader) io.Reader { return bufio.NewReaderSize(input, 4096) }},
		{"limited", func(input io.Reader) io.Reader { return io.LimitReader(input, math.MaxInt64) }},
	}
	for _, wrapper := range wrappers {
		for _, size := range []int{1, 512, 4096} {
			buffer := make([]byte, size)
			run := func(b *testing.B, reader io.Reader) {
				b.ReportAllocs()
				for b.Loop() {
					read, err := reader.Read(buffer)
					if err != nil || read != size {
						b.Fatalf("read %d bytes (%v), want %d", read, err, size)
					}
				}
			}
			b.Run(fmt.Sprintf("%s/%dB/a-none", wrapper.name, size), func(b *testing.B) {
				reader := wrapper.wrap(&endlessReader{})
				if iastBuild() && iobridge.GuardCountForTest() != 0 {
					b.Fatalf("state (a) has %d live guards, want 0", iobridge.GuardCountForTest())
				}
				run(b, reader)
			})
			b.Run(fmt.Sprintf("%s/%dB/b-other", wrapper.name, size), func(b *testing.B) {
				reader := wrapper.wrap(&endlessReader{})
				ctx := activeRequest(b)
				body := &endlessReader{}
				request.BindReader(ctx, body)
				guarded := wrapper.wrap(body)
				if iastBuild() && (iobridge.GuardCountForTest() != 1 || iobridge.GuardEntriesOfForTest(guarded) != 1) {
					b.Fatalf("state (b) has %d live guards, want 1 on the other reader", iobridge.GuardCountForTest())
				}
				run(b, reader)
				resultReader = guarded
			})
			b.Run(fmt.Sprintf("%s/%dB/c-self", wrapper.name, size), func(b *testing.B) {
				ctx := activeRequest(b)
				body := &endlessReader{}
				request.BindReader(ctx, body)
				reader := wrapper.wrap(body)
				if iastBuild() && (iobridge.GuardCountForTest() != 1 || iobridge.GuardEntriesOfForTest(reader) != 1) {
					b.Fatalf("state (c) has %d live guards, want 1 on the reader", iobridge.GuardCountForTest())
				}
				run(b, reader)
				if iastBuild() && iobridge.GuardEntriesOfForTest(reader) != 1 {
					b.Fatal("the guard of the reader was removed during the benchmark")
				}
			})
		}
	}
}
