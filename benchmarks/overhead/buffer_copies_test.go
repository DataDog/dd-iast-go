// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

var bufferCopyResult string

// BenchmarkBytesBufferCopies is PR #39's BytesBufferCopies on the public API:
// the request is a real sampled httptest request.
func BenchmarkBytesBufferCopies(b *testing.B) {
	if !built.WithOrchestrion {
		b.Skip("requires woven ordinary-call fixture")
	}
	for _, mode := range []string{"read", "write", "active-unrelated"} {
		b.Run(mode, func(b *testing.B) {
			benchInRequest(b, "/buffer", func(ctx context.Context, _ *http.Request) {
				input := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "buffer"}, "attacker")
				buffer := NewTrackedBuffer(input)
				var unrelated bytes.Buffer
				unrelated.Grow(64)
				write, reset := unrelated.WriteString, unrelated.Reset
				b.ReportAllocs()
				for b.Loop() {
					switch mode {
					case "read":
						bufferCopyResult = ReadBufferCopy(*buffer)
					case "write":
						bufferCopyResult = WriteBufferCopy(buffer, input)
					case "active-unrelated":
						write("clean")
						reset()
					}
				}
			})
		})
	}
}
