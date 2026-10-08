// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
)

var (
	activeString  string
	activeStrings []string
	activeBytes   []byte
)

// BenchmarkPropagationActiveUntainted measures the propagation hooks in an
// active (sampled) request that handles no tainted value. The timed loop runs
// in the handler of a real httptest server (see support_test.go). The request
// sampling must be 100 (DD_IAST_REQUEST_SAMPLING=100, the runner default).
func BenchmarkPropagationActiveUntainted(b *testing.B) {
	run := func(name string, body func()) {
		b.Run(name, func(b *testing.B) {
			benchInRequest(b, "/active", func(context.Context, *http.Request) {
				b.ReportAllocs()
				for b.Loop() {
					body()
				}
			})
		})
	}
	stringWindow := "  attacker  "
	run("StringWindow", func() { activeString = strings.TrimSpace(stringWindow) })
	stringWindows := "a,b,c"
	run("StringWindows", func() { activeStrings = strings.Split(stringWindows, ",") })
	stringCopy := "attacker"
	run("StringCopy", func() { activeString = strings.Clone(stringCopy) })
	stringCoarse := "Attacker"
	run("StringCoarse", func() { activeString = strings.ToLower(stringCoarse) })
	byteWindow := []byte("  attacker  ")
	run("ByteWindow", func() { activeBytes = bytes.TrimSpace(byteWindow) })
	byteCopy := []byte("attacker")
	run("ByteCopy", func() { activeBytes = bytes.Clone(byteCopy) })
}
