// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

import (
	"strings"
	"testing"
)

var (
	chainOperands [4]string // built at run time: the compiler cannot fold them
	chainResult   string
	chainLength   int
)

func init() {
	for i := range chainOperands {
		// 2+4+6+8 = 20 bytes: the stack case fits the 32-byte stack buffer
		// of the compiler.
		chainOperands[i] = strings.Repeat(string(rune('a'+i)), 2+2*i)
	}
}

// BenchmarkConcatChainHeap is gate G-A5 (plan heapbits-sqli-cmdi 10.1): a
// maximal a+b+c+d chain whose result escapes (one allocation). Disabled, no
// request, untainted: the IAST variant must have the same allocation count.
func BenchmarkConcatChainHeap(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		chainResult = chainOperands[0] + chainOperands[1] + chainOperands[2] + chainOperands[3]
	}
}

// BenchmarkConcatChainStack is the same chain with a result that does not
// escape (the compiler gives it a 32-byte stack buffer: no allocation).
func BenchmarkConcatChainStack(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		chainLength = len(chainOperands[0] + chainOperands[1] + chainOperands[2] + chainOperands[3])
	}
}
