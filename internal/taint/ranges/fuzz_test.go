// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func FuzzCanonicalize(f *testing.F) {
	f.Add([]byte{4, 4, 0, 2, 8, 1}, uint8(10), uint8(16))
	f.Add([]byte{}, uint8(1), uint8(0))
	f.Add([]byte{0, 1, 0, 0, 1, 1}, uint8(64), uint8(2))
	f.Fuzz(func(t *testing.T, encoded []byte, rawLimit, rawValueLen uint8) {
		valueLen := uint32(rawValueLen)
		limit := ranges.ClampLimit(uint64(rawLimit))
		count := min(len(encoded)/3, ranges.MaxCanonicalInput)
		raw := make([]ranges.Range, 0, count)
		for i := 0; i < count; i++ {
			if valueLen == 0 {
				break
			}
			start := uint32(encoded[i*3]) % valueLen
			length := uint32(encoded[i*3+1])%(valueLen-start) + 1
			raw = append(raw, ranges.Range{
				Start:    start,
				Length:   length,
				SourceID: ranges.SourceID(encoded[i*3+2] % 16),
			})
		}
		var got ranges.Set
		outcome := ranges.Canonicalize(&got, limit, raw, valueLen)
		if !outcome.Valid {
			t.Fatalf("valid generated input was rejected: %v", raw)
		}
		if !got.ValidFor(valueLen) {
			t.Fatalf("invalid canonical result: %v", snapshot(&got))
		}
		expected, truncated := canonicalOracle(raw, valueLen, int(limit))
		actual := snapshot(&got)
		if len(expected) != len(actual) {
			t.Fatalf("range count differs: expected=%v actual=%v", expected, actual)
		}
		for i := range expected {
			if expected[i] != actual[i] {
				t.Fatalf("range %d differs: expected=%v actual=%v raw=%v", i, expected, actual, raw)
			}
		}
		if truncated != outcome.Truncated {
			t.Fatalf("truncation differs: expected=%v actual=%v", truncated, outcome.Truncated)
		}
	})
}

func FuzzSliceAndCopy(f *testing.F) {
	f.Add(uint8(8), uint8(2), uint8(6), uint8(1), uint8(3))
	f.Fuzz(func(t *testing.T, rawLen, rawLow, rawHigh, rawDestination, rawCount uint8) {
		valueLen := uint32(rawLen%64 + 1)
		low := uint32(rawLow) % (valueLen + 1)
		high := uint32(rawHigh) % (valueLen + 1)
		if low > high {
			low, high = high, low
		}
		baseRaw := []ranges.Range{{Length: valueLen, SourceID: 0}}
		var base ranges.Set
		if !ranges.Canonicalize(&base, 10, baseRaw, valueLen).Valid {
			t.Fatal("base setup failed")
		}
		var sliced ranges.Set
		if outcome := ranges.Slice(&sliced, 10, &base, valueLen, low, high); !outcome.Valid || !sliced.ValidFor(high-low) {
			t.Fatalf("invalid slice outcome: %+v", outcome)
		}

		n := uint32(rawCount) % (valueLen + 1)
		sourceOffset := uint32(rawLow) % (valueLen + 1)
		destination := uint32(rawDestination) % (valueLen + 1)
		if sourceOffset+n > valueLen || destination+n > valueLen {
			return
		}
		var copied ranges.Set
		outcome := ranges.CopyOverwrite(&copied, 10, &base, valueLen, destination, &base, valueLen, sourceOffset, n)
		if !outcome.Valid || !copied.ValidFor(valueLen) {
			t.Fatalf("invalid copy outcome: %+v ranges=%v", outcome, snapshot(&copied))
		}
	})
}
