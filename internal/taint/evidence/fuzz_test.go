// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

func FuzzSnapshotCanonicalization(f *testing.F) {
	f.Add([]byte{0, 3, 'a', 1, 2, 'b', 4, 3, 'c'})
	f.Add([]byte{2, 8, 'z', 2, 4, 'a', 0, 10, 'x'})
	f.Fuzz(func(t *testing.T, data []byte) {
		const value = "0123456789abcdef"
		count := min(len(data)/3, 32)
		inputs := make([]request.ResolvedRange, 0, count)
		for index := 0; index < count; index++ {
			start := uint32(data[3*index] % byte(len(value)))
			remaining := uint32(len(value)) - start
			length := uint32(data[3*index+1])%remaining + 1
			source := string([]byte{data[3*index+2]})
			input := resolved(start, length, source, uint64(index%4+1))
			input.RangeOrdinal = uint8(index)
			inputs = append(inputs, input)
		}
		if len(inputs) == 0 {
			return
		}
		first := snapshotFromResolved(t, value, inputs)
		for left, right := 0, len(inputs)-1; left < right; left, right = left+1, right-1 {
			inputs[left], inputs[right] = inputs[right], inputs[left]
		}
		second := snapshotFromResolved(t, value, inputs)
		assertEquivalentSnapshots(t, first, second)
		assertSnapshotTiling(t, first)
	})
}

func assertEquivalentSnapshots(t *testing.T, left, right *Snapshot) {
	t.Helper()
	if left.Value() != right.Value() || left.SourceCount() != right.SourceCount() || left.PartCount() != right.PartCount() || left.OwnerCount() != right.OwnerCount() {
		t.Fatalf("snapshot counts differ")
	}
	for index := 0; index < left.SourceCount(); index++ {
		leftValue, _ := left.SourceAt(index)
		rightValue, _ := right.SourceAt(index)
		if leftValue != rightValue {
			t.Fatalf("source %d differs", index)
		}
	}
	for index := 0; index < left.PartCount(); index++ {
		leftValue, _ := left.PartAt(index)
		rightValue, _ := right.PartAt(index)
		if leftValue != rightValue {
			t.Fatalf("part %d differs: %#v != %#v", index, leftValue, rightValue)
		}
	}
	for index := 0; index < left.OwnerCount(); index++ {
		leftValue, _ := left.OwnerAt(index)
		rightValue, _ := right.OwnerAt(index)
		if leftValue != rightValue {
			t.Fatalf("owner %d differs", index)
		}
	}
}

func assertSnapshotTiling(t *testing.T, snapshot *Snapshot) {
	t.Helper()
	position := uint32(0)
	for index := 0; index < snapshot.PartCount(); index++ {
		part, _ := snapshot.PartAt(index)
		if part.Start != position || part.Length == 0 {
			t.Fatalf("part %d does not tile at %d: %#v", index, position, part)
		}
		if _, ok := snapshot.PartValue(part); !ok {
			t.Fatalf("part %d has invalid value bounds", index)
		}
		position += part.Length
	}
	if position != uint32(len(snapshot.Value())) {
		t.Fatalf("parts end at %d, want %d", position, len(snapshot.Value()))
	}
}
