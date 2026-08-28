// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence

import (
	"context"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
)

func TestCollectStringOwnsCanonicalEvidence(t *testing.T) {
	ctx := withScope(t)
	managed := taint.TaintString(ctx, taint.Source{
		Origin: constants.OriginHttpRequestParameter,
		Name:   "query",
	}, "attacker")
	snapshot, status := CollectString(managed, constants.VulnerabilityTypeSqlInjection)
	if status != StatusCollected || snapshot == nil {
		t.Fatalf("CollectString status = %v, want %v", status, StatusCollected)
	}
	if snapshot.Value() != managed || unsafe.StringData(snapshot.Value()) == unsafe.StringData(managed) {
		t.Fatal("snapshot did not own a distinct evidence clone")
	}
	if snapshot.SourceCount() != 1 || snapshot.PartCount() != 1 || snapshot.OwnerCount() != 1 {
		t.Fatalf("counts = sources:%d parts:%d owners:%d", snapshot.SourceCount(), snapshot.PartCount(), snapshot.OwnerCount())
	}
	source, _ := snapshot.SourceAt(0)
	if source.Name != "query" || source.Value != "attacker" || unsafe.StringData(source.Value) == unsafe.StringData(managed) {
		t.Fatalf("unexpected or borrowed source: %#v", source)
	}
	part, _ := snapshot.PartAt(0)
	if value, ok := snapshot.PartValue(part); !ok || value != managed || part.Source != 0 {
		t.Fatalf("unexpected part/value: %#v, %q, %t", part, value, ok)
	}
}

func TestCollectJoinedStringsPreservesArgumentOffsets(t *testing.T) {
	ctx := withScope(t)
	managed := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "argument"}, "secret")
	values := []string{"echo", managed, "tail"}
	result := strings.Join(values, " ")
	snapshot, status := CollectJoinedStrings(values, " ", result, constants.VulnerabilityTypeCommandInjection)
	if status != StatusCollected || snapshot == nil {
		t.Fatalf("status = %v", status)
	}
	if snapshot.Value() != result || snapshot.SourceCount() != 1 || snapshot.PartCount() != 3 {
		t.Fatalf("snapshot = value:%q sources:%d parts:%d", snapshot.Value(), snapshot.SourceCount(), snapshot.PartCount())
	}
	part, _ := snapshot.PartAt(1)
	if part.Start != 5 || part.Length != 6 || part.Source != 0 {
		t.Fatalf("tainted argument part = %#v", part)
	}
}

func TestCollectJoinedStringsFindsLateArgument(t *testing.T) {
	ctx := withScope(t)
	managed := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "argument"}, "secret")
	values := make([]string, 20)
	for index := range values {
		values[index] = "clean"
	}
	values[len(values)-1] = managed
	result := strings.Join(values, " ")
	snapshot, status := CollectJoinedStrings(values, " ", result, constants.VulnerabilityTypeCommandInjection)
	if status != StatusCollected || snapshot == nil {
		t.Fatalf("late argument status = %v", status)
	}
	part, _ := snapshot.PartAt(snapshot.PartCount() - 1)
	if part.Source != 0 || part.Start != uint32(len(result)-len(managed)) {
		t.Fatalf("late argument part = %#v", part)
	}
}

func TestCollectJoinedStringsRejectsMismatchedResult(t *testing.T) {
	if snapshot, status := CollectJoinedStrings([]string{"echo", "secret"}, " ", "different", constants.VulnerabilityTypeCommandInjection); snapshot != nil || status != StatusNone {
		t.Fatalf("mismatched result = (%#v, %v)", snapshot, status)
	}
}

func TestCollectorCanonicalOrderingAndOverlap(t *testing.T) {
	value := "0123456789"
	inputs := []request.ResolvedRange{
		resolved(2, 5, "b", 2),
		resolved(2, 3, "a", 1),
		resolved(0, 2, "c", 3),
	}
	first := snapshotFromResolved(t, value, inputs)
	for left, right := 0, len(inputs)-1; left < right; left, right = left+1, right-1 {
		inputs[left], inputs[right] = inputs[right], inputs[left]
	}
	second := snapshotFromResolved(t, value, inputs)

	if first.SourceCount() != 3 || first.PartCount() != 4 {
		t.Fatalf("counts = sources:%d parts:%d", first.SourceCount(), first.PartCount())
	}
	for index := 0; index < first.SourceCount(); index++ {
		left, _ := first.SourceAt(index)
		right, _ := second.SourceAt(index)
		if left != right {
			t.Fatalf("source %d differs: %#v != %#v", index, left, right)
		}
	}
	want := []Part{
		{Start: 0, Length: 2, Source: 0},
		{Start: 2, Length: 3, Source: 1},
		{Start: 5, Length: 2, Source: 2},
		{Start: 7, Length: 3, Source: -1},
	}
	for index, expected := range want {
		left, _ := first.PartAt(index)
		right, _ := second.PartAt(index)
		if left != expected || right != expected {
			t.Fatalf("part %d = %#v / %#v, want %#v", index, left, right, expected)
		}
	}
}

func TestCollectorMergesAdjacentRanges(t *testing.T) {
	snapshot := snapshotFromResolved(t, "abcdef", []request.ResolvedRange{
		resolved(0, 2, "same", 1),
		resolved(2, 2, "same", 2),
	})
	if snapshot.OwnerCount() != 2 {
		t.Fatalf("OwnerCount = %d, want 2", snapshot.OwnerCount())
	}
	if snapshot.PartCount() != 2 {
		t.Fatalf("PartCount = %d, want 2", snapshot.PartCount())
	}
	part, _ := snapshot.PartAt(0)
	if part != (Part{Start: 0, Length: 4, Source: 0}) {
		t.Fatalf("merged part = %#v", part)
	}
}

func TestSnapshotRecomputesRetainedSourceBytes(t *testing.T) {
	value := "abcd"
	inputs := []request.ResolvedRange{
		resolved(0, 4, "a", 1),
		{Start: 0, Length: 4, Source: request.Source{
			Origin: constants.OriginHttpRequestParameter,
			Name:   "z",
			Value:  strings.Repeat("z", 4_096),
		}, OwnerID: 2, OwnerGen: 1, OwnerIndex: 2},
	}
	snapshot := snapshotFromResolved(t, value, inputs)
	if snapshot.SourceCount() != 1 {
		t.Fatalf("SourceCount = %d, want 1", snapshot.SourceCount())
	}
	source, _ := snapshot.SourceAt(0)
	want := uint32(len(source.Name) + len(source.Value))
	if snapshot.SourceBytes() != want {
		t.Fatalf("SourceBytes = %d, want %d", snapshot.SourceBytes(), want)
	}
	if snapshot.OwnerCount() != 2 {
		t.Fatalf("OwnerCount = %d, want 2", snapshot.OwnerCount())
	}
}

func TestSnapshotMaxParts(t *testing.T) {
	value := strings.Repeat("x", 513)
	inputs := make([]request.ResolvedRange, MaxCollectedRanges)
	for index := range inputs {
		inputs[index] = resolved(uint32(2*index+1), 1, "x", 1)
	}
	snapshot := snapshotFromResolved(t, value, inputs)
	if snapshot.PartCount() != MaxParts {
		t.Fatalf("PartCount = %d, want %d", snapshot.PartCount(), MaxParts)
	}
}

func BenchmarkCollectStringMiss(b *testing.B) {
	for b.Loop() {
		CollectString("clean-value", constants.VulnerabilityTypeSqlInjection)
	}
}

func TestCollectStringMissDoesNotAllocate(t *testing.T) {
	allocations := testing.AllocsPerRun(1_000, func() {
		if snapshot, status := CollectString("clean-value", constants.VulnerabilityTypeSqlInjection); snapshot != nil || status != StatusNone {
			t.Fatalf("miss = (%v, %v)", snapshot, status)
		}
	})
	if allocations != 0 {
		t.Fatalf("clean miss allocations = %f, want 0", allocations)
	}
}

func TestCollectorSuppressesMarkedRanges(t *testing.T) {
	bit, ok := ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	if !ok {
		t.Fatal("SQL injection has no mark bit")
	}
	var collector collector
	if !collector.add("abcd", constants.VulnerabilityTypeSqlInjection, request.ResolvedRange{
		Start: 0, Length: 4, Marks: bit, Source: request.Source{Origin: constants.OriginHttpRequestParameter, Value: "abcd"},
	}) {
		t.Fatal("marked range stopped collection")
	}
	if collector.count != 0 || collector.dropped {
		t.Fatalf("marked collector = count:%d dropped:%t", collector.count, collector.dropped)
	}
}

func TestCollectorDropsCompleteReportAtBounds(t *testing.T) {
	value := "abcd"
	t.Run("invalid range", func(t *testing.T) {
		var collector collector
		if collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(3, 2, "x", 1)) || !collector.dropped {
			t.Fatal("invalid range was not dropped")
		}
	})
	t.Run("source bytes", func(t *testing.T) {
		var collector collector
		chunk := strings.Repeat("x", store.MaxRootBytes-1)
		for index := 0; index < 4; index++ {
			if !collector.add(value, constants.VulnerabilityTypeSqlInjection, request.ResolvedRange{
				Start: 0, Length: 2, Source: request.Source{Origin: constants.OriginHttpRequestParameter, Name: string(rune('a' + index)), Value: chunk},
			}) {
				t.Fatalf("source %d was dropped early", index)
			}
		}
		if collector.sourceBytes != MaxSnapshotBytes {
			t.Fatalf("source bytes = %d, want %d", collector.sourceBytes, MaxSnapshotBytes)
		}
		if collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(0, 2, "overflow", 5)) || !collector.dropped {
			t.Fatal("cumulative source overflow was not dropped")
		}
	})
	t.Run("ranges", func(t *testing.T) {
		var collector collector
		for index := 0; index < MaxCollectedRanges; index++ {
			if !collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(0, 1, "x", uint64(index+1))) {
				t.Fatalf("range %d was dropped early", index)
			}
		}
		if collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(0, 1, "x", 999)) || !collector.dropped {
			t.Fatal("range overflow was not dropped")
		}
	})
}

func TestCollectStringRejectsInvalidVulnerability(t *testing.T) {
	if snapshot, status := CollectString("clean-value", constants.VulnerabilityType(255)); snapshot != nil || status != StatusDropped {
		t.Fatalf("invalid vulnerability = (%v, %v), want (nil, dropped)", snapshot, status)
	}
}

func TestSnapshotAccessorsRejectInvalidInputs(t *testing.T) {
	var nilSnapshot *Snapshot
	if nilSnapshot.Value() != "" || nilSnapshot.SourceCount() != 0 || nilSnapshot.PartCount() != 0 || nilSnapshot.OwnerCount() != 0 {
		t.Fatal("nil snapshot accessors returned data")
	}
	if _, ok := nilSnapshot.SourceAt(0); ok {
		t.Fatal("nil SourceAt succeeded")
	}
	if _, ok := nilSnapshot.PartAt(0); ok {
		t.Fatal("nil PartAt succeeded")
	}
	if _, ok := nilSnapshot.OwnerAt(0); ok {
		t.Fatal("nil OwnerAt succeeded")
	}
	if _, ok := nilSnapshot.PartValue(Part{Length: 1}); ok {
		t.Fatal("nil PartValue succeeded")
	}
}

func snapshotFromResolved(t *testing.T, value string, inputs []request.ResolvedRange) *Snapshot {
	t.Helper()
	var collector collector
	for _, input := range inputs {
		if !collector.add(value, constants.VulnerabilityTypeSqlInjection, input) {
			t.Fatal("collector dropped input")
		}
	}
	return collector.finish(value)
}

func resolved(start, length uint32, source string, owner uint64) request.ResolvedRange {
	return request.ResolvedRange{
		Start: start, Length: length,
		Source:  request.Source{Origin: constants.OriginHttpRequestParameter, Name: source, Value: source},
		OwnerID: owner, OwnerGen: 1, OwnerIndex: uint8(owner % 4),
	}
}

func withScope(t *testing.T) context.Context {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("request scope was not created")
	}
	t.Cleanup(func() {
		scope.Finish()
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	return ctx
}
