// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

// Independent implementation of the published, unsalted index calculation.
// Candidates are chosen without observing the request table's random seed.
func reviewIndexSlot(name, value string) uint64 {
	hash := uint64(14695981039346656037) ^ uint64(constants.OriginHttpRequestCookieValue)
	for i := 0; i < len(name); i++ {
		hash = (hash ^ uint64(name[i])) * 1099511628211
	}
	hash = (hash ^ 0xff) * 1099511628211
	for i := 0; i < len(value); i++ {
		hash = (hash ^ uint64(value[i])) * 1099511628211
	}
	return hash % 512
}

// Use the command sink's actual source-collection API, not a forged collector:
// the source table, managed roots, owner lookup, and source snapshot are real.
type reviewCase struct {
	count   int
	collide bool
	prefix  string
}

func reviewJoinedSources(tb testing.TB, spec reviewCase) ([]string, string, *Snapshot) {
	tb.Helper()
	if !config.Enabled || config.MaxRangeCount != 10 || config.MaxConcurrentRequests != 2 {
		tb.Fatalf("requires default configuration: enabled=%t ranges=%d concurrent=%d",
			config.Enabled, config.MaxRangeCount, config.MaxConcurrentRequests)
	}
	previousSampling := config.RequestSamplingPct
	config.RequestSamplingPct = 100 // Deterministic admission; default is 30%.
	tb.Cleanup(func() { config.RequestSamplingPct = previousSampling })
	ctx, scope, created := request.Begin(context.Background())
	if !created || scope == nil || scope.Decision() != request.DecisionActive {
		tb.Fatal("failed to start sampled request")
	}
	tb.Cleanup(scope.Finish)

	args := make([]string, 0, spec.count)
	used := make(map[uint64]bool, spec.count)
	for candidate := 0; len(args) < spec.count; candidate++ {
		value := spec.prefix + fmt.Sprintf("s%06d", candidate)
		slot := reviewIndexSlot("v", value)
		if spec.collide && slot != 0 || !spec.collide && used[slot] {
			continue
		}
		used[slot] = true
		if actual := sourceHash(request.Source{
			Origin: constants.OriginHttpRequestCookieValue, Name: "v", Value: value,
		}) % 512; actual != slot {
			tb.Fatalf("independently calculated slot %d differs from runtime slot %d", slot, actual)
		}
		name := "v" // One cookie name can have many values; names under two bytes are not tainted.
		request.ManageCookie(ctx, &name, &value)
		if name != "v" || !request.IsTaintedString(value) {
			tb.Fatalf("cookie source %d was not tainted", len(args))
		}
		args = append(args, value)
	}
	result := strings.Join(args, " ")
	snapshot, status := CollectJoinedStrings(args, " ", result, constants.VulnerabilityTypeCommandInjection)
	if status != StatusCollected || snapshot == nil {
		tb.Fatalf("command collection: status=%v snapshot=%v", status, snapshot)
	}
	if snapshot.SourceCount() != spec.count || snapshot.PartCount() != 2*spec.count-1 {
		tb.Fatalf("command collection: sources=%d parts=%d, want %d/%d",
			snapshot.SourceCount(), snapshot.PartCount(), spec.count, 2*spec.count-1)
	}
	for index := 0; index < snapshot.SourceCount(); index++ {
		source, _ := snapshot.SourceAt(index)
		if source.Origin != constants.OriginHttpRequestCookieValue || source.Name != "v" {
			tb.Fatalf("source %d = %#v, want cookie v", index, source)
		}
	}
	return args, result, snapshot
}

func TestReviewCollisionThroughDefaultCommandCollection(t *testing.T) {
	for _, count := range []int{32, 128, 256} {
		for _, collide := range []bool{false, true} {
			label := "distinct"
			if collide {
				label = "colliding"
			}
			t.Run(fmt.Sprintf("%s/%d", label, count), func(t *testing.T) {
				args, _, snapshot := reviewJoinedSources(t, reviewCase{count: count, collide: collide})
				occupiedComparisons := 0
				if collide {
					occupiedComparisons = count * (count - 1) / 2
				}
				t.Logf("case=%s count=%d firstSlot=%d occupiedComparisonsByIndex=%d sources=%d parts=%d args=%d defaultMaxRanges=%d",
					label, count, reviewIndexSlot("v", args[0]), occupiedComparisons,
					snapshot.SourceCount(), snapshot.PartCount(), len(args), config.MaxRangeCount)
			})
		}
	}
}

func TestReviewCollisionWithCommonPrefixWithinCommandAnalyzerLimit(t *testing.T) {
	const count = 256
	prefix := strings.Repeat("a", 100)
	args, result, snapshot := reviewJoinedSources(t, reviewCase{
		count: count, collide: true, prefix: prefix,
	})
	if len(result) > 32<<10 {
		t.Fatalf("command value length %d exceeds analyzer bound", len(result))
	}
	t.Logf("commonPrefixBytes=%d sourceValueBytes=%d commandBytes=%d firstSlot=%d occupiedComparisonsByIndex=%d sources=%d parts=%d",
		len(prefix), len(args[0]), len(result), reviewIndexSlot("v", args[0]),
		count*(count-1)/2, snapshot.SourceCount(), snapshot.PartCount())
}

func TestReviewCollisionNearCommandCollectorBound(t *testing.T) {
	const count = 256
	prefix := strings.Repeat("a", 247)
	args, result, snapshot := reviewJoinedSources(t, reviewCase{
		count: count, collide: true, prefix: prefix,
	})
	if len(result) > 64<<10 {
		t.Fatalf("command value length %d exceeds collector bound", len(result))
	}
	t.Logf("commonPrefixBytes=%d sourceValueBytes=%d commandBytes=%d firstSlot=%d occupiedComparisonsByIndex=%d sources=%d parts=%d",
		len(prefix), len(args[0]), len(result), reviewIndexSlot("v", args[0]),
		count*(count-1)/2, snapshot.SourceCount(), snapshot.PartCount())
}

func BenchmarkReviewIndependentCommandCollection(b *testing.B) {
	for _, count := range []int{32, 64, 128, 256} {
		for _, collide := range []bool{false, true} {
			label := "distinct"
			if collide {
				label = "colliding"
			}
			b.Run(fmt.Sprintf("%s/%d", label, count), func(b *testing.B) {
				b.StopTimer()
				args, result, _ := reviewJoinedSources(b, reviewCase{count: count, collide: collide})
				b.ReportAllocs()
				b.StartTimer()
				for b.Loop() {
					snapshot, status := CollectJoinedStrings(args, " ", result, constants.VulnerabilityTypeCommandInjection)
					if status != StatusCollected || snapshot.SourceCount() != count {
						b.Fatalf("command collection: status=%v sources=%d", status, snapshot.SourceCount())
					}
				}
				b.StopTimer()
			})
		}
	}
}

func BenchmarkReviewIndependentCommandCollectionLong(b *testing.B) {
	for _, prefixLength := range []int{100, 247} {
		for _, collide := range []bool{false, true} {
			label := "distinct"
			if collide {
				label = "colliding"
			}
			b.Run(fmt.Sprintf("prefix=%d/%s", prefixLength, label), func(b *testing.B) {
				b.StopTimer()
				args, result, _ := reviewJoinedSources(b, reviewCase{
					count: 256, collide: collide, prefix: strings.Repeat("a", prefixLength),
				})
				b.ReportAllocs()
				b.StartTimer()
				for b.Loop() {
					snapshot, status := CollectJoinedStrings(args, " ", result, constants.VulnerabilityTypeCommandInjection)
					if status != StatusCollected || snapshot.SourceCount() != 256 {
						b.Fatalf("command collection: status=%v sources=%d", status, snapshot.SourceCount())
					}
				}
				b.StopTimer()
			})
		}
	}
}

// This isolates the hash-index insertion cost from per-argv lookup and sort.
// The inputs were first admitted and validated by the real request/store path.
func BenchmarkReviewIndependentIndexOnly(b *testing.B) {
	for _, collide := range []bool{false, true} {
		label := "distinct"
		if collide {
			label = "colliding"
		}
		b.Run(label, func(b *testing.B) {
			b.StopTimer()
			args, result, _ := reviewJoinedSources(b, reviewCase{
				count: 256, collide: collide, prefix: strings.Repeat("a", 100),
			})
			b.ReportAllocs()
			b.StartTimer()
			for b.Loop() {
				var c collector
				for index, value := range args {
					if !c.add(result, constants.VulnerabilityTypeCommandInjection, request.ResolvedRange{
						Start: uint32(index * 108), Length: uint32(len(value)),
						Source: request.Source{
							Origin: constants.OriginHttpRequestCookieValue, Name: "v", Value: value,
						},
						OwnerID: 1, OwnerGen: 1,
					}) {
						b.Fatal("collector dropped an admitted source")
					}
				}
				if c.sourceCount != 256 {
					b.Fatalf("collector indexed %d of 256 sources", c.sourceCount)
				}
			}
			b.StopTimer()
		})
	}
}
