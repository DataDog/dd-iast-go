package evidence

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

// This reproducer exercises the real request -> propagation -> sink snapshot path.
// Each doubling doubles both the number of separated taint ranges and the full
// HTTP source value length; the resulting sink string is only 2*n-1 bytes.
func BenchmarkReviewCollectRepeatedSource(b *testing.B) {
	oldEnabled, oldSampling := config.Enabled, config.RequestSamplingPct
	oldConcurrent, oldRanges := config.MaxConcurrentRequests, config.MaxRangeCount
	config.Enabled, config.RequestSamplingPct = true, 100
	config.MaxConcurrentRequests, config.MaxRangeCount = 64, 64
	defer func() {
		config.Enabled, config.RequestSamplingPct = oldEnabled, oldSampling
		config.MaxConcurrentRequests, config.MaxRangeCount = oldConcurrent, oldRanges
	}()
	for _, count := range []int{8, 16, 32, 64} {
		b.Run(fmt.Sprintf("ranges=%d/sourceBytes=%d", count, count*512), func(b *testing.B) {
			b.StopTimer()
			ctx, scope, created := request.Begin(context.Background())
			if !created {
				b.Fatal("no request scope")
			}
			defer scope.Finish()
			source := taint.TaintString(ctx, taint.Source{
				Origin: constants.OriginHttpRequestParameter, Name: "value",
			}, strings.Repeat("a", count*512))
			if !request.IsTaintedString(source) {
				b.Fatal("source is not tainted")
			}
			one := source[:1]
			propagation.StringWindow(source, one)
			groups := make([]string, 0, (count+15)/16)
			for left := 0; left < count; left += 16 {
				parts := make([]string, min(16, count-left))
				for i := range parts {
					parts[i] = one
				}
				plain := strings.Join(parts, "-")
				groups = append(groups, propagation.JoinString(parts, "-", plain))
			}
			value := groups[0]
			if len(groups) > 1 {
				value = propagation.JoinString(groups, "-", strings.Join(groups, "-"))
			}
			snapshot, status := CollectString(value, constants.VulnerabilityTypeSqlInjection)
			if status != StatusCollected || snapshot.SourceCount() != 1 || snapshot.PartCount() != 2*count-1 {
				b.Fatalf("unexpected provenance: status=%v sources=%d parts=%d", status, snapshot.SourceCount(), snapshot.PartCount())
			}
			b.ReportAllocs()
			b.StartTimer()
			for b.Loop() {
				snapshot, status := CollectString(value, constants.VulnerabilityTypeSqlInjection)
				if status != StatusCollected || snapshot.PartCount() != 2*count-1 {
					b.Fatalf("unexpected collection: status=%v", status)
				}
			}
			b.StopTimer()
		})
	}
}

// All source identities share one FNV index slot, chosen by attacker-controlled
// source strings. The fixed request source table uses a different seeded hash.
func BenchmarkReviewSourceIndexCollisions(b *testing.B) {
	for _, count := range []int{8, 16, 32, 64, 128} {
		for _, collide := range []bool{false, true} {
			label := "distinct"
			if collide {
				label = "colliding"
			}
			b.Run(fmt.Sprintf("%s/%d", label, count), func(b *testing.B) {
				sources := make([]request.Source, 0, count)
				used := make(map[uint64]bool, count)
				for candidate := 0; len(sources) < count; candidate++ {
					source := request.Source{
						Origin: constants.OriginHttpRequestParameter,
						Name:   "same-name",
						Value:  "source-" + strconv.Itoa(candidate),
					}
					slot := sourceHash(source) % 512
					if collide && slot != 0 || !collide && used[slot] {
						continue
					}
					used[slot] = true
					sources = append(sources, source)
				}
				value := strings.Repeat("x-", count)
				b.ReportAllocs()
				for b.Loop() {
					var c collector
					for index, source := range sources {
						if !c.add(value, constants.VulnerabilityTypeSqlInjection, request.ResolvedRange{
							Start: uint32(index * 2), Length: 1, Source: source,
							OwnerID: 1, OwnerGen: 1,
						}) {
							b.Fatal("collector dropped valid source")
						}
					}
					if c.sourceCount != count {
						b.Fatal("wrong source count")
					}
				}
			})
		}
	}
}

func BenchmarkReviewRepeatedSourceIndex(b *testing.B) {
	for _, count := range []int{8, 16, 32, 64} {
		b.Run(fmt.Sprintf("ranges=%d/sourceBytes=%d", count, count*512), func(b *testing.B) {
			source := request.Source{
				Origin: constants.OriginHttpRequestParameter, Name: "parameter",
				Value: strings.Repeat("a", count*512),
			}
			value := strings.Repeat("x-", count)
			b.ReportAllocs()
			for b.Loop() {
				var c collector
				for index := 0; index < count; index++ {
					if !c.add(value, constants.VulnerabilityTypeSqlInjection, request.ResolvedRange{
						Start: uint32(index * 2), Length: 1, Source: source,
						OwnerID: 1, OwnerGen: 1,
					}) {
						b.Fatal("collector dropped valid range")
					}
				}
				if c.count != count || c.sourceCount != 1 {
					b.Fatal("unexpected range/source count")
				}
			}
		})
	}
}

func BenchmarkReviewOneSourceHash(b *testing.B) {
	for _, count := range []int{8, 16, 32, 64} {
		b.Run(fmt.Sprintf("sourceBytes=%d", count*512), func(b *testing.B) {
			source := request.Source{
				Origin: constants.OriginHttpRequestParameter, Name: "parameter",
				Value: strings.Repeat("a", count*512),
			}
			var last uint64
			for b.Loop() {
				last = sourceHash(source)
			}
			if last == 0 {
				b.Fatal("unexpected zero hash")
			}
		})
	}
}
