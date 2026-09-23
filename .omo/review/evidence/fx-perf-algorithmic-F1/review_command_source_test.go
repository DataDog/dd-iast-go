package evidence_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// Exercise the same collector used by the command sink, keeping the default
// range limit and varying source length independently of the number of ranges.
func BenchmarkReviewCommandRepeatedSource(b *testing.B) {
	if !config.Enabled || config.MaxRangeCount != ranges.DefaultLimit {
		b.Fatalf("expected enabled IAST and default range limit %d, got enabled=%t limit=%d",
			ranges.DefaultLimit, config.Enabled, config.MaxRangeCount)
	}
	previousSampling := config.RequestSamplingPct
	config.RequestSamplingPct = 100 // Deterministically admit the sampled request.
	defer func() { config.RequestSamplingPct = previousSampling }()

	for _, sourceBytes := range []int{128, store.MaxRootBytes} {
		for _, count := range []int{1, ranges.DefaultLimit} {
			b.Run(fmt.Sprintf("sourceBytes=%d/arguments=%d", sourceBytes, count), func(b *testing.B) {
				b.StopTimer()
				ctx, scope, created := request.Begin(context.Background())
				if !created || !scope.Active() {
					b.Fatal("could not acquire request analysis")
				}
				defer scope.Finish()

				headers := request.EagerHTTP(ctx, nil, nil, nil, map[string][]string{
					"X-Input": {strings.Repeat("x", sourceBytes)},
				}, nil, nil)
				root := headers["X-Input"][0]
				if !request.IsTaintedString(root) {
					b.Fatal("HTTP header source was not tainted")
				}
				arguments := make([]string, count)
				for i := range arguments {
					arguments[i] = root[i : i+1]
				}
				propagation.StringWindows(root, arguments)
				command := strings.Join(arguments, " ")
				snapshot, status := evidence.CollectJoinedStrings(
					arguments, " ", command, constants.VulnerabilityTypeCommandInjection,
				)
				if status != evidence.StatusCollected || snapshot.SourceCount() != 1 || snapshot.PartCount() != 2*count-1 {
					b.Fatalf("invalid command evidence: status=%v sources=%d parts=%d",
						status, snapshot.SourceCount(), snapshot.PartCount())
				}
				source, ok := snapshot.SourceAt(0)
				if !ok || source.Value != root {
					b.Fatal("command evidence lost its full original source")
				}
				b.Logf("sourceBytes=%d sinkBytes=%d collectedRanges=%d distinctSources=%d defaultRangeLimit=%d",
					sourceBytes, len(command), count, snapshot.SourceCount(), config.MaxRangeCount)
				b.ReportAllocs()
				b.StartTimer()
				for b.Loop() {
					snapshot, status = evidence.CollectJoinedStrings(
						arguments, " ", command, constants.VulnerabilityTypeCommandInjection,
					)
					if status != evidence.StatusCollected || snapshot.SourceCount() != 1 ||
						snapshot.PartCount() != 2*count-1 {
						b.Fatal("lost command evidence on repeated collection")
					}
				}
				b.StopTimer()
			})
		}
	}
}
