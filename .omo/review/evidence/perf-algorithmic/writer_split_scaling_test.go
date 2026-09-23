package propagation

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

func BenchmarkReviewBuilderAndSplit(b *testing.B) {
	oldEnabled, oldSampling, oldConcurrent := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	defer func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldConcurrent
	}()
	for _, count := range []int{128, 256, 512, 1024, 2048} {
		b.Run(fmt.Sprintf("builder/%d", count), func(b *testing.B) {
			b.StopTimer()
			ctx, scope, created := request.Begin(context.Background())
			if !created {
				b.Fatal("no request scope")
			}
			defer scope.Finish()
			input := taint.TaintString(ctx, taint.Source{
				Origin: constants.OriginHttpRequestParameter, Name: "value",
			}, "xx")
			var builder strings.Builder
			builder.Grow(count * len(input))
			b.ReportAllocs()
			b.StartTimer()
			for b.Loop() {
				BuilderReset(&builder)
				for index := 0; index < count; index++ {
					if _, err := BuilderWriteString(&builder, input); err != nil {
						b.Fatal(err)
					}
				}
				if builder.Len() != count*len(input) {
					b.Fatal("short builder")
				}
			}
			b.StopTimer()
		})
		b.Run(fmt.Sprintf("split/%d", count), func(b *testing.B) {
			b.StopTimer()
			ctx, scope, created := request.Begin(context.Background())
			if !created {
				b.Fatal("no request scope")
			}
			defer scope.Finish()
			value := taint.TaintString(ctx, taint.Source{
				Origin: constants.OriginHttpRequestParameter, Name: "value",
			}, strings.Repeat("a,", count))
			b.ReportAllocs()
			b.StartTimer()
			for b.Loop() {
				output := StringsSplit(value, ",")
				if len(output) != count+1 {
					b.Fatal("unexpected split result count")
				}
			}
			b.StopTimer()
		})
	}
}
