package redaction

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

func BenchmarkReviewSQLAndRedaction(b *testing.B) {
	previousEnabled, previousSampling := config.Enabled, config.RequestSamplingPct
	previousConcurrent, previousRedaction := config.MaxConcurrentRequests, config.RedactionEnabled
	config.Enabled, config.RequestSamplingPct = true, 100
	config.MaxConcurrentRequests, config.RedactionEnabled = 64, true
	defer func() {
		config.Enabled, config.RequestSamplingPct = previousEnabled, previousSampling
		config.MaxConcurrentRequests, config.RedactionEnabled = previousConcurrent, previousRedaction
	}()
	for _, size := range []int{4096, 8192, 16384, 32768} {
		b.Run(fmt.Sprintf("sql/%d", size), func(b *testing.B) {
			query := "SELECT '" + strings.Repeat("x", size-9) + "'"
			b.ReportAllocs()
			for b.Loop() {
				analysis := AnalyzeSQL(query)
				if analysis.Status != AnalysisOK {
					b.Fatal("valid SQL rejected")
				}
			}
		})
		b.Run(fmt.Sprintf("redact/%d", size), func(b *testing.B) {
			b.StopTimer()
			ctx, scope, created := request.Begin(context.Background())
			if !created {
				b.Fatal("no request scope")
			}
			defer scope.Finish()
			value := taint.TaintString(ctx, taint.Source{
				Origin: constants.OriginHttpRequestParameter,
				Name:   "secret",
			}, strings.Repeat("s", size))
			snapshot, status := evidence.CollectString(value, constants.VulnerabilityTypeSqlInjection)
			if status != evidence.StatusCollected {
				b.Fatalf("snapshot status=%v", status)
			}
			b.ReportAllocs()
			b.StartTimer()
			for b.Loop() {
				result, ok := BuildWithSensitive(snapshot, nil, true)
				if !ok || len(result.Sources) != 1 || len(result.Parts) == 0 {
					b.Fatal("failed to redact")
				}
			}
			b.StopTimer()
		})
	}
}
