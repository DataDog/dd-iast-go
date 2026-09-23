package perfsample

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

func runExtra(b *testing.B) {
	src := []byte("GET")
	var fixedBuf bytes.Buffer
	fixedBuf.WriteString("abc")
	var fixedSB strings.Builder
	fixedSB.WriteString("abc")
	cases := []struct {
		name string
		fn   func()
	}{
		{"ConcatLocal2", func() { sink += ConcatLocal2("GE", "T") }},
		{"ConcatLocal4", func() { sink += ConcatLocal4("GE", "T") }},
		{"ConcatLocal5", func() { sink += ConcatLocal5("GE", "T") }},
		{"ConcatLocal8", func() { sink += ConcatLocal8("GE", "T") }},
		{"ConcatLocal16", func() { sink += ConcatLocal16("G", "T") }},
		{"ConcatConvOperand", func() { sink += ConcatConvOperand(src) }},
		{"SplitSeqPass", func() { sink += SplitSeqPass("a,b,c") }},
		{"BufferStringLocal", func() { sinkB = BufferStringLocal(&fixedBuf) }},
		{"BuilderStringLocal", func() { sink += BuilderStringLocal(&fixedSB) }},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				c.fn()
			}
		})
	}
}

func BenchmarkExtra(b *testing.B) { runExtra(b) }

// BenchmarkActive runs every sample with one active (sampled) request scope,
// i.e. the IAST-enabled-but-untainted-data path.
func BenchmarkActive(b *testing.B) {
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	_, scope, created := request.Begin(context.Background())
	if !created {
		b.Skip("no active scope (plain build or disabled)")
	}
	b.Cleanup(func() {
		scope.Finish()
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	b.Run("Sample", BenchmarkSample)
	b.Run("Extra", runExtra)
}
