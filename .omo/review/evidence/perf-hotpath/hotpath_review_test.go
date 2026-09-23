// Review-only benchmark; copy this file into iast/propagation in the private checkout.
package propagation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	hooks "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

var reviewString string
var reviewBytes []byte
var reviewAny any

func BenchmarkHotPathReview(b *testing.B) {
	parts := make([]string, 4096)
	for i := range parts {
		parts[i] = "x"
	}
	large := make([]string, 65536)
	for i := range large {
		large[i] = "x"
	}
	empty := make([]string, 4096)
	value := strings.Repeat("a", 64)
	raw := []byte(value)
	payload := []byte(`{"name":"clean"}`)
	run := func(b *testing.B, f func()) {
		b.Helper()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			f()
		}
	}
	cases := func(prefix string) {
		b.Run(prefix+"/join/native", func(b *testing.B) {
			run(b, func() { reviewString = strings.Join(parts, "") })
		})
		b.Run(prefix+"/join/hook", func(b *testing.B) {
			run(b, func() { reviewString = hooks.StringsJoin(parts, "") })
		})
		b.Run(prefix+"/join/large-gate", func(b *testing.B) {
			result := strings.Join(large, "")
			run(b, func() { reviewString = internal.JoinString(large, "", result) })
		})
		b.Run(prefix+"/join-empty/native", func(b *testing.B) {
			run(b, func() { reviewString = strings.Join(empty, "") })
		})
		b.Run(prefix+"/join-empty/hook", func(b *testing.B) {
			run(b, func() { reviewString = hooks.StringsJoin(empty, "") })
		})
		b.Run(prefix+"/split-seq/native", func(b *testing.B) {
			run(b, func() { reviewAny = strings.SplitSeq(value, "a") })
		})
		b.Run(prefix+"/split-seq/hook", func(b *testing.B) {
			run(b, func() { reviewAny = hooks.StringsSplitSeq(value, "a") })
		})
		b.Run(prefix+"/split-seq-consumed/native", func(b *testing.B) {
			run(b, func() {
				for part := range strings.SplitSeq(value, "a") {
					reviewString = part
				}
			})
		})
		b.Run(prefix+"/split-seq-consumed/hook", func(b *testing.B) {
			run(b, func() {
				for part := range hooks.StringsSplitSeq(value, "a") {
					reviewString = part
				}
			})
		})
		b.Run(prefix+"/builder/native", func(b *testing.B) {
			var builder strings.Builder
			run(b, func() {
				builder.Reset()
				builder.WriteString(value)
				reviewString = builder.String()
			})
		})
		b.Run(prefix+"/builder/hook", func(b *testing.B) {
			var builder strings.Builder
			run(b, func() {
				builder.Reset()
				hooks.BuilderWriteString(&builder, value)
				reviewString = builder.String()
			})
		})
		b.Run(prefix+"/buffer/native", func(b *testing.B) {
			var buffer bytes.Buffer
			run(b, func() {
				buffer.Reset()
				buffer.WriteString(value)
				reviewString = buffer.String()
			})
		})
		b.Run(prefix+"/buffer/hook", func(b *testing.B) {
			var buffer bytes.Buffer
			run(b, func() {
				buffer.Reset()
				hooks.BufferWriteString(&buffer, value)
				reviewString = buffer.String()
			})
		})
		b.Run(prefix+"/concat/native", func(b *testing.B) {
			run(b, func() { reviewString = value + value })
		})
		b.Run(prefix+"/concat/hook", func(b *testing.B) {
			run(b, func() { reviewString = hooks.Concat2(value, value) })
		})
		b.Run(prefix+"/case/native", func(b *testing.B) {
			run(b, func() { reviewString = strings.ToUpper(value) })
		})
		b.Run(prefix+"/case/hook", func(b *testing.B) {
			run(b, func() { reviewString = hooks.StringsToUpper(value) })
		})
		b.Run(prefix+"/fmt/native", func(b *testing.B) {
			run(b, func() { reviewString = fmt.Sprintf("%s/%s", value, value) })
		})
		b.Run(prefix+"/fmt/hook", func(b *testing.B) {
			run(b, func() { reviewString = hooks.FmtSprintf("%s/%s", value, value) })
		})
		b.Run(prefix+"/bytes/native", func(b *testing.B) {
			run(b, func() { reviewBytes = bytes.Clone(raw) })
		})
		b.Run(prefix+"/bytes/hook", func(b *testing.B) {
			run(b, func() { reviewBytes = hooks.BytesClone(raw) })
		})
		b.Run(prefix+"/json/native", func(b *testing.B) {
			var decoded struct{ Name string }
			if err := json.Unmarshal(payload, &decoded); err != nil { b.Fatal(err) }
			reviewAny = decoded
		})
		b.Run(prefix+"/json/bridge", func(b *testing.B) {
			run(b, func() { jsonbridge.Quoted(nil, payload, 0, len(payload), `"clean"`) })
		})
	}
	cases("no-owner")
	original := config.RequestSamplingPct
	config.RequestSamplingPct = 100
	defer func() { config.RequestSamplingPct = original }()
	ctx, created := request.BeginContext(context.Background())
	if !created {
		b.Fatal("could not acquire active request owner")
	}
	defer request.FinishContext(ctx, created)
	cases("active-clean")
}
