// Command wbench measures the process-wide cost that the woven bytes.Buffer
// invalidation hook adds to unrelated code (json.Marshal in a goroutine with
// no request) while request writer state exists.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

type doc struct {
	Name   string
	Items  []string
	Values map[string]int
	Nested []struct{ A, B string }
}

var sample = func() doc {
	d := doc{Name: "clean-name", Values: map[string]int{}}
	for i := range 64 {
		d.Items = append(d.Items, fmt.Sprintf("item-%d", i))
		d.Values[fmt.Sprintf("k%d", i)] = i
		d.Nested = append(d.Nested, struct{ A, B string }{"a", "b"})
	}
	return d
}()

func measure() float64 {
	r := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			if _, err := json.Marshal(&sample); err != nil {
				b.Fatal(err)
			}
		}
	})
	return float64(r.T.Nanoseconds()) / float64(r.N)
}

type request struct {
	ctx context.Context
	buf *bytes.Buffer
}

func open(n int, withWriter bool) []request {
	var out []request
	for i := range n {
		ctx, _, created := taintrequest.Begin(context.Background())
		if !created || !taintrequest.FromContext(ctx).Active() {
			fmt.Println("scope not active at", i)
			continue
		}
		req := request{ctx: ctx}
		if withWriter {
			v := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "q"}, fmt.Sprintf("tainted-%d-value", i))
			req.buf = new(bytes.Buffer)
			req.buf.WriteString(v) // direct root-application call: creates writer state
		}
		out = append(out, req)
	}
	return out
}

func closeAll(rs []request) {
	for _, r := range rs {
		taintrequest.FinishContext(r.ctx, true)
	}
}

func main() {
	fmt.Printf("woven=%v DD_IAST_MAX_CONCURRENT_REQUESTS=%s\n", built.WithOrchestrion, os.Getenv("DD_IAST_MAX_CONCURRENT_REQUESTS"))
	configs := []struct {
		name   string
		n      int
		writer bool
	}{
		{"no request", 0, false},
		{"1 active request, no writer", 1, false},
		{"1 active request with writer", 1, true},
		{"64 active requests with writers", 64, true},
	}
	res := make([][]float64, len(configs))
	for round := range 5 {
		for i, c := range configs {
			rs := open(c.n, c.writer)
			active := writerbridge.Active()
			res[i] = append(res[i], measure())
			closeAll(rs)
			if round == 0 {
				fmt.Printf("  %-34s opened=%d writerbridge.Active=%v\n", c.name, len(rs), active)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	base := 0.0
	for i, c := range configs {
		slices.Sort(res[i])
		med := res[i][len(res[i])/2]
		if i == 0 {
			base = med
		}
		fmt.Printf("json.Marshal (no request ctx) %-34s median=%8.0f ns/op  x%.2f  samples=%v\n", c.name, med, med/base, fmtAll(res[i]))
	}
}

func fmtAll(v []float64) []int {
	out := make([]int, len(v))
	for i, x := range v {
		out[i] = int(x)
	}
	return out
}
