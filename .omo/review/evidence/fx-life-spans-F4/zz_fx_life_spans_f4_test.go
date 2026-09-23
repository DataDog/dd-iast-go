// Review reproducer (fx-life-spans-F4). Not part of the repository.

package overhead_test

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

var (
	fxMD5  [md5.Size]byte
	fxSHA1 [sha1.Size]byte
)

func fxEnv() string {
	return fmt.Sprintf("DD_IAST_ENABLED=%q DD_IAST_REQUEST_SAMPLING=%q DD_IAST_STACK_TRACE_ENABLED=%q",
		os.Getenv("DD_IAST_ENABLED"), os.Getenv("DD_IAST_REQUEST_SAMPLING"), os.Getenv("DD_IAST_STACK_TRACE_ENABLED"))
}

type fxSummary struct {
	spans, withPayload, forcedKeep, vulns int
	hashes                                map[string]int
	names                                 map[string]int
}

func fxSummarize(t *testing.T, mt mocktracer.Tracer) fxSummary {
	t.Helper()
	sum := fxSummary{hashes: map[string]int{}, names: map[string]int{}}
	for _, s := range mt.FinishedSpans() {
		sum.spans++
		sum.names[s.OperationName()]++
		if p, _ := s.Tag("_sampling_priority_v1").(float64); p == 2 {
			sum.forcedKeep++
		}
		payload, _ := s.Tag("_dd.iast.json").(string)
		if payload == "" {
			continue
		}
		sum.withPayload++
		var ev struct {
			Vulnerabilities []struct {
				Type string          `json:"type"`
				Hash json.RawMessage `json:"hash"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatalf("bad payload %q: %v", payload, err)
		}
		for _, v := range ev.Vulnerabilities {
			sum.vulns++
			sum.hashes[v.Type+"/"+string(v.Hash)]++
		}
	}
	return sum
}

// A background worker (no request, no span) hashing with md5/sha1 at ONE call
// site each, e.g. cache keys or ETags.
func fxBackgroundWorker(n int, p []byte) {
	for range n {
		fxMD5 = md5.Sum(p)   //nolint:gosec // reproducer
		fxSHA1 = sha1.Sum(p) //nolint:gosec // reproducer
	}
}

func TestFxOrphanPerCallOutsideSpan(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	mt := mocktracer.Start()
	defer mt.Stop()
	const n = 500
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fxBackgroundWorker(n, []byte("etag payload")) }()
	wg.Wait()
	s := fxSummarize(t, mt)
	t.Logf("%s", fxEnv())
	t.Logf("background worker: %d md5.Sum + %d sha1.Sum calls (2 call sites) -> finished spans=%d names=%v", n, n, s.spans, s.names)
	t.Logf("spans carrying _dd.iast.json=%d, forced-keep (_sampling_priority_v1=2)=%d, vulnerabilities=%d, distinct type/hash=%d", s.withPayload, s.forcedKeep, s.vulns, len(s.hashes))
	for k, c := range s.hashes {
		t.Logf("  finding %s emitted %d times", k, c)
	}
	mt.Reset()
	p := []byte("etag payload")
	allocs := testing.AllocsPerRun(1000, func() { fxMD5 = md5.Sum(p) }) //nolint:gosec // reproducer
	t.Logf("allocs per md5.Sum outside any span (averaged over 1000 calls): %.1f", allocs)
	t.Logf("spans finished during alloc measurement: %d", len(mt.FinishedSpans()))
}

func TestFxInRequestRepeatedCalls(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	mt := mocktracer.Start()
	defer mt.Stop()
	var firstAllocs, laterAllocs float64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := []byte("request payload")
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fxMD5 = md5.Sum(p) //nolint:gosec // reproducer: first call records the finding
		runtime.ReadMemStats(&after)
		firstAllocs = float64(after.Mallocs - before.Mallocs)
		// The finding is recorded now; every later call at the same site is dropped.
		laterAllocs = testing.AllocsPerRun(1000, func() { fxMD5 = md5.Sum(p) }) //nolint:gosec // reproducer
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/hash")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	server.Close()
	s := fxSummarize(t, mt)
	t.Logf("%s", fxEnv())
	t.Logf("one woven HTTP request doing 1002 md5.Sum calls at one site -> spans=%d names=%v withPayload=%d vulnerabilities=%d distinct=%v", s.spans, s.names, s.withPayload, s.vulns, s.hashes)
	t.Logf("allocs: first call=%.0f, later (already-recorded) calls avg over 1000=%.1f", firstAllocs, laterAllocs)
}

// Real tracer (not mocktracer) against a fake agent: cost of one md5.Sum
// outside any span, measured on the same woven binary.
func TestFxRealTracerAllocs(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	}))
	defer agent.Close()
	if err := tracer.Start(tracer.WithAgentURL(agent.URL), tracer.WithLogStartup(false)); err != nil {
		t.Fatal(err)
	}
	defer tracer.Stop()
	p := []byte("etag payload")
	allocs := testing.AllocsPerRun(2000, func() { fxMD5 = md5.Sum(p) }) //nolint:gosec // reproducer
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			fxMD5 = md5.Sum(p) //nolint:gosec // reproducer
		}
	})
	t.Logf("%s", fxEnv())
	t.Logf("real tracer, md5.Sum outside any span: allocs/call=%.1f; bench %s %s (timing indicative only, shared machine)", allocs, res.String(), res.MemString())
}
