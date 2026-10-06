// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// allWorkloads are the top-level workloads of the benchmark module (both
// trees; the tree of PR #39 has no HeapBits workload).
var allWorkloads = []string{
	"BytesBuffer", "BytesBufferCopies", "BytesClone", "BytesJoin", "BytesMap", "BytesRepeat",
	"BytesReplaceAll", "BytesSplit", "BytesToLower", "BytesTrimSpace", "ConcatChainHeap",
	"ConcatChainStack", "FmtSprintf", "Health", "HeapBitsAllocChurn", "HeapBitsGC", "HeapBitsJSON",
	"HTTPRoundTrip", "PropagationActiveUntainted", "RequestProcessing", "RequestProcessingParallel",
	"SinkCommand", "SinkSQL", "StrconvQuote", "StringsBuilder", "StringsClone", "StringsJoin",
	"StringsRepeat", "StringsReplaceAll", "StringsSplit", "StringsSplitSeq", "StringsToLower",
	"StringsTrimSpace", "URLQueryEscape", "WeakCipherActiveSpan", "WeakCipherNoActiveSpan",
	"WeakHashActiveSpan", "WeakHashNoActiveSpan",
}

func TestPassExpressions(t *testing.T) {
	gateOff := 0
	for _, name := range allWorkloads {
		if got, want := selectsTopLevel(gateOffBench, name), gateOffWorkload(name); got != want {
			t.Errorf("gate-off -bench selects %s: %v, want %v", name, got, want)
		}
		if gateOffWorkload(name) {
			gateOff++
		}
		if got, want := selectsTopLevel(activeBench, name), name == "PropagationActiveUntainted"; got != want {
			t.Errorf("active -bench selects %s: %v, want %v", name, got, want)
		}
	}
	// The 21 G-A3 workloads of PR #39 (without BytesBufferCopies) and the 2
	// G-A5 workloads.
	if gateOff != 21+2 {
		t.Errorf("gate-off workloads = %d, want 23", gateOff)
	}
	if gateA3Workload("BytesBufferCopies/read") || !untaintedWorkload("PropagationActiveUntainted/ByteCopy") {
		t.Error("BytesBufferCopies must not be a G-A3 workload; PropagationActiveUntainted is untainted")
	}
	if !selectsTopLevel("HeapBits|Health", "HeapBitsGC") || selectsTopLevel("^HeapBits", "HeapBitsGC") || !selectsTopLevel(".", "HeapBitsGC") || !selectsTopLevel("/x", "HeapBitsGC") {
		t.Error("selectsTopLevel does not match like go test")
	}
}

func TestValidateTaintLive(t *testing.T) {
	for _, test := range []struct {
		value    string
		sampling int
		wantErr  string
	}{
		{"", 0, ""},
		{"", 100, ""},
		{"1", 100, ""},
		{"1", 0, "needs -sampling=100"},
		{"1", 50, "needs -sampling=100"},
		{"true", 100, "must be empty or 1"},
	} {
		err := validateTaintLive(test.value, test.sampling)
		if test.wantErr == "" && err != nil || test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
			t.Errorf("validateTaintLive(%q, %d) = %v, want %q", test.value, test.sampling, err, test.wantErr)
		}
	}
}

// resultsDir writes the files to a new output directory and returns a
// configuration for it.
func resultsDir(t *testing.T, files map[string]string) configuration {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range files {
		if err := os.WriteFile(dir+"/"+name, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	output, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { output.Close() })
	return configuration{output: output, count: 4, sampling: 100}
}

// lines returns count result lines for each workload, with ns/op from ns.
func lines(count int, ns float64, names ...string) string {
	var b strings.Builder
	for range count {
		for _, name := range names {
			fmt.Fprintf(&b, "Benchmark%s-1 100 %g ns/op 8 B/op 1 allocs/op\n", name, ns)
		}
	}
	return b.String()
}

func metadata(sampling int, count int, live string) string {
	return fmt.Sprintf("revision=x\ncount=%d\nsampling=%d\ntaint_live=%q\n", count, sampling, live)
}

func rows(results []gateResult) map[string]gateResult {
	out := map[string]gateResult{}
	for _, r := range results {
		key := r.rule[:strings.IndexByte(r.rule, ' ')] + " " + r.benchmark
		out[key] = r
	}
	return out
}

func TestPairedGateClasses(t *testing.T) {
	t.Setenv(gateProfileEnvironment, "")
	tests := []struct {
		name      string
		workloads []string
		live      string
		sampling  int
		want      map[string]string // "<id> <benchmark>" -> status
	}{
		{
			name:      "gate-off pass",
			workloads: []string{"StringsClone", "ConcatChainHeap"},
			sampling:  100,
			want:      map[string]string{"G-A3 StringsClone": "PASS", "G-A5 ConcatChainHeap": "PASS", "G-A4 PropagationActiveUntainted/*": "SKIP", "G-A3L Strings*|Bytes*|Fmt*|URL*|Strconv*": "N/A"},
		},
		{
			// BytesBufferCopies taints data: the sticky gate of the heapbits
			// tree is on for the next workloads, so G-A3 does not apply.
			name:      "process that taints",
			workloads: []string{"BytesBufferCopies/read", "StringsClone", "PropagationActiveUntainted/ByteCopy"},
			sampling:  100,
			want: map[string]string{
				"G-A3 Strings*|Bytes*|Fmt*|URL*|Strconv*": "N/A", "G-A4 PropagationActiveUntainted/*": "N/A",
				"REC BytesBufferCopies/read": "INFO", "REC StringsClone": "INFO", "REC PropagationActiveUntainted/ByteCopy": "INFO",
			},
		},
		{
			name:      "active pass",
			workloads: []string{"PropagationActiveUntainted/ByteCopy"},
			sampling:  100,
			want:      map[string]string{"G-A4 PropagationActiveUntainted/ByteCopy": "PASS", "G-A3 Strings*|Bytes*|Fmt*|URL*|Strconv*": "N/A"},
		},
		{
			name:      "taint live pass",
			workloads: []string{"StringsClone", "PropagationActiveUntainted/ByteCopy", "ConcatChainStack"},
			live:      "1",
			sampling:  100,
			want: map[string]string{
				"G-A3L StringsClone": "INFO", "G-A4L PropagationActiveUntainted/ByteCopy": "INFO", "G-A5L ConcatChainStack": "INFO",
				"G-A3 Strings*|Bytes*|Fmt*|URL*|Strconv*": "N/A",
			},
		},
		{
			name:      "sampled out",
			workloads: []string{"HTTPRoundTrip", "SinkSQL/tainted"},
			sampling:  0,
			want:      map[string]string{"G-A1 HTTPRoundTrip": "PASS", "G-A2 HTTPRoundTrip": "N/A", "REC SinkSQL/tainted": "INFO"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := resultsDir(t, map[string]string{
				controlResultsFile: lines(4, 100, test.workloads...),
				iastResultsFile:    lines(4, 101, test.workloads...),
			})
			cfg.sampling, cfg.taintLive = test.sampling, test.live
			results, err := checkPairedGates(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got := rows(results)
			for key, status := range test.want {
				r, ok := got[key]
				if !ok {
					t.Errorf("no row %q in %v", key, got)
					continue
				}
				if gateStatus(r) != status {
					t.Errorf("%s: status %s, want %s (%s)", key, gateStatus(r), status, r.delta)
				}
			}
		})
	}
}

func TestPairedGateRecordVerdict(t *testing.T) {
	cfg := resultsDir(t, map[string]string{
		controlResultsFile: lines(4, 10, "StringsClone"),
		iastResultsFile:    lines(4, 30, "StringsClone"),
	})
	cfg.taintLive = taintLiveOn
	results, err := checkPairedGates(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := rows(results)["G-A3L StringsClone"]
	if gateStatus(r) != "INFO" || r.timeVerdict != verdictFail || r.allocsVerdict != verdictPass {
		t.Fatalf("a record-only rule must keep the verdict of its limit: %+v", r)
	}
	if !strings.Contains(formatGateTable(results, false), "INFO\tG-A3L\tStringsClone\t4\t") ||
		!strings.Contains(formatGateTable(results, false), "\t8\t8\tFAIL\tPASS\n") {
		t.Errorf("gate.tsv:\n%s", formatGateTable(results, false))
	}
}

func TestIncompletePairs(t *testing.T) {
	series := func(n int) []benchSample {
		out := make([]benchSample, n)
		for i := range out {
			out[i] = benchSample{ns: 10, hasAllocs: true}
		}
		return out
	}
	rule := pairedRule{name: "small", kind: limitSmall, allocs: true}
	d := comparePaired(series(2), series(2))
	if r := evaluatePaired(rule, "X", d, "local", 2, true); r.pass || !strings.Contains(r.delta, "INCOMPLETE") {
		t.Errorf("2 pairs in an enforced gate must fail (INCOMPLETE): %+v", r)
	}
	if r := evaluatePaired(rule, "X", d, "local", 2, false); !r.pass || !strings.Contains(r.delta, "too few pairs") {
		t.Errorf("2 pairs in an informative gate: %+v", r)
	}
	record := pairedRule{name: "record", kind: limitNone, record: true}
	if r := evaluatePaired(record, "X", d, "local", 2, true); gateStatus(r) != "FAIL" {
		t.Errorf("an incomplete record-only row must fail an enforced gate: %+v", r)
	}
	d = comparePaired(series(4), series(4))
	if r := evaluatePaired(rule, "X", d, "local", 20, false); r.pass || !strings.Contains(r.delta, "INCOMPLETE: 4 pairs, want 20") {
		t.Errorf("4 pairs of 20 must fail: %+v", r)
	}
}

func TestValidateSampleCounts(t *testing.T) {
	tests := []struct {
		name          string
		control, iast string
		wantErr       string
	}{
		{"complete", lines(4, 1, "A", "B"), lines(4, 1, "A", "B"), ""},
		{"unequal", lines(4, 1, "A", "B"), lines(3, 1, "A", "B"), "iast.txt: A has 3 samples, want 4"},
		{"missing workload", lines(4, 1, "A", "B"), lines(4, 1, "A"), "iast.txt has the workloads [A]"},
		{"extra sample", lines(5, 1, "A"), lines(4, 1, "A"), "control.txt: A has 5 samples, want 4"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := resultsDir(t, map[string]string{controlResultsFile: test.control, iastResultsFile: test.iast})
			err := validateSampleCounts(cfg, []string{controlResultsFile, iastResultsFile})
			if test.wantErr == "" && err != nil || test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Errorf("validateSampleCounts() = %v, want %q", err, test.wantErr)
			}
		})
	}
	// checkGates refuses incomplete results, also without -gate.
	cfg := resultsDir(t, map[string]string{controlResultsFile: lines(4, 1, "A"), iastResultsFile: lines(3, 1, "A")})
	if err := checkGates(cfg); err == nil || !strings.Contains(err.Error(), "incomplete results") {
		t.Errorf("checkGates() = %v, want incomplete results", err)
	}
}

func TestApplyMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
		cfg      configuration
		env      string
		want     configuration
		wantErr  string
	}{
		{
			// The default -sampling=100 must not hide the sampling of the run.
			name:     "sampling 0 from metadata",
			metadata: metadata(0, 20, ""),
			cfg:      configuration{sampling: 100, count: 10},
			want:     configuration{sampling: 0, count: 20},
		},
		{
			name:     "explicit flags that agree",
			metadata: metadata(0, 20, ""),
			cfg:      configuration{sampling: 0, samplingSet: true, count: 20, countSet: true},
			want:     configuration{sampling: 0, count: 20},
		},
		{name: "sampling mismatch", metadata: metadata(0, 20, ""), cfg: configuration{sampling: 100, samplingSet: true}, wantErr: "-sampling=100 does not agree with sampling=0"},
		{name: "count mismatch", metadata: metadata(100, 2, ""), cfg: configuration{count: 20, countSet: true}, wantErr: "-count=20 does not agree with count=2"},
		{name: "taint live from metadata", metadata: metadata(100, 4, "1"), want: configuration{sampling: 100, count: 4, taintLive: "1"}},
		{name: "taint live mismatch", metadata: metadata(100, 4, ""), env: "1", wantErr: `DD_IAST_BENCH_TAINT_LIVE="1" does not agree with taint_live=""`},
		{name: "taint live sampled out", metadata: metadata(0, 4, "1"), wantErr: "needs -sampling=100"},
		{name: "no taint_live", metadata: "count=4\nsampling=100\n", wantErr: "has no taint_live"},
		{name: "no sampling", metadata: "count=4\ntaint_live=\"\"\n", wantErr: "sampling of metadata.txt"},
		{name: "invalid line", metadata: "count=4\nsampling\n", wantErr: "invalid line"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := resultsDir(t, map[string]string{metadataFile: test.metadata})
			output := cfg.output
			cfg = test.cfg
			cfg.output, cfg.taintLive = output, test.env
			got, err := applyMetadata(cfg)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("applyMetadata() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.sampling != test.want.sampling || got.count != test.want.count || got.taintLive != test.want.taintLive {
				t.Fatalf("applyMetadata() = sampling %d, count %d, taint live %q; want %d, %d, %q",
					got.sampling, got.count, got.taintLive, test.want.sampling, test.want.count, test.want.taintLive)
			}
		})
	}
	if _, err := applyMetadata(resultsDir(t, nil)); err == nil || !strings.Contains(err.Error(), "-evaluate needs metadata.txt") {
		t.Errorf("applyMetadata() with no metadata.txt = %v", err)
	}
}

// TestEvaluateSampledOut evaluates the results of a sampling-0 run with the
// default flags: G-A1 must apply (it gates the HTTP overhead), and an
// enforced gate must fail on a regression.
func TestEvaluateSampledOut(t *testing.T) {
	t.Setenv(gateProfileEnvironment, "")
	cfg := resultsDir(t, map[string]string{
		controlResultsFile: lines(4, 1000, "HTTPRoundTrip"),
		iastResultsFile:    lines(4, 1100, "HTTPRoundTrip"),
		metadataFile:       metadata(0, 4, ""),
	})
	cfg.sampling, cfg.gate = 100, true // the defaults of the flags, and -gate
	cfg, err := applyMetadata(cfg)
	if err != nil {
		t.Fatal(err)
	}
	results, err := checkPairedGates(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := rows(results)["G-A1 HTTPRoundTrip"]
	if gateStatus(r) != "FAIL" {
		t.Fatalf("G-A1 at +10 %%: %s %s, want FAIL", gateStatus(r), r.delta)
	}
	if _, failed := formatGateReport(results, true); !failed {
		t.Fatal("the enforced report must fail")
	}
}
