// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ci_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests of runtime-bench.py (the gate report) and runtime-bench.sh (the
// argument checks and the source transforms). They do not build or run a
// benchmark.

var (
	benchPlacements = []string{"00", "01", "03", "05", "07", "09", "11", "13"}
	benchShapes     = []string{
		"concat2-heap", "concat4-heap", "concat6-heap", "concat16-heap",
		"concat2-stack", "concat4-stack", "concat6-stack", "concat16-stack",
		"b2s-heap", "b2s-stack", "s2b-heap", "s2b-stack",
		"r2s-heap", "r2s-stack", "s2r-heap", "s2r-stack",
	}
	benchLoads = []string{"sparse", "typical", "full"}
)

// benchResult is the result of one benchmark case in one run.
type benchResult struct {
	ns     float64
	bytes  int
	allocs int
}

// benchData is a complete set of results. Change it before write.
type benchData struct {
	// hook and nohook are the runtime results: case -> placement -> result.
	hook, nohook map[string]map[string]benchResult
	placements   []string
	runs         int
	suffix       string // the GOMAXPROCS suffix of the benchmark names
	store        map[string]benchResult
	admissionOld map[string]float64
	admissionNew map[string]float64
	short        map[string]string // case -> the placement with one hook run less
	storeRuns    int               // runs of each store and admission row
	httpRuns     int               // runs of each side of the HTTP benchmark
	allocs       bool
}

// newBenchData returns data where every gate passes. The hook cost of a
// placement is 0.2 ns x its index, so the pooled median (+0.70 ns) is not the
// worst placement (+1.40 ns, k=13).
func newBenchData() *benchData {
	d := &benchData{
		hook:         map[string]map[string]benchResult{},
		nohook:       map[string]map[string]benchResult{},
		placements:   benchPlacements,
		runs:         8,
		suffix:       "-8",
		store:        map[string]benchResult{},
		admissionOld: map[string]float64{},
		admissionNew: map[string]float64{},
		storeRuns:    8,
		httpRuns:     10,
		allocs:       true,
	}
	add := func(name string, nohook, hook benchResult) {
		d.hook[name], d.nohook[name] = map[string]benchResult{}, map[string]benchResult{}
		for i, k := range d.placements {
			shifted := hook
			shifted.ns += 0.2 * float64(i)
			d.hook[name][k], d.nohook[name][k] = shifted, nohook
		}
	}
	for _, group := range []string{"RuntimeOff", "RuntimeClean"} {
		for _, shape := range benchShapes {
			add(group+"/"+shape, benchResult{20, 48, 1}, benchResult{20, 48, 1})
		}
	}
	for _, shape := range []string{"s2b-heap", "s2b-stack", "s2r-heap", "s2r-stack"} {
		add("RuntimeS2SOff/"+shape, benchResult{20, 0, 0}, benchResult{20, 0, 0})
	}
	add("RuntimeCleanHit/s2b-stack", benchResult{10, 0, 0}, benchResult{40, 0, 0})
	add("RuntimeCleanHit/concat2-stack", benchResult{10, 0, 0}, benchResult{60, 0, 0})
	for name, bytes := range map[string]int{"concat2": 16, "b2s": 16, "s2b": 16, "r2s": 16, "s2r": 48} {
		add("RuntimeTainted/"+name+"-stack", benchResult{10, 0, 0}, benchResult{600, bytes, 1})
	}
	for _, load := range benchLoads {
		for _, c := range []string{"clean-random", "clean-miss", "clean-neighbor"} {
			d.store["MayContain/"+c+"/"+load] = benchResult{2, 0, 0}
		}
		d.store["RuntimePre/"+load+"/one-clean-hit"] = benchResult{30, 0, 0}
	}
	d.store["RuntimePre/sparse/concat2-clean-hit"] = benchResult{50, 0, 0}
	d.store["RuntimePre/full/concat2-clean-hit"] = benchResult{70, 0, 0}
	d.store["RuntimePre/full/concat2-clean-random"] = benchResult{60, 0, 0}
	for _, workload := range []string{"params1000", "dense256", "span257"} {
		for _, api := range []string{"TaintString", "TaintBytes", "TaintSourceString", "TaintSourceBytes", "AdoptSourceBytes"} {
			for _, load := range []string{"sparse", "stressed", "saturated"} {
				name := fmt.Sprintf("SourceAdmission/%s/%s/%s", workload, load, api)
				d.admissionOld[name], d.admissionNew[name] = 99, 99
			}
		}
	}
	for _, load := range []string{"sparse", "stressed", "saturated"} {
		name := "SourceAdmission/collide/" + load + "/AdoptSourceBytes"
		d.admissionOld[name], d.admissionNew[name] = 99, 99
	}
	d.admissionOld["SourceAdmission/retention/sparse/TaintString"] = 100
	d.admissionNew["SourceAdmission/retention/sparse/TaintString"] = 100
	return d
}

func (d *benchData) line(name string, r benchResult, extra string) string {
	return fmt.Sprintf("Benchmark%s%s \t 1000000\t %.2f ns/op\t%s %d B/op\t %d allocs/op\n", name, d.suffix, r.ns, extra, r.bytes, r.allocs)
}

// write writes the data in the layout of runtime-bench.sh, runs
// runtime-bench.py, and returns the verdict and the report.
func (d *benchData) write(t *testing.T, optional string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	files := map[string]*strings.Builder{}
	file := func(name string) *strings.Builder {
		if files[name] == nil {
			files[name] = &strings.Builder{}
		}
		return files[name]
	}
	for _, k := range d.placements {
		for run := range d.runs {
			for name, byPlacement := range d.hook {
				if r, ok := byPlacement[k]; ok && (run < d.runs-1 || d.short[name] != k) {
					file("runtime/h" + k + ".txt").WriteString(d.line(name, r, ""))
				}
			}
			for name, byPlacement := range d.nohook {
				if r, ok := byPlacement[k]; ok {
					file("runtime/n" + k + ".txt").WriteString(d.line(name, r, ""))
				}
			}
		}
		if d.allocs {
			file("runtime/allocs.txt").WriteString("PASS\n")
		}
	}
	for range d.storeRuns {
		for name, r := range d.store {
			file("store/lookup-new.txt").WriteString(d.line(name, r, " 50 filter-hit%\t"))
		}
		for name, v := range d.admissionOld {
			file("store/admission-old.txt").WriteString(d.line(name, benchResult{}, fmt.Sprintf(" %.2f admitted%%\t", v)))
		}
		for name, v := range d.admissionNew {
			file("store/admission-new.txt").WriteString(d.line(name, benchResult{}, fmt.Sprintf(" %.2f admitted%%\t", v)))
		}
	}
	for range d.httpRuns {
		file("http/control.txt").WriteString("BenchmarkHTTPRoundTrip \t 1000\t 50000 ns/op\n")
		file("http/iast.txt").WriteString("BenchmarkHTTPRoundTrip \t 1000\t 51000 ns/op\n")
	}
	for name, content := range files {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("runtime-bench.py")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", script, directory)
	command.Env = append(os.Environ(), "RUNTIME_BENCH_OPTIONAL="+optional)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("runtime-bench.py: %v\n%s", err, output)
	}
	verdict, err := os.ReadFile(filepath.Join(directory, "verdict"))
	if err != nil {
		t.Fatal(err)
	}
	return string(verdict), string(output)
}

func requireVerdict(t *testing.T, d *benchData, optional, want string, contains ...string) string {
	t.Helper()
	verdict, report := d.write(t, optional)
	if verdict != want {
		t.Fatalf("verdict %q; want %q\n%s", verdict, want, report)
	}
	for _, s := range contains {
		if !strings.Contains(report, s) {
			t.Fatalf("the report has no %q\n%s", s, report)
		}
	}
	return report
}

func TestRuntimeBenchReportPassesWithAllData(t *testing.T) {
	requireVerdict(t, newBenchData(), "", "PASS",
		// The pooled median and the worst placement of 8.
		"| RuntimeOff/concat2-heap | **+0.70**", "| +1.40 (13) |",
		"**Verdict: PASS**")
}

func TestRuntimeBenchReportParsesNamesWithoutSuffix(t *testing.T) {
	d := newBenchData()
	d.suffix = ""
	requireVerdict(t, d, "", "PASS", "| RuntimeOff/concat2-heap | **+0.70**")
}

func TestRuntimeBenchReportGateOffBoundary(t *testing.T) {
	d := newBenchData()
	// Pooled +2.00 ns (the limit) passes; +2.01 ns fails.
	for k, r := range d.hook["RuntimeOff/concat2-heap"] {
		r.ns = 22
		d.hook["RuntimeOff/concat2-heap"][k] = r
	}
	requireVerdict(t, d, "", "PASS", "| RuntimeOff/concat2-heap | **+2.00**")
	for k, r := range d.hook["RuntimeOff/concat2-heap"] {
		r.ns = 22.01
		d.hook["RuntimeOff/concat2-heap"][k] = r
	}
	requireVerdict(t, d, "", "FAIL", "**Verdict: FAIL** (off)")
}

// TestRuntimeBenchReportFilterHitGates checks the "hit" and "full2" gates: the
// woven clean filter hit (hook - nohook, pooled) plus the extra cost of the
// pre-check at the worst load (store benchmark, worst load - sparse).
func TestRuntimeBenchReportFilterHitGates(t *testing.T) {
	// hit: +30.70 ns pooled + (30 - 30) = 30.70 ns; full2: +50.70 + (70 - 50).
	requireVerdict(t, newBenchData(), "", "PASS", "= 30.70 ns", "= 70.70 ns")
	d := newBenchData()
	d.store["RuntimePre/full/one-clean-hit"] = benchResult{50, 0, 0}
	requireVerdict(t, d, "", "FAIL", "(hit)", "= 50.70 ns")
	d = newBenchData()
	d.store["RuntimePre/full/concat2-clean-random"] = benchResult{100, 0, 0}
	requireVerdict(t, d, "", "FAIL", "(full2)", "= 100.70 ns")
	d = newBenchData()
	for k, r := range d.hook["RuntimeCleanHit/s2b-stack"] {
		r.allocs = 1
		d.hook["RuntimeCleanHit/s2b-stack"][k] = r
	}
	requireVerdict(t, d, "", "FAIL", "(hit")
	d = newBenchData()
	delete(d.store, "RuntimePre/sparse/concat2-clean-hit")
	requireVerdict(t, d, "", "INCOMPLETE", "NOT MEASURED")
}

func TestRuntimeBenchReportFailsExtraAllocationWithGateOff(t *testing.T) {
	d := newBenchData()
	for k, r := range d.hook["RuntimeOff/s2b-stack"] {
		r.allocs++
		d.hook["RuntimeOff/s2b-stack"][k] = r
	}
	requireVerdict(t, d, "", "FAIL", "**Verdict: FAIL** (off)")
}

func TestRuntimeBenchReportFailsTaintedAllocation(t *testing.T) {
	// The tainted concat result is 12 B: its size class is 16 B, not 32 B.
	d := newBenchData()
	for k, r := range d.hook["RuntimeTainted/concat2-stack"] {
		r.bytes = 32
		d.hook["RuntimeTainted/concat2-stack"][k] = r
	}
	requireVerdict(t, d, "", "FAIL", "(tainted)")
	// No allocation in the tainted stack case: the hook did not adopt.
	d = newBenchData()
	for k, r := range d.hook["RuntimeTainted/s2r-stack"] {
		r.allocs, r.bytes = 0, 0
		d.hook["RuntimeTainted/s2r-stack"][k] = r
	}
	requireVerdict(t, d, "", "FAIL", "(tainted-rune)")
}

func TestRuntimeBenchReportIsIncompleteWithMissingData(t *testing.T) {
	for name, change := range map[string]func(*benchData){
		"7 placements": func(d *benchData) { d.placements = d.placements[:7] },
		"missing case": func(d *benchData) { delete(d.hook, "RuntimeOff/r2s-heap") },
		"unpaired runs": func(d *benchData) {
			d.nohook["RuntimeOff/b2s-heap"] = map[string]benchResult{"00": {20, 48, 1}}
		},
		"no store":     func(d *benchData) { d.store = map[string]benchResult{} },
		"no old store": func(d *benchData) { d.admissionOld = map[string]float64{} },
		"disjoint admission": func(d *benchData) {
			d.admissionOld = map[string]float64{"SourceAdmission/other/sparse/TaintString": 100}
		},
		"no HTTP":         func(d *benchData) { d.httpRuns = 0 },
		"9 HTTP runs":     func(d *benchData) { d.httpRuns = 9 },
		"7 store runs":    func(d *benchData) { d.storeRuns = 7 },
		"7 runtime runs":  func(d *benchData) { d.runs = 7 },
		"a missing round": func(d *benchData) { d.short = map[string]string{"RuntimeClean/b2s-stack": "07"} },
		"no allocs":       func(d *benchData) { d.allocs = false },
	} {
		t.Run(name, func(t *testing.T) {
			d := newBenchData()
			change(d)
			requireVerdict(t, d, "", "INCOMPLETE", "NOT MEASURED")
			requireVerdict(t, d, "all", "PASS", "optional, not measured")
		})
	}
}

func TestRuntimeBenchReportOptionalGate(t *testing.T) {
	d := newBenchData()
	d.admissionOld = map[string]float64{}
	requireVerdict(t, d, "admission", "PASS", "Optional gates that are not measured: admission.")
	requireVerdict(t, d, "http", "INCOMPLETE", "(not measured: admission)")
}

func TestRuntimeBenchReportFailsAdmissionLoss(t *testing.T) {
	d := newBenchData()
	d.admissionNew["SourceAdmission/dense256/stressed/TaintBytes"] = 97.5
	requireVerdict(t, d, "", "FAIL", "(admission)")
	// Saturated rows are reported, not gated.
	d = newBenchData()
	d.admissionNew["SourceAdmission/collide/saturated/AdoptSourceBytes"] = 10
	requireVerdict(t, d, "", "PASS")
}

// runRuntimeBench runs runtime-bench.sh in the repository root, and returns
// its output and exit code.
func runRuntimeBench(t *testing.T, out string, args ...string) (string, int) {
	t.Helper()
	script, err := filepath.Abs("runtime-bench.sh")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", append([]string{script}, args...)...)
	command.Dir = ".."
	command.Env = append(os.Environ(), "RUNTIME_BENCH_OUT="+out)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return string(output), command.ProcessState.ExitCode()
}

func TestRuntimeBenchRejectsBadArguments(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	// An output directory in the repository. The test makes it, so that the
	// script can remove it.
	inside, err := os.MkdirTemp(root, "runtime-bench-out-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(inside) })
	// An output directory where src is a symbolic link.
	linked := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, "src")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		out  string
		args []string
		want string
	}{
		{t.TempDir(), []string{"unknown"}, "unknown command"},
		{t.TempDir(), []string{"build", "1", "1"}, "duplicate"},
		{t.TempDir(), []string{"build", "x"}, "not a number"},
		{t.TempDir(), []string{"prepare", "1", "other", "name"}, "usage"},
		{t.TempDir(), []string{"prepare", "1", "hook", "../name"}, "usage"},
		{t.TempDir(), []string{"build", "32"}, "not a number"},
		{t.TempDir(), []string{"build", "123456789012345678901234567890"}, "not a number"},
		{t.TempDir(), []string{"prepare", "32", "hook", "name"}, "usage"},
		{t.TempDir(), []string{"prepare", "123456789012345678901234567890", "hook", "name"}, "usage"},
		{"/", []string{"plain"}, "must not be /"},
		{linked, []string{"plain"}, "must not be a symbolic link"},
		{inside, []string{"plain"}, "outside the repository"},
	} {
		output, code := runRuntimeBench(t, c.out, c.args...)
		if code != 2 || !strings.Contains(output, c.want) {
			t.Fatalf("%v: exit code %d, output %q; want exit code 2 and %q", c.args, code, output, c.want)
		}
	}
	if _, err := os.Stat(inside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused empty output directory stays in the repository: %v", err)
	}
}

// TestRuntimeBenchSourceTransforms checks the nohook and padding transforms
// on the real iast/runtime/orchestrion.yml.
func TestRuntimeBenchSourceTransforms(t *testing.T) {
	original, err := os.ReadFile("../iast/runtime/orchestrion.yml")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	read := func(k, variant string) string {
		t.Helper()
		dir := filepath.Join(out, variant+k)
		if output, code := runRuntimeBench(t, out, "prepare", k, variant, variant+k); code != 0 {
			t.Fatalf("prepare %s %s: exit code %d\n%s", k, variant, code, output)
		}
		content, err := os.ReadFile(filepath.Join(dir, "iast/runtime/orchestrion.yml"))
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	if read("0", "hook") != string(original) {
		t.Fatal("placement 0 of the hook variant is not the repository file")
	}
	hookIDs := []string{
		"iast-concatstrings", "iast-concatbytes", "iast-slicebytetostring",
		"iast-stringtoslicebyte", "iast-slicerunetostring", "iast-stringtoslicerune",
	}
	nohook := read("0", "nohook")
	for _, id := range hookIDs {
		if !strings.Contains(string(original), "  - id: "+id+"\n") || strings.Contains(nohook, id) {
			t.Fatalf("aspect %s: in the original file, not in nohook", id)
		}
	}
	if strings.Contains(nohook, "prepend-statements") || !strings.HasPrefix(string(original), nohook) ||
		!strings.Contains(nohook, "  - id: iast-runtime-decls\n") || !strings.Contains(nohook, "func __dd_iast_ok() bool {") {
		t.Fatal("nohook is not the original file up to the first hook aspect")
	}
	padded := read("3", "hook")
	if strings.Count(padded, "__dd_iast_padv[") != 3 || !strings.Contains(padded, "__dd_iast_padv[2] = 3\n") ||
		!strings.Contains(padded, "func init() { __dd_iast_pad() }\n\n            //go:nosplit\n            func __dd_iast_ok() bool {") {
		t.Fatalf("placement 3 does not add 3 stores before __dd_iast_ok:\n%s", padded)
	}
	if strings.ReplaceAll(padded, padBlock(3), "") != string(original) {
		t.Fatal("placement 3 changes more than the padding function")
	}
	// A leading zero is a decimal number, not an octal number.
	if strings.Count(read("08", "hook"), "__dd_iast_padv[") != 8 {
		t.Fatal("placement 08 does not have 8 stores")
	}
	if strings.Count(read("13", "nohook"), "__dd_iast_padv[") != 13 {
		t.Fatal("placement 13 of nohook does not have 13 stores")
	}
}

// padBlock is the padding function of placement k.
func padBlock(k int) string {
	var b strings.Builder
	b.WriteString("            var __dd_iast_padv [32]uint32\n\n            //go:noinline\n            func __dd_iast_pad() {\n")
	for i := range k {
		fmt.Fprintf(&b, "              __dd_iast_padv[%d] = %d\n", i, i+1)
	}
	b.WriteString("            }\n\n            func init() { __dd_iast_pad() }\n\n")
	return b.String()
}
