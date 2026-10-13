// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"bufio"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The gates G-A1 to G-A5 of plan _docs/plans/heapbits-sqli-cmdi.md, section
// 10.1, compare the control variant with the IAST variant, with the limits of
// the gates of PR #39 (its plans phase-5.md:113 and phase-6.md:344-348, and
// its runtime-bench.py profiles). The samples of the 2 variants are paired by
// position: sample k of each file comes from the k-th round of the runner,
// which runs the variants in turns. The point estimate is the difference of
// the medians. The upper bound is the 95 % one-sided paired-bootstrap bound of
// the same difference (the pairs are resampled together).
//
// Process classes. The taint gate of the heapbits tree is sticky: after the
// first taint in a process, the hooks do more work until the process stops.
// G-A3 and G-A5 ("no request") are thus valid only in a process that ran no
// workload that can taint data or open a request: the "gate-off" pass,
// -bench=gateOffBench. G-A4 also accepts PropagationActiveUntainted (a request
// with no taint): the "active" pass. With DD_IAST_BENCH_TAINT_LIVE=1 (the
// "taint live elsewhere" pass, sampling 100 only), the same workloads are
// recorded as G-A3L, G-A4L and G-A5L: they show the verdict of the limit, but
// they do not fail the run. The other workloads are recorded as REC.

const (
	// bootstrapResamples is the number of resamples of the paired bootstrap.
	bootstrapResamples = 2000
	// smallBenchmarkNs separates the absolute limit from the relative limit.
	smallBenchmarkNs = 80.0
	// smallLimitNs is the limit (ns) for a benchmark under smallBenchmarkNs.
	smallLimitNs = 4.0
	// largeLimitPercent is the limit (%) for the other benchmarks.
	largeLimitPercent = 5.0

	// gateProfileEnvironment selects the limit of G-A1 (see pairedRule.http).
	gateProfileEnvironment = "DD_IAST_BENCH_GATE_PROFILE"

	// gateOffBench is the -bench expression of the gate-off pass: the
	// workloads of G-A3 and G-A5 only. (go test matches -bench with the
	// name of the function, "Benchmark" included.)
	gateOffBench = `^Benchmark(Strings|Fmt|URL|Strconv|ConcatChain)|^BenchmarkBytes(Buffer|Clone|Join|Map|Repeat|ReplaceAll|Split|ToLower|TrimSpace)$`
	// activeBench is the -bench expression of the G-A4 pass.
	activeBench = `^BenchmarkPropagationActiveUntainted$`
)

// httpLimits are the limits (%) of G-A1 for each profile: "local" (the
// default) and "ci" (GitHub runners); see .github/runtime-bench.py.
var httpLimits = map[string]float64{"local": 3.70, "ci": 6.0}

var (
	noRequestWorkloads = regexp.MustCompile(`^(Strings|Bytes|Fmt|URL|Strconv)`)
	// bufferCopyWorkloads taint data in a sampled request: record only.
	bufferCopyWorkloads      = regexp.MustCompile(`^BytesBufferCopies(/|$)`)
	concatChainWorkloads     = regexp.MustCompile(`^ConcatChain`)
	activeUntaintedWorkloads = regexp.MustCompile(`^PropagationActiveUntainted/`)
	httpWorkloads            = regexp.MustCompile(`^HTTPRoundTrip$`)
)

// gateA3Workload selects the workloads of G-A3.
func gateA3Workload(name string) bool {
	return noRequestWorkloads.MatchString(name) && !bufferCopyWorkloads.MatchString(name)
}

// gateOffWorkload reports whether the workload never taints data and never
// opens a request.
func gateOffWorkload(name string) bool {
	return gateA3Workload(name) || concatChainWorkloads.MatchString(name)
}

// untaintedWorkload reports whether the workload never taints data.
func untaintedWorkload(name string) bool {
	return gateOffWorkload(name) || activeUntaintedWorkloads.MatchString(name)
}

type limitKind int

const (
	limitNone     limitKind = iota // record only
	limitSmall                     // < 80 ns: +4 ns; otherwise +5 %
	limitHTTP                      // percentage of the profile; the estimate alone is gated
	limitAllocsOn                  // allocation count only
)

// liveMode tells whether a rule applies with "taint live elsewhere".
type liveMode int

const (
	anyLive liveMode = iota
	notLive
	onlyLive
)

// pairedRule is one gate G-A (or a record-only row).
type pairedRule struct {
	id        string
	name      string
	label     string // the workloads, for the rows with no benchmark
	base, cmp string
	selects   func(name string) bool // on the name without "Benchmark" and the "-N" suffix
	samplings []int                  // the samplings where the rule applies (nil: all)
	live      liveMode
	// process, when set, must accept every workload of the process (see the
	// process classes above); processBench is the -bench of that pass.
	process      func(name string) bool
	processBench string
	kind         limitKind
	allocs       bool // the IAST variant must not allocate more
	record       bool // show the verdict, but never fail (status INFO)
	rest         bool // select the workloads that no earlier rule selected
}

func matcher(re *regexp.Regexp) func(string) bool { return re.MatchString }

var pairedRules = []pairedRule{
	{
		id: "G-A1", name: "G-A1 HTTP sampled out, control vs iast", label: "HTTPRoundTrip",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: matcher(httpWorkloads), samplings: []int{0}, live: notLive, kind: limitHTTP,
	},
	{
		id: "G-A2", name: "G-A2 HTTP sampled, control vs iast", label: "HTTPRoundTrip",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: matcher(httpWorkloads), samplings: []int{100}, live: notLive, kind: limitNone,
	},
	{
		id: "G-A3", name: "G-A3 disabled or no request, control vs iast", label: "Strings*|Bytes*|Fmt*|URL*|Strconv*",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: gateA3Workload, live: notLive, process: gateOffWorkload, processBench: gateOffBench,
		kind: limitSmall, allocs: true,
	},
	{
		id: "G-A4", name: "G-A4 active, untainted, control vs iast", label: "PropagationActiveUntainted/*",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: matcher(activeUntaintedWorkloads), samplings: []int{100}, live: notLive,
		process: untaintedWorkload, processBench: activeBench, kind: limitSmall, allocs: true,
	},
	{
		id: "G-A5", name: "G-A5 concat chain, control vs iast", label: "ConcatChain*",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: matcher(concatChainWorkloads), live: notLive, process: gateOffWorkload, processBench: gateOffBench,
		kind: limitAllocsOn, allocs: true,
	},
	{
		id: "G-A3L", name: "G-A3L taint live, record, control vs iast", label: "Strings*|Bytes*|Fmt*|URL*|Strconv*",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: gateA3Workload, live: onlyLive, process: untaintedWorkload, processBench: gateOffBench + "|" + activeBench,
		kind: limitSmall, allocs: true, record: true,
	},
	{
		id: "G-A4L", name: "G-A4L taint live, record, control vs iast", label: "PropagationActiveUntainted/*",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: matcher(activeUntaintedWorkloads), samplings: []int{100}, live: onlyLive,
		process: untaintedWorkload, processBench: gateOffBench + "|" + activeBench, kind: limitSmall, allocs: true, record: true,
	},
	{
		id: "G-A5L", name: "G-A5L taint live, record, control vs iast", label: "ConcatChain*",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: matcher(concatChainWorkloads), live: onlyLive, process: untaintedWorkload, processBench: gateOffBench + "|" + activeBench,
		kind: limitAllocsOn, allocs: true, record: true,
	},
	{
		// The other workloads (for example BytesBufferCopies, the sinks, and
		// the G-A3 workloads of a process that can taint), for the table.
		id: "REC", name: "REC record only, control vs iast", label: "other workloads",
		base: controlResultsFile, cmp: iastResultsFile,
		selects: func(string) bool { return true }, kind: limitNone, rest: true,
	},
}

// benchSample is one line of a results file.
type benchSample struct {
	ns, allocs, bytes   float64
	hasAllocs, hasBytes bool
}

// readSamples reads a results file: for each benchmark name (without the
// "Benchmark" prefix and the "-N" suffix), its samples in file order.
func readSamples(path string) (map[string][]benchSample, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	samples := map[string][]benchSample{}
	var order []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		name, sample, ok := parseSample(scanner.Text())
		if !ok {
			continue
		}
		if _, seen := samples[name]; !seen {
			order = append(order, name)
		}
		samples[name] = append(samples[name], sample)
	}
	return samples, order, scanner.Err()
}

var benchmarkSuffix = regexp.MustCompile(`-\d+$`)

// parseSample parses a line "BenchmarkName-1  N  V ns/op  ...  A allocs/op".
func parseSample(line string) (string, benchSample, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.HasPrefix(fields[0], "Benchmark") {
		return "", benchSample{}, false
	}
	if _, err := strconv.ParseInt(fields[1], 10, 64); err != nil {
		return "", benchSample{}, false
	}
	var sample benchSample
	found := false
	for i := 2; i+1 < len(fields); i += 2 {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return "", benchSample{}, false
		}
		switch fields[i+1] {
		case "ns/op":
			sample.ns, found = value, true
		case "allocs/op":
			sample.allocs, sample.hasAllocs = value, true
		case "B/op":
			sample.bytes, sample.hasBytes = value, true
		}
	}
	if !found {
		return "", benchSample{}, false
	}
	name := benchmarkSuffix.ReplaceAllString(strings.TrimPrefix(fields[0], "Benchmark"), "")
	return name, sample, true
}

func median(values []float64) float64 {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	n := len(sorted)
	if n == 0 {
		return math.NaN()
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func column(samples []benchSample, pick func(benchSample) float64) []float64 {
	values := make([]float64, len(samples))
	for i, s := range samples {
		values[i] = pick(s)
	}
	return values
}

func nsOf(s benchSample) float64     { return s.ns }
func allocsOf(s benchSample) float64 { return s.allocs }
func bytesOf(s benchSample) float64  { return s.bytes }

// pairedDelta is the result of the paired comparison of one benchmark.
type pairedDelta struct {
	n                  int
	base               float64 // median ns/op of the base
	estimate, upper    float64 // ns/op
	lo, hi             float64 // ns/op: two-sided 95 % interval
	allocsBase, allocs float64 // median allocs/op
	hasAllocs          bool
	bytesBase, bytes   float64 // median B/op
	hasBytes           bool
}

// comparePaired computes the delta of cmp against base. The 2 series must
// have the same length (sample k of each is pair k); see checkPairedGates.
func comparePaired(base, cmp []benchSample) pairedDelta {
	n := len(base)
	d := pairedDelta{n: n}
	if n == 0 || len(cmp) != n {
		return d
	}
	baseNs, cmpNs := column(base, nsOf), column(cmp, nsOf)
	d.base = median(baseNs)
	d.estimate = median(cmpNs) - d.base
	d.lo, d.hi, d.upper = bootstrapInterval(baseNs, cmpNs)
	d.hasAllocs = all(base, cmp, func(s benchSample) bool { return s.hasAllocs })
	if d.hasAllocs {
		d.allocsBase = median(column(base, allocsOf))
		d.allocs = median(column(cmp, allocsOf))
	}
	d.hasBytes = all(base, cmp, func(s benchSample) bool { return s.hasBytes })
	if d.hasBytes {
		d.bytesBase = median(column(base, bytesOf))
		d.bytes = median(column(cmp, bytesOf))
	}
	return d
}

func all(base, cmp []benchSample, ok func(benchSample) bool) bool {
	return !slices.ContainsFunc(base, func(s benchSample) bool { return !ok(s) }) &&
		!slices.ContainsFunc(cmp, func(s benchSample) bool { return !ok(s) })
}

// bootstrapInterval returns the two-sided 95 % interval (lo, hi) and the 95 %
// one-sided upper bound of median(cmp)-median(base), with the pairs resampled
// together. The generator has a fixed seed: the same files give the same
// numbers.
func bootstrapInterval(base, cmp []float64) (lo, hi, upper float64) {
	n := len(base)
	random := rand.New(rand.NewPCG(1, 2))
	differences := make([]float64, bootstrapResamples)
	a, b := make([]float64, n), make([]float64, n)
	for r := range differences {
		for i := range n {
			k := random.IntN(n)
			a[i], b[i] = base[k], cmp[k]
		}
		differences[r] = median(b) - median(a)
	}
	slices.Sort(differences)
	at := func(q float64) float64 { return differences[int(math.Ceil(q*float64(bootstrapResamples)))-1] }
	return at(0.025), at(0.975), at(0.95)
}

// Verdicts of the limits, in gate.tsv.
const (
	verdictPass = "PASS"
	verdictFail = "FAIL"
	verdictNone = "-"
)

func verdict(pass bool) string {
	if pass {
		return verdictPass
	}
	return verdictFail
}

// evaluatePaired applies the rule to one benchmark. want is the number of
// pairs that the run must have; with enforced, fewer than minGateCount pairs
// fail (INCOMPLETE).
func evaluatePaired(rule pairedRule, name string, d pairedDelta, profile string, want int, enforced bool) gateResult {
	percent := func(ns float64) float64 { return 100 * ns / d.base }
	text := fmt.Sprintf("%+.2f ns (%+.2f %%), upper %+.2f ns (%+.2f %%), base %.2f ns, allocs %+g, n=%d",
		d.estimate, percent(d.estimate), d.upper, percent(d.upper), d.base, d.allocs-d.allocsBase, d.n)
	result := gateResult{
		rule: rule.name, benchmark: name, delta: text, pass: true, id: rule.id, stats: d, hasStats: true,
		timeVerdict: verdictNone, allocsVerdict: verdictNone,
	}
	switch rule.kind {
	case limitNone:
		result.info = true
	case limitSmall:
		var pass bool
		if d.base < smallBenchmarkNs {
			pass = d.estimate <= smallLimitNs && d.upper <= smallLimitNs
			result.delta += fmt.Sprintf(" [limit +%g ns]", smallLimitNs)
		} else {
			pass = percent(d.estimate) <= largeLimitPercent && percent(d.upper) <= largeLimitPercent
			result.delta += fmt.Sprintf(" [limit +%g %%]", largeLimitPercent)
		}
		result.timeVerdict = verdict(pass)
	case limitHTTP:
		limit := httpLimits[profile]
		result.timeVerdict = verdict(percent(d.estimate) <= limit)
		result.delta += fmt.Sprintf(" [limit +%.2f %%, profile %s]", limit, profile)
	case limitAllocsOn:
		// Only the allocation count is gated (below).
	}
	if rule.allocs {
		switch {
		case !d.hasAllocs:
			result.allocsVerdict = verdictFail
			result.delta += " [no allocs/op: run with -benchmem]"
		case d.allocs > d.allocsBase:
			result.allocsVerdict = verdictFail
			result.delta += " [allocs increased]"
		default:
			result.allocsVerdict = verdictPass
		}
	}
	result.pass = result.timeVerdict != verdictFail && result.allocsVerdict != verdictFail
	if rule.record {
		if rule.kind != limitNone {
			result.delta += " [record: limit verdict " + verdict(result.pass) + "]"
		}
		result.info, result.pass = true, true
	}
	switch {
	case d.n != want:
		result.info, result.pass = false, false
		result.delta += fmt.Sprintf(" [INCOMPLETE: %d pairs, want %d]", d.n, want)
	case d.n < minGateCount && enforced:
		result.info, result.pass = false, false
		result.delta += fmt.Sprintf(" [INCOMPLETE: %d pairs, an enforced gate needs %d or more]", d.n, minGateCount)
	case d.n < minGateCount:
		result.delta += fmt.Sprintf(" (too few pairs for a verdict: %d < %d)", d.n, minGateCount)
	}
	return result
}

// notApplicable returns the reason why the rule does not apply to the run,
// or "".
func notApplicable(rule pairedRule, cfg configuration, names []string) string {
	if rule.samplings != nil && !slices.Contains(rule.samplings, cfg.sampling) {
		return fmt.Sprintf("not applicable at sampling %d", cfg.sampling)
	}
	live := cfg.taintLive == taintLiveOn
	switch {
	case rule.live == notLive && live:
		return "not applicable with " + taintLiveEnvironment + "=1"
	case rule.live == onlyLive && !live:
		return "applies only with " + taintLiveEnvironment + "=1"
	}
	if rule.process != nil {
		for _, name := range names {
			if !rule.process(name) {
				return fmt.Sprintf("not applicable: the process also ran %s (it can taint or open a request); measure in a separate pass with -bench='%s'", name, rule.processBench)
			}
		}
	}
	return ""
}

// checkPairedGates evaluates the gates G-A1 to G-A5 (and the record-only
// rows) on the results of the runner. The results must be complete: see
// validateSampleCounts.
func checkPairedGates(cfg configuration) ([]gateResult, error) {
	profile := os.Getenv(gateProfileEnvironment)
	if profile == "" {
		profile = "local"
	}
	if _, ok := httpLimits[profile]; !ok {
		return nil, fmt.Errorf("%s must be local or ci: %q", gateProfileEnvironment, profile)
	}
	files := map[string]map[string][]benchSample{}
	var names []string // the workloads of the process, in file order
	for _, name := range []string{controlResultsFile, iastResultsFile} {
		samples, order, err := readSamples(filepath.Join(cfg.output.Name(), name))
		if err != nil {
			return nil, fmt.Errorf("paired gates: %w", err)
		}
		files[name] = samples
		for _, benchmark := range order {
			if !slices.Contains(names, benchmark) {
				names = append(names, benchmark)
			}
		}
	}
	evaluated := map[string]bool{}
	var results []gateResult
	for _, rule := range pairedRules {
		if reason := notApplicable(rule, cfg, names); reason != "" {
			results = append(results, gateResult{rule: rule.name, benchmark: rule.label, delta: reason, pass: true, na: true})
			continue
		}
		base, cmp := files[rule.base], files[rule.cmp]
		selected := 0
		for _, name := range names {
			if !rule.selects(name) || (rule.rest && evaluated[name]) {
				continue
			}
			selected++
			evaluated[name] = true
			switch {
			case len(base[name]) == 0 || len(cmp[name]) == 0:
				results = append(results, gateResult{rule: rule.name, benchmark: name, id: rule.id,
					delta: fmt.Sprintf("INCOMPLETE: missing variant (%s: %d samples, %s: %d samples)", rule.base, len(base[name]), rule.cmp, len(cmp[name]))})
			case len(base[name]) != len(cmp[name]):
				results = append(results, gateResult{rule: rule.name, benchmark: name, id: rule.id,
					delta: fmt.Sprintf("INCOMPLETE: unequal sample counts (%s: %d, %s: %d)", rule.base, len(base[name]), rule.cmp, len(cmp[name]))})
			default:
				results = append(results, evaluatePaired(rule, name, comparePaired(base[name], cmp[name]), profile, cfg.count, cfg.gate))
			}
		}
		if selected == 0 && !rule.rest {
			results = append(results, gateResult{rule: rule.name, benchmark: rule.label, delta: "not run", pass: true, skipped: true})
		}
	}
	return results, nil
}

// validateSampleCounts checks that each results file has the same workloads,
// each with exactly count samples (one for each round of the runner): a
// missing or extra sample would shift the pairs.
func validateSampleCounts(cfg configuration, names []string) error {
	var problems []string
	var reference []string
	for i, file := range names {
		samples, order, err := readSamples(filepath.Join(cfg.output.Name(), file))
		if err != nil {
			return err
		}
		sorted := slices.Sorted(slices.Values(order))
		if i == 0 {
			reference = sorted
		} else if !slices.Equal(sorted, reference) {
			problems = append(problems, fmt.Sprintf("%s has the workloads %v, %s has %v", file, sorted, names[0], reference))
		}
		for _, name := range order {
			if got := len(samples[name]); got != cfg.count {
				problems = append(problems, fmt.Sprintf("%s: %s has %d samples, want %d", file, name, got, cfg.count))
			}
		}
	}
	if len(problems) != 0 {
		return fmt.Errorf("incomplete results (missing variant or unequal sample counts):\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}
