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
)

// httpLimits are the limits (%) of G-A1 for each profile: "local" (the
// default) and "ci" (GitHub runners); see .github/runtime-bench.py.
var httpLimits = map[string]float64{"local": 3.70, "ci": 6.0}

type limitKind int

const (
	limitNone     limitKind = iota // record only
	limitSmall                     // < 80 ns: +4 ns; otherwise +5 %
	limitHTTP                      // percentage of the profile; the estimate alone is gated
	limitAllocsOn                  // allocation count only
)

// pairedRule is one gate G-A.
type pairedRule struct {
	id         string
	name       string
	base, cmp  string
	benchmarks *regexp.Regexp // on the name without "Benchmark" and the "-N" suffix
	samplings  []int          // the samplings where the rule applies (nil: all)
	kind       limitKind
	allocs     bool // the IAST variant must not allocate more
}

var pairedRules = []pairedRule{
	{
		id: "G-A1", name: "G-A1 HTTP sampled out, control vs iast",
		base: controlResultsFile, cmp: iastResultsFile,
		benchmarks: regexp.MustCompile(`^HTTPRoundTrip$`), samplings: []int{0}, kind: limitHTTP,
	},
	{
		id: "G-A2", name: "G-A2 HTTP sampled, control vs iast",
		base: controlResultsFile, cmp: iastResultsFile,
		benchmarks: regexp.MustCompile(`^HTTPRoundTrip$`), samplings: []int{100}, kind: limitNone,
	},
	{
		id: "G-A3", name: "G-A3 disabled or no request, control vs iast",
		base: controlResultsFile, cmp: iastResultsFile,
		benchmarks: regexp.MustCompile(`^(Strings|Bytes|Fmt|URL|Strconv)`), kind: limitSmall, allocs: true,
	},
	{
		id: "G-A4", name: "G-A4 active, untainted, control vs iast",
		base: controlResultsFile, cmp: iastResultsFile,
		benchmarks: regexp.MustCompile(`^PropagationActiveUntainted/`), samplings: []int{100}, kind: limitSmall, allocs: true,
	},
	{
		id: "G-A5", name: "G-A5 concat chain, control vs iast",
		base: controlResultsFile, cmp: iastResultsFile,
		benchmarks: regexp.MustCompile(`^ConcatChain`), kind: limitAllocsOn, allocs: true,
	},
}

// benchSample is one line of a results file.
type benchSample struct {
	ns, allocs float64
	hasAllocs  bool
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

// pairedDelta is the result of the paired comparison of one benchmark.
type pairedDelta struct {
	n                  int
	base               float64 // median ns/op of the base
	estimate, upper    float64 // ns/op
	lo, hi             float64 // ns/op: two-sided 95 % interval
	allocsBase, allocs float64 // median allocs/op
	hasAllocs          bool
}

// comparePaired computes the delta of cmp against base for the first
// min(len) pairs.
func comparePaired(base, cmp []benchSample) pairedDelta {
	n := min(len(base), len(cmp))
	base, cmp = base[:n], cmp[:n]
	d := pairedDelta{n: n}
	if n == 0 {
		return d
	}
	baseNs, cmpNs := column(base, nsOf), column(cmp, nsOf)
	d.base = median(baseNs)
	d.estimate = median(cmpNs) - d.base
	d.lo, d.hi, d.upper = bootstrapInterval(baseNs, cmpNs)
	d.hasAllocs = base[0].hasAllocs && cmp[0].hasAllocs
	if d.hasAllocs {
		d.allocsBase = median(column(base, allocsOf))
		d.allocs = median(column(cmp, allocsOf))
	}
	return d
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

// evaluatePaired applies the rule to one benchmark.
func evaluatePaired(rule pairedRule, name string, d pairedDelta, profile string) gateResult {
	percent := func(ns float64) float64 { return 100 * ns / d.base }
	text := fmt.Sprintf("%+.2f ns (%+.2f %%), upper %+.2f ns (%+.2f %%), base %.2f ns, allocs %+g, n=%d",
		d.estimate, percent(d.estimate), d.upper, percent(d.upper), d.base, d.allocs-d.allocsBase, d.n)
	result := gateResult{rule: rule.name, benchmark: name, delta: text, pass: true, id: rule.id, stats: d, hasStats: true}
	if d.n < minGateCount {
		result.delta += " (too few samples)"
	}
	switch rule.kind {
	case limitNone:
		result.info = true
		return result
	case limitSmall:
		if d.base < smallBenchmarkNs {
			result.pass = d.estimate <= smallLimitNs && d.upper <= smallLimitNs
			result.delta += fmt.Sprintf(" [limit +%g ns]", smallLimitNs)
		} else {
			result.pass = percent(d.estimate) <= largeLimitPercent && percent(d.upper) <= largeLimitPercent
			result.delta += fmt.Sprintf(" [limit +%g %%]", largeLimitPercent)
		}
	case limitHTTP:
		limit := httpLimits[profile]
		result.pass = percent(d.estimate) <= limit
		result.delta += fmt.Sprintf(" [limit +%.2f %%, profile %s]", limit, profile)
	case limitAllocsOn:
		// Only the allocation count is gated (below).
	}
	if rule.allocs {
		if !d.hasAllocs {
			result.pass = false
			result.delta += " [no allocs/op: run with -benchmem]"
		} else if d.allocs > d.allocsBase {
			result.pass = false
			result.delta += " [allocs increased]"
		}
	}
	return result
}

// checkPairedGates evaluates the gates G-A1 to G-A5 on the results of the
// runner.
func checkPairedGates(cfg configuration) ([]gateResult, error) {
	profile := os.Getenv(gateProfileEnvironment)
	if profile == "" {
		profile = "local"
	}
	if _, ok := httpLimits[profile]; !ok {
		return nil, fmt.Errorf("%s must be local or ci: %q", gateProfileEnvironment, profile)
	}
	var results []gateResult
	for _, rule := range pairedRules {
		if rule.samplings != nil && !slices.Contains(rule.samplings, cfg.sampling) {
			results = append(results, gateResult{rule: rule.name, benchmark: rule.benchmarks.String(), delta: fmt.Sprintf("not applicable at sampling %d", cfg.sampling), pass: true, na: true})
			continue
		}
		base, _, err := readSamples(filepath.Join(cfg.output.Name(), rule.base))
		if err != nil {
			return nil, fmt.Errorf("gate %s: %w", rule.id, err)
		}
		cmp, order, err := readSamples(filepath.Join(cfg.output.Name(), rule.cmp))
		if err != nil {
			return nil, fmt.Errorf("gate %s: %w", rule.id, err)
		}
		selected := 0
		for _, name := range order {
			if !rule.benchmarks.MatchString(name) || len(base[name]) == 0 {
				continue
			}
			selected++
			if len(cmp[name]) == 0 {
				results = append(results, gateResult{rule: rule.name, benchmark: name, delta: "no sample in " + rule.cmp, pass: false})
				continue
			}
			results = append(results, evaluatePaired(rule, name, comparePaired(base[name], cmp[name]), profile))
		}
		if selected == 0 {
			results = append(results, gateResult{rule: rule.name, benchmark: rule.benchmarks.String(), delta: "not run", pass: true, skipped: true})
		}
	}
	return results, nil
}
