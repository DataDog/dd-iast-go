// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

// gateRule is one regression gate "G-C" of the HeapBits workloads (plan
// _docs/plans/allocator-taint-bits.md, section 7.2): for the benchmarks that
// start with prefix, the time of cmp must not be more than maxIncrease
// percent above the time of base, when benchstat finds the difference
// significant.
type gateRule struct {
	name        string
	base, cmp   string
	prefix      string
	unit        string // the benchstat table (default: sec/op; benchstat shows a "-ns" metric as "-sec")
	maxIncrease float64
}

var gateRules = []gateRule{
	// The woven, inert runtime hooks must cost nothing measurable.
	{name: "G-C inert (iast) against control", base: controlResultsFile, cmp: iastResultsFile, prefix: "HeapBits", maxIncrease: 2},
	// The GC with 1 object in 4 tainted.
	{name: "G-C active against inert, GC", base: iastResultsFile, cmp: activeResultsFile, prefix: "HeapBitsGC", maxIncrease: 10},
	// The wait to stop the world (99th percentile) during the GC.
	{name: "G-C active against inert, GC STW p99", base: iastResultsFile, cmp: activeResultsFile, prefix: "HeapBitsGC", unit: "stw-p99-sec", maxIncrease: 10},
}

// gateResult is the result of one rule for one benchmark.
type gateResult struct {
	rule      string
	benchmark string
	delta     string // benchstat "vs base": "~" or a signed percentage
	increase  float64
	pass      bool
	skipped   bool // no selected benchmark for the rule
	info      bool // record only: no threshold
	na        bool // the rule does not apply to this run (for example another sampling)

	// id and stats are set for the paired rules G-A1 to G-A5 (gate.tsv).
	id       string
	stats    pairedDelta
	hasStats bool
}

// checkGates evaluates the gate rules, writes gate.txt, and returns an error
// if a rule fails and cfg.gate is set. Without -gate the report is only
// informative (shared CI runners are too noisy for hard thresholds). With
// -gate, a rule without a selected benchmark (see -bench) also fails.
func checkGates(cfg configuration) error {
	var results []gateResult
	paired, err := checkPairedGates(cfg)
	if err != nil {
		return err
	}
	results = append(results, paired...)
	for _, rule := range gateRules {
		if !resultsExist(cfg, rule.base, rule.cmp) {
			results = append(results, gateResult{rule: rule.name, benchmark: rule.prefix + "*", delta: "no results file", pass: true, na: true})
			continue
		}
		var out bytes.Buffer
		err := executeWithWriters(cfg.module, nil, &out, io.Discard,
			"go", "tool", "benchstat", "-format", "csv",
			filepath.Join(cfg.output.Name(), rule.base),
			filepath.Join(cfg.output.Name(), rule.cmp))
		if err != nil {
			return fmt.Errorf("benchstat for gate %q: %w", rule.name, err)
		}
		r, err := evaluateGate(rule, out.Bytes())
		if err != nil {
			return fmt.Errorf("gate %q: %w", rule.name, err)
		}
		results = append(results, r...)
	}
	report, failed := formatGateReport(results, cfg.gate)
	fmt.Print(report)
	if err := cfg.output.WriteFile(gateFile, []byte(report), 0o644); err != nil {
		return fmt.Errorf("write gate report: %w", err)
	}
	if err := cfg.output.WriteFile(gateTableFile, []byte(formatGateTable(results, cfg.gate)), 0o644); err != nil {
		return fmt.Errorf("write gate table: %w", err)
	}
	if failed && cfg.gate {
		return errors.New("a regression gate failed (see gate.txt)")
	}
	return nil
}

// resultsExist reports whether all the named results files have data.
func resultsExist(cfg configuration, names ...string) bool {
	for _, name := range names {
		info, err := cfg.output.Stat(name)
		if err != nil || info.Size() == 0 {
			return false
		}
	}
	return true
}

// evaluateGate reads the CSV output of benchstat for two files and applies
// the rule to the table of its unit.
func evaluateGate(rule gateRule, csvOutput []byte) ([]gateResult, error) {
	want := rule.unit
	if want == "" {
		want = "sec/op"
	}
	reader := csv.NewReader(bytes.NewReader(csvOutput))
	reader.FieldsPerRecord = -1
	var results []gateResult
	unit := ""
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) >= 7 && record[0] == "" && record[5] == "vs base" {
			unit = record[1]
			continue
		}
		if unit != want || len(record) < 7 || !strings.HasPrefix(record[0], rule.prefix) {
			continue
		}
		delta := record[5]
		result := gateResult{rule: rule.name, benchmark: record[0], delta: delta, pass: true}
		if delta != "~" {
			value, err := strconv.ParseFloat(strings.TrimSuffix(delta, "%"), 64)
			if err != nil {
				return nil, fmt.Errorf("parse delta %q of %s: %w", delta, record[0], err)
			}
			result.increase = value
			result.pass = value <= rule.maxIncrease
		}
		results = append(results, result)
	}
	if len(results) == 0 {
		// The -bench expression did not select these benchmarks.
		return []gateResult{{rule: rule.name, benchmark: rule.prefix + "*", delta: "not run", pass: true, skipped: true}}, nil
	}
	return results, nil
}

// gateStatus is the status of a result in the report: PASS, FAIL, SKIP, INFO
// or N/A. An enforced gate also fails for SKIP.
func gateStatus(r gateResult) string {
	switch {
	case r.na:
		return "N/A"
	case r.info:
		return "INFO"
	case r.skipped:
		return "SKIP"
	case !r.pass:
		return "FAIL"
	}
	return "PASS"
}

func formatGateReport(results []gateResult, enforced bool) (string, bool) {
	var b strings.Builder
	mode := "informative (run with -gate on a stable machine to enforce)"
	if enforced {
		mode = "enforced"
	}
	fmt.Fprintf(&b, "Regression gates (G-A1 to G-A5 of plan heapbits-sqli-cmdi 10.1, G-C of the HeapBits workloads), %s:\n", mode)
	failed := false
	for _, r := range results {
		status := gateStatus(r)
		// An enforced gate must check something.
		failed = failed || status == "FAIL" || (status == "SKIP" && enforced)
		fmt.Fprintf(&b, "%-4s  %-44s %-46s %s\n", status, r.rule, r.benchmark, r.delta)
	}
	return b.String(), failed
}

// formatGateTable is the machine-readable form of the paired gates (G-A1 to
// G-A5): one tab-separated line for each benchmark, with a header line. The
// percentages and the interval are relative to the median ns/op of the base.
func formatGateTable(results []gateResult, enforced bool) string {
	var b strings.Builder
	b.WriteString("status\tgate\tbenchmark\tn\tbase_ns\testimate_ns\testimate_pct\tlo_pct\thi_pct\tupper_pct\tallocs_base\tallocs_cmp\n")
	for _, r := range results {
		if !r.hasStats {
			continue
		}
		d := r.stats
		pct := func(ns float64) float64 { return 100 * ns / d.base }
		fmt.Fprintf(&b, "%s\t%s\t%s\t%d\t%.4f\t%.4f\t%.3f\t%.3f\t%.3f\t%.3f\t%g\t%g\n",
			gateStatus(r), r.id, r.benchmark, d.n, d.base, d.estimate, pct(d.estimate), pct(d.lo), pct(d.hi), pct(d.upper), d.allocsBase, d.allocs)
	}
	return b.String()
}
