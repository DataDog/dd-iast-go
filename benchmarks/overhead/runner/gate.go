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

// gateRule is one regression gate of the HeapBits workloads (plan
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
	{name: "inert (iast) against control", base: controlResultsFile, cmp: iastResultsFile, prefix: "HeapBits", maxIncrease: 2},
	// The GC with 1 object in 4 tainted.
	{name: "active against inert, GC", base: iastResultsFile, cmp: activeResultsFile, prefix: "HeapBitsGC", maxIncrease: 10},
	// The wait to stop the world (99th percentile) during the GC.
	{name: "active against inert, GC STW p99", base: iastResultsFile, cmp: activeResultsFile, prefix: "HeapBitsGC", unit: "stw-p99-sec", maxIncrease: 10},
}

// gateResult is the result of one rule for one benchmark.
type gateResult struct {
	rule      string
	benchmark string
	delta     string // benchstat "vs base": "~" or a signed percentage
	increase  float64
	pass      bool
	skipped   bool // no selected benchmark for the rule
}

// checkGates evaluates the gate rules, writes gate.txt, and returns an error
// if a rule fails and cfg.gate is set. Without -gate the report is only
// informative (shared CI runners are too noisy for hard thresholds). With
// -gate, a rule without a selected benchmark (see -bench) also fails.
func checkGates(cfg configuration) error {
	var results []gateResult
	for _, rule := range gateRules {
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
	if failed && cfg.gate {
		return errors.New("a regression gate of the HeapBits workloads failed (see gate.txt)")
	}
	return nil
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

func formatGateReport(results []gateResult, enforced bool) (string, bool) {
	var b strings.Builder
	mode := "informative (run with -gate on a stable machine to enforce)"
	if enforced {
		mode = "enforced"
	}
	fmt.Fprintf(&b, "HeapBits regression gates, %s:\n", mode)
	failed := false
	for _, r := range results {
		status := "PASS"
		switch {
		case r.skipped:
			// An enforced gate must check something.
			status = "SKIP"
			failed = failed || enforced
		case !r.pass:
			status = "FAIL"
			failed = true
		}
		fmt.Fprintf(&b, "%s  %-36s %-26s %s\n", status, r.rule, r.benchmark, r.delta)
	}
	return b.String(), failed
}
