// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command configdump loads internal/config under the current process
// environment and prints the resolved values plus warnings as JSON. It is a
// review harness, not part of the shipped package: it exists to observe
// config.load()'s behavior against extreme/malformed DD_IAST_* environment
// values without crashing, one process per combination.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/config/loader"
)

type dump struct {
	Enabled                   bool     `json:"enabled"`
	RequestSamplingPct        int      `json:"request_sampling_pct"`
	MaxConcurrentRequests     int      `json:"max_concurrent_requests"`
	VulnerabilitiesPerRequest int      `json:"vulnerabilities_per_request"`
	DeduplicationEnabled      bool     `json:"deduplication_enabled"`
	RedactionEnabled          bool     `json:"redaction_enabled"`
	RedactionNamePattern      string   `json:"redaction_name_pattern"`
	RedactionValuePattern     string   `json:"redaction_value_pattern"`
	TruncationMaxValue        uint64   `json:"truncation_max_value"`
	MaxRangeCount             uint64   `json:"max_range_count"`
	TelemetryVerbosity        int      `json:"telemetry_verbosity"`
	DbRowsToTaint             uint64   `json:"db_rows_to_taint"`
	StackTraceEnabled         bool     `json:"stack_trace_enabled"`
	Warnings                  []string `json:"warnings"`
	Defaults                  []string `json:"defaults"`
	Environment               []string `json:"environment"`
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "PANIC: %v\n", r)
			os.Exit(2)
		}
	}()

	d := dump{
		Enabled:                   config.Enabled,
		RequestSamplingPct:        config.RequestSamplingPct,
		MaxConcurrentRequests:     config.MaxConcurrentRequests,
		VulnerabilitiesPerRequest: config.VulnerabilitiesPerRequest,
		DeduplicationEnabled:      config.DeduplicationEnabled,
		RedactionEnabled:          config.RedactionEnabled,
		TruncationMaxValue:        config.TruncationMaxValue,
		MaxRangeCount:             config.MaxRangeCount,
		TelemetryVerbosity:        int(config.TelemetryVerbosity),
		DbRowsToTaint:             config.DbRowsToTaint,
		StackTraceEnabled:         config.StackTraceEnabled,
	}
	if config.RedactionNamePattern != nil {
		d.RedactionNamePattern = config.RedactionNamePattern.String()
	}
	if config.RedactionValuePattern != nil {
		d.RedactionValuePattern = config.RedactionValuePattern.String()
	}

	config.Observe(loader.Observer{
		Warn: func(format string, args ...any) {
			d.Warnings = append(d.Warnings, fmt.Sprintf(format, args...))
		},
		RegisterDefault: func(name string, value any) {
			d.Defaults = append(d.Defaults, fmt.Sprintf("%s=%v", name, value))
		},
		RegisterEnvironment: func(name string, value any) {
			d.Environment = append(d.Environment, fmt.Sprintf("%s=%v", name, value))
		},
	})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
		os.Exit(3)
	}
}
