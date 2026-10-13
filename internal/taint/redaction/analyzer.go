// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import "slices"

const (
	// MaxAnalyzerBytes bounds evidence examined by a vulnerability analyzer.
	MaxAnalyzerBytes = 32 << 10
	// MaxSensitiveIntervals bounds analyzer output before evidence segmentation.
	MaxSensitiveIntervals = 256
	maxAnalyzerTokens     = 16_384
	// MaxCommandArguments bounds command evidence traversal.
	MaxCommandArguments = 256
)

// AnalysisStatus classifies bounded vulnerability-specific analysis.
type AnalysisStatus uint8

const (
	// AnalysisOK means Value and Sensitive are complete.
	AnalysisOK AnalysisStatus = iota
	// AnalysisOversized means the input exceeded its byte or argument cap and
	// must be conservatively fully redacted.
	AnalysisOversized
	// AnalysisDropped means malformed or excessive token work prevented a
	// complete classification and must be conservatively fully redacted.
	AnalysisDropped
)

// Interval is one sensitive byte interval.
type Interval struct {
	Start  uint32
	Length uint32
}

// Analysis is one bounded vulnerability-specific evidence analysis.
type Analysis struct {
	Value     string
	Sensitive []Interval
	Status    AnalysisStatus
}

func canonicalIntervals(values []Interval) []Interval {
	if len(values) == 0 {
		return nil
	}
	slices.SortFunc(values, func(left, right Interval) int {
		if left.Start < right.Start {
			return -1
		}
		if left.Start > right.Start {
			return 1
		}
		if left.Length < right.Length {
			return -1
		}
		if left.Length > right.Length {
			return 1
		}
		return 0
	})
	output := 0
	for _, current := range values {
		if current.Length == 0 {
			continue
		}
		end := current.Start + current.Length
		if output > 0 {
			previous := &values[output-1]
			previousEnd := previous.Start + previous.Length
			if current.Start <= previousEnd {
				if end > previousEnd {
					previous.Length = end - previous.Start
				}
				continue
			}
		}
		values[output] = current
		output++
	}
	return values[:output]
}
