// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import (
	"testing"

	"github.com/DataDog/go-sqllexer"
)

func FuzzAnalyzeSQL(f *testing.F) {
	f.Add("SELECT 'secret', 123")
	f.Add("SELECT q'{pass'word}' FROM dual")
	f.Add("SELECT $tag$secret$tag$")
	f.Add("SELECT q'\\x\\'hunter2'")
	f.Add("'!q'!1!'!\\]]1{{ {")
	f.Add("a)(q'![['{!',(][")
	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > MaxAnalyzerBytes+1 {
			return
		}
		analysis := AnalyzeSQL(query)
		if analysis.Status != AnalysisOK {
			if analysis.Value != "" || len(analysis.Sensitive) != 0 {
				t.Fatalf("non-OK analysis exposed evidence: %#v", analysis)
			}
			return
		}
		if analysis.Value != query || len(analysis.Sensitive) > MaxSensitiveIntervals {
			t.Fatalf("invalid OK analysis: %#v", analysis)
		}
		var previousEnd uint32
		for index, interval := range analysis.Sensitive {
			if interval.Length == 0 || interval.Start > uint32(len(query)) || interval.Length > uint32(len(query))-interval.Start || index > 0 && interval.Start <= previousEnd {
				t.Fatalf("invalid interval %d: %#v", index, interval)
			}
			previousEnd = interval.Start + interval.Length
		}
		assertDefaultSQLLiteralsCovered(t, query, analysis.Sensitive)
	})
}

func assertDefaultSQLLiteralsCovered(t *testing.T, query string, intervals []Interval) {
	t.Helper()
	_, quoteSpans, _ := scanOracleQuotes(query)
	segmentStart := 0
	for _, span := range quoteSpans {
		assertSQLSegmentLiteralsCovered(t, query[segmentStart:span.start], segmentStart, intervals)
		segmentStart = span.end
	}
	assertSQLSegmentLiteralsCovered(t, query[segmentStart:], segmentStart, intervals)
}

func assertSQLSegmentLiteralsCovered(t *testing.T, segment string, offset int, intervals []Interval) {
	t.Helper()
	lexer := sqllexer.New(segment)
	position := 0
	for tokens := 0; tokens < maxAnalyzerTokens; tokens++ {
		token := lexer.Scan()
		if token == nil || token.Type == sqllexer.ERROR || token.Type == sqllexer.EOF {
			return
		}
		interval, sensitive := sqlSensitiveToken(token.Type, offset+position, token.Value)
		position += len(token.Value)
		if !sensitive {
			continue
		}
		end := interval.Start + interval.Length
		covered := false
		for _, candidate := range intervals {
			if candidate.Start <= interval.Start && candidate.Start+candidate.Length >= end {
				covered = true
				break
			}
		}
		if !covered {
			t.Fatalf("literal interval %#v is not covered by %#v", interval, intervals)
		}
	}
}

func FuzzMappedPattern(f *testing.F) {
	f.Add("secret", "prefix-secret-suffix", 1_000)
	f.Add("repeat", "repeat-repeat", 1_000)
	f.Add("\xff", "\x00\xff\xfe", 1)
	f.Fuzz(func(t *testing.T, value, source string, budget int) {
		if len(value) > 1_024 || len(source) > 4_096 {
			return
		}
		budget &= 0xffff
		got := mappedPattern(value, source, alphanumericPattern(len(source)), &budget)
		if len(got) != len(value) {
			t.Fatalf("pattern length = %d, want %d", len(got), len(value))
		}
		if budget < 0 {
			t.Fatalf("budget became negative: %d", budget)
		}
	})
}
