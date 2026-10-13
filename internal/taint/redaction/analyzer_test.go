// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import (
	"strings"
	"testing"
)

func TestAnalyzeSQLLiterals(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{name: "ansi", query: `SELECT 'secret', 123, true, NULL`, want: `SELECT '?', ?, ?, ?`},
		{name: "parameters", query: `SELECT * FROM users WHERE a = ? AND b = $1 AND c = :name`, want: `SELECT * FROM users WHERE a = ? AND b = $1 AND c = :name`},
		{name: "mysql quotes", query: `SELECT "secret"`, want: `SELECT "?"`},
		{name: "postgres dollar", query: `SELECT $tag$secret$tag$`, want: `SELECT $tag$?$tag$`},
		{name: "oracle square quote", query: `SELECT q'[secret]' FROM dual`, want: `SELECT q'[?]' FROM dual`},
		{name: "oracle paired quote", query: `SELECT q'<secret>' FROM dual`, want: `SELECT q'<?>' FROM dual`},
		{name: "oracle embedded quote", query: `SELECT q'{pass'word=hunter2secret}' FROM dual`, want: `SELECT q'{?}' FROM dual`},
		{name: "identifier ending q", query: `SELECT faq'secret'`, want: `SELECT faq'?'`},
		{name: "empty q-like sequence", query: `SELECT 'pass q'||'other'`, want: `SELECT '?'||'?'`},
		{name: "q span cannot suppress longer token", query: "SELECT q'\\x\\'hunter2'", want: "SELECT q'?'"},
		{name: "incomplete", query: `SELECT 'secret`, want: `SELECT '?`},
		{name: "comments", query: `SELECT column -- secret` + "\nFROM table", want: `SELECT column -- secret` + "\nFROM table"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analysis := AnalyzeSQL(test.query)
			if analysis.Status != AnalysisOK {
				t.Fatalf("status = %v", analysis.Status)
			}
			if got := maskSensitive(analysis); got != test.want {
				t.Fatalf("masked SQL = %q, want %q; intervals=%#v", got, test.want, analysis.Sensitive)
			}
		})
	}
}

func TestAnalyzeSQLBounds(t *testing.T) {
	oversized := AnalyzeSQL(strings.Repeat("x", MaxAnalyzerBytes+1))
	if oversized.Status != AnalysisOversized || oversized.Value != "" || len(oversized.Sensitive) != 0 {
		t.Fatalf("oversized analysis = %#v", oversized)
	}
	flood := AnalyzeSQL(strings.Repeat("1,", MaxSensitiveIntervals+1))
	if flood.Status != AnalysisDropped || flood.Value != "" {
		t.Fatalf("literal flood = %#v, want self-safe dropped result", flood)
	}
	ordinary := AnalyzeSQL(`INSERT INTO t VALUES (` + strings.Repeat(`'value',`, 199) + `'value')`)
	if ordinary.Status != AnalysisOK || len(ordinary.Sensitive) != 200 {
		t.Fatalf("200-literal analysis = status:%v intervals:%d", ordinary.Status, len(ordinary.Sensitive))
	}
}

func TestAnalyzeCommand(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{name: "command only", argv: []string{"ls"}, want: "ls"},
		{name: "arguments", argv: []string{"ls", "-l", "/secret"}, want: "ls ?"},
		{name: "sudo", argv: []string{"sudo", "ls", "-l", "/secret"}, want: "sudo ls ?"},
		{name: "sudo path", argv: []string{"/usr/bin/sudo", "ls", "-l"}, want: "/usr/bin/sudo ls ?"},
		{name: "doas", argv: []string{"doas", "cat", "/secret"}, want: "doas cat ?"},
		{name: "empty", argv: nil, want: ""},
		{name: "empty arguments", argv: []string{"ls", "", "secret"}, want: "ls ?"},
		{name: "single empty argument", argv: []string{"ls", ""}, want: "ls "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analysis := AnalyzeCommand(test.argv)
			if analysis.Status != AnalysisOK {
				t.Fatalf("status = %v", analysis.Status)
			}
			if got := maskSensitive(analysis); got != test.want {
				t.Fatalf("masked command = %q, want %q; intervals=%#v", got, test.want, analysis.Sensitive)
			}
		})
	}
}

func TestAnalyzeCommandBounds(t *testing.T) {
	many := make([]string, MaxCommandArguments+1)
	if got := AnalyzeCommand(many); got.Status != AnalysisOversized || got.Value != "" {
		t.Fatalf("argument flood = %#v", got)
	}
	if got := AnalyzeCommand([]string{"cmd", strings.Repeat("x", MaxAnalyzerBytes)}); got.Status != AnalysisOversized {
		t.Fatalf("byte flood = %#v", got)
	}
	exact := AnalyzeCommand([]string{strings.Repeat("x", MaxAnalyzerBytes)})
	if exact.Status != AnalysisOK || len(exact.Value) != MaxAnalyzerBytes {
		t.Fatalf("exact boundary = %#v", exact)
	}
}

func TestCanonicalIntervals(t *testing.T) {
	values := canonicalIntervals([]Interval{{Start: 5, Length: 2}, {Start: 1, Length: 2}, {Start: 3, Length: 2}, {Start: 1, Length: 1}})
	if len(values) != 1 || values[0] != (Interval{Start: 1, Length: 6}) {
		t.Fatalf("canonical intervals = %#v", values)
	}
}

func BenchmarkAnalyzeSQL(b *testing.B) {
	benchmarks := []struct {
		name  string
		query string
	}{
		{name: "typical", query: `SELECT * FROM users WHERE email = 'user@example.com' AND tenant = 123`},
		{name: "two_hundred_literals", query: `INSERT INTO t VALUES (` + strings.Repeat(`'value',`, 199) + `'value')`},
		{name: "q_quote_flood", query: strings.Repeat("q'||' ", MaxAnalyzerBytes/6)},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = AnalyzeSQL(benchmark.query)
			}
		})
	}
}

func BenchmarkAnalyzeCommand(b *testing.B) {
	argv := []string{"/bin/sh", "-c", "curl https://example.com/token | jq .secret"}
	b.ReportAllocs()
	for b.Loop() {
		_ = AnalyzeCommand(argv)
	}
}

func maskSensitive(analysis Analysis) string {
	if analysis.Status != AnalysisOK || len(analysis.Sensitive) == 0 {
		return analysis.Value
	}
	var builder strings.Builder
	position := uint32(0)
	for _, interval := range analysis.Sensitive {
		builder.WriteString(analysis.Value[position:interval.Start])
		builder.WriteByte('?')
		position = interval.Start + interval.Length
	}
	builder.WriteString(analysis.Value[position:])
	return builder.String()
}
