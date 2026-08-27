// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import "testing"

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
