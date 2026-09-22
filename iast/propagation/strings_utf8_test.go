// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestToValidUTF8UsesOnlyContributingProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	tests := []struct {
		name        string
		value       string
		replacement string
		taintValue  bool
		taintRepair bool
		wantSources map[string]string
	}{
		{
			name: "tainted valid value ignores tainted replacement", value: "valid", replacement: "REPL",
			taintValue: true, taintRepair: true, wantSources: map[string]string{"value": "valid"},
		},
		{
			name: "clean valid value ignores tainted replacement", value: "valid", replacement: "REPL",
			taintRepair: true,
		},
		{
			name: "clean invalid value uses tainted replacement", value: "a\xffb", replacement: "REPL",
			taintRepair: true, wantSources: map[string]string{"replacement": "REPL"},
		},
		{
			name: "tainted invalid value uses both contributors", value: "a\xffb", replacement: "REPL",
			taintValue: true, taintRepair: true,
			wantSources: map[string]string{"value": "a\xffb", "replacement": "REPL"},
		},
		{
			name: "tainted invalid value remains tainted with clean replacement", value: "a\xffb", replacement: "REPL",
			taintValue: true, wantSources: map[string]string{"value": "a\xffb"},
		},
		{
			name: "empty value ignores tainted replacement", value: "", replacement: "REPL",
			taintRepair: true,
		},
		{
			name: "used replacement can preserve the original bytes", value: "\xff\xc0", replacement: "\xff\xc0",
			taintRepair: true, wantSources: map[string]string{"replacement": "\xff\xc0"},
		},
		{
			name: "malformed run uses replacement once", value: "\xff\xc0", replacement: "REPL",
			taintRepair: true, wantSources: map[string]string{"replacement": "REPL"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := strings.ToValidUTF8(test.value, test.replacement)
			value := test.value
			if test.taintValue {
				value = activeStringSource(t, "value", value)
			}
			replacement := test.replacement
			if test.taintRepair {
				replacement = activeStringSource(t, "replacement", replacement)
			}

			got := testapp.ToValidUTF8(value, replacement)
			require.Equal(t, want, got)
			gotSources := make(map[string]string)
			tainted := taint.VisitString(got, func(observed taint.Range) bool {
				require.Zero(t, observed.Start)
				require.Equal(t, uint32(len(got)), observed.Length)
				gotSources[observed.Source.Name] = observed.Source.Value
				return true
			})
			require.Equal(t, len(test.wantSources) > 0, tainted)
			if len(test.wantSources) == 0 {
				require.Empty(t, gotSources)
			} else {
				require.Equal(t, test.wantSources, gotSources)
			}
		})
	}
}
