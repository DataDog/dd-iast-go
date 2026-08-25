// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package taint

import "testing"

func TestMarksHas(t *testing.T) {
	marks := Marks{bits: uint64(1) << VulnerabilityTypeSqlInjection}
	if !marks.Has(VulnerabilityTypeSqlInjection) {
		t.Fatal("SQL injection mark was not visible")
	}
	if marks.Has(VulnerabilityTypeCommandInjection) {
		t.Fatal("unrelated command injection mark was visible")
	}
}
