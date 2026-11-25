// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func TestRuntimeWoven(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires a woven build")
	}
	if knobs.Gate == nil {
		t.Fatal("runtime gate is not linked")
	}
	if got := knobs.Gate(); got != 0 {
		t.Fatalf("gate = %d, want armed", got)
	}
	if heapranges.Enabled() {
		t.Fatal("heap tracking enabled before initialization")
	}
}
