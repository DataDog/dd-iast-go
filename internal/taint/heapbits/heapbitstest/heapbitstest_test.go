// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbitstest_test

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// Without the woven runtime, all the knobs do nothing and return zero
// values (the tests of package heapbits skip in this case).
func TestKnobsWithoutRuntime(t *testing.T) {
	if heapbitstest.Enabled() {
		t.Skip("the runtime is woven: the tests of package heapbits use the knobs")
	}
	var x [64]byte
	p := unsafe.Pointer(&x)
	if probe, worker, yields := heapbitstest.Knobs(false, false); probe != heapbitstest.ProbeNone || worker != heapbitstest.ProbeNone || yields != 0 {
		t.Errorf("Knobs: %d %d %d", probe, worker, yields)
	}
	if st := heapbitstest.Stats(); st != (heapbitstest.Storage{}) {
		t.Errorf("Stats: %+v", st)
	}
	if got := heapbitstest.AllocKnobs(false, false, false, false); got != heapbitstest.NoneParked {
		t.Errorf("AllocKnobs: %d", got)
	}
	heapbitstest.SetNoSweep(false)
	heapbitstest.SetHookKnobs(false, false)
	if heapbitstest.Freegc(p, 64) {
		t.Error("Freegc succeeded")
	}
	if got := heapbitstest.SetForceSlowPath(false); got != 0 {
		t.Errorf("SetForceSlowPath: %d", got)
	}
	if heapbitstest.HasDirectory(p) {
		t.Error("HasDirectory: true")
	}
	if got := heapbitstest.SpanFlag(p); got != -1 {
		t.Errorf("SpanFlag: %d", got)
	}
	if base, n := heapbitstest.SpanInfo(p); base != 0 || n != 0 {
		t.Errorf("SpanInfo: %#x %d", base, n)
	}
	if sweeps, waiting := heapbitstest.SweepKnobs(nil, heapbitstest.NoPause, false); sweeps != 0 || waiting != 0 {
		t.Errorf("SweepKnobs: %d %d", sweeps, waiting)
	}
	if n, _ := heapbitstest.SweepDurations(); n != 0 {
		t.Errorf("SweepDurations: %d", n)
	}
}
