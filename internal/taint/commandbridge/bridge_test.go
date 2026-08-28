// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package commandbridge

import (
	"context"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReportGateAndPanicShield(t *testing.T) {
	oldCallback := registered.Load()
	oldOwners := activeOwners.Load()
	t.Cleanup(func() {
		registered.Store(oldCallback)
		activeOwners.Store(oldOwners)
	})
	registered.Store(nil)
	activeOwners.Store(nil)
	var owners atomic.Uint64
	var calls atomic.Uint64
	Register(func(context.Context, []string) {
		calls.Add(1)
		panic("shielded")
	})
	Report(context.Background(), []string{"echo"})
	BindActiveOwners(&owners)
	Report(context.Background(), []string{"echo"})
	if calls.Load() != 0 {
		t.Fatal("inactive report invoked callback")
	}
	owners.Store(1)
	Report(context.Background(), []string{"echo"})
	if calls.Load() != 1 {
		t.Fatalf("callback count = %d", calls.Load())
	}
}

func TestDependencyClosureStaysMinimal(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	dependencies := "\n" + string(output)
	for _, forbidden := range []string{
		"os/exec",
		"github.com/DataDog/dd-iast-go/iast/os/exec",
		"github.com/DataDog/dd-iast-go/internal/vulnerability",
		"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer",
	} {
		if strings.Contains(dependencies, "\n"+forbidden+"\n") {
			t.Fatalf("minimal bridge depends on %s", forbidden)
		}
	}
}

func BenchmarkReportInactive(b *testing.B) {
	oldOwners := activeOwners.Load()
	b.Cleanup(func() { activeOwners.Store(oldOwners) })
	var owners atomic.Uint64
	BindActiveOwners(&owners)
	b.ReportAllocs()
	for b.Loop() {
		Report(context.Background(), []string{"echo"})
	}
}
