// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package sqlbridge

import (
	"context"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestKindWireValues(t *testing.T) {
	if KindPrepare != 1 || KindExec != 2 || KindQuery != 3 {
		t.Fatalf("kind values = (%d, %d, %d)", KindPrepare, KindExec, KindQuery)
	}
}

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
	Register(func(context.Context, string, Kind) {
		calls.Add(1)
		panic("shielded")
	})
	Report(context.Background(), "SELECT 1", KindExec, true)
	if calls.Load() != 0 {
		t.Fatal("inactive report invoked callback")
	}
	BindActiveOwners(&owners)
	Report(context.Background(), "SELECT 1", KindExec, true)
	if calls.Load() != 0 {
		t.Fatal("zero owner bitset invoked callback")
	}
	owners.Store(1)
	Report(context.Background(), "SELECT 1", KindExec, true)
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
		"database/sql",
		"github.com/DataDog/dd-iast-go/iast/database/sql",
		"github.com/DataDog/dd-iast-go/internal/vulnerability",
		"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer",
		"github.com/DataDog/go-sqllexer",
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
		Report(context.Background(), "SELECT 1", KindExec, true)
	}
}
