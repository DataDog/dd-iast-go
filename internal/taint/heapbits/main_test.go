// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"flag"
	"os"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

// childEnv is set in the child processes of tests that need a fresh runtime
// (negative controls, budget tests). They set their own budget.
const childEnv = "HEAPBITS_CHILD"

func TestMain(m *testing.M) {
	// The tests taint much more memory than an application: the storage is
	// never given back (chunks of small objects stay in use), so the default
	// budget would be used after a few tests.
	if os.Getenv(childEnv) == "" {
		heapbits.SetBudget(heapbits.MaxBudget)
	}
	os.Exit(m.Run())
}

// childArgs returns the arguments of a child process of this test binary
// that runs the tests that match pattern, with verbose output. When the
// parent collects coverage, the child writes its counters in the coverage
// directory of the parent: go test adds them to the coverage profile (else
// the code that only the children run would count as not covered).
func childArgs(pattern string) []string {
	args := []string{"-test.run=" + pattern, "-test.v"}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	return args
}
