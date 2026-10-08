// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain gives the builds that the tests start (go tool orchestrion go
// build) their own build cache when the test binary collects coverage. With
// -coverpkg, the parent build puts woven standard library packages that were
// compiled against coverage-instrumented dd-iast-go packages in the shared
// cache, and Orchestrion reuses them in the child build: the link then fails
// with "fingerprint mismatch". The separate cache is shared by all the test
// packages of one run.
func TestMain(m *testing.M) {
	if testing.CoverMode() != "" {
		_ = os.Setenv("GOCACHE", filepath.Join(os.TempDir(), "dd-iast-cover-gocache"))
	}
	os.Exit(m.Run())
}
