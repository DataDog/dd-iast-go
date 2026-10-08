// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bridgetests_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestBridgeDependencies checks the dependency rule of the bridge:
// encoding/json and encoding/json/v2 import jsonbridge, thus jsonbridge must
// not import an encoding package. It imports only reflect, sync/atomic, unsafe,
// and their dependencies.
func TestBridgeDependencies(t *testing.T) {
	gotool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not available")
	}
	list := func(pkg string) map[string]bool {
		t.Helper()
		output, err := exec.Command(gotool, "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		packages := map[string]bool{}
		for _, line := range strings.Fields(string(output)) {
			packages[line] = true
		}
		return packages
	}
	const bridgePackage = "github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	allowed := list("reflect")
	for _, dependency := range []string{bridgePackage, "sync/atomic", "unsafe"} {
		allowed[dependency] = true
	}
	for dependency := range list(bridgePackage) {
		if strings.HasPrefix(dependency, "encoding/") || !allowed[dependency] {
			t.Errorf("jsonbridge depends on %s", dependency)
		}
	}
}
