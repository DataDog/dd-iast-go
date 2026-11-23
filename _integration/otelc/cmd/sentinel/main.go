// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command sentinel is a woven program that exits with an error when a
// capability that the build must have does not work (see package sentinel).
//
// The environment variable DD_IAST_EXPECTED_BUILD_TOOL names the tool that must
// have built the program ("orchestrion" or "otelc"). Without it, the program
// accepts any tool, but it still fails for a build with no tool.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/DataDog/dd-iast-go/_integration/otelc/internal/sentinel"
	"github.com/DataDog/dd-iast-go/internal/build"
)

func main() {
	if err := sentinel.Run(os.Getenv("DD_IAST_EXPECTED_BUILD_TOOL")); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel: FAIL:", err)
		os.Exit(1)
	}
	fmt.Printf("sentinel: ok tool=%q go=%s\n", build.Tool(), runtime.Version())
}
