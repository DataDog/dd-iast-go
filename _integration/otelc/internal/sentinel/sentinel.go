// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package sentinel holds the checks of the sentinel program
// (_integration/otelc/cmd/sentinel). The program exits with an error when a
// capability that the build must have does not work. A build that passes is
// not a proof that the hooks are installed: a tool can skip a rule with no
// error. The sentinel never skips: in a job that expects a woven build, a build
// that is not instrumented is a failure.
//
// The code is in a package that is not "main" because otelc adds rules to the
// main package of a test binary, and the build of such a test fails (see
// _integration/otelc/doc.go).
package sentinel

import (
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/DataDog/dd-iast-go/_integration/otelc/internal/hookmanifest"
	"github.com/DataDog/dd-iast-go/internal/build"
)

//go:embed hooks.manifest
var manifestText string

// Run checks the build and every hook that the expected-hook manifest lists for
// the current Go version and platform. expectedTool is the name of the tool
// that must have built the program (see [build.Tool]); when it is empty, any
// tool is accepted, but a build with no tool is still a failure. Run returns
// an error that joins all the failures.
func Run(expectedTool string) error {
	return run(expectedTool, manifestText, witnesses)
}

func run(expectedTool, manifestText string, witnesses map[string]func() error) error {
	if !build.Instrumented() {
		return errors.New("the program was not built with Orchestrion or otelc")
	}
	if expectedTool != "" && build.Tool() != expectedTool {
		return fmt.Errorf("the program was built with %q, want %q", build.Tool(), expectedTool)
	}

	manifest, err := hookmanifest.Parse(strings.NewReader(manifestText))
	if err != nil {
		return fmt.Errorf("invalid expected-hook manifest: %w", err)
	}
	minor := hookmanifest.GoMinor(runtime.Version())
	if !strings.HasPrefix(minor, "tip") && !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(minor) {
		// Do not check only the hooks of the entries for all versions.
		return fmt.Errorf("cannot find the Go minor version in %q", runtime.Version())
	}
	var failures []error
	for _, hook := range manifest.Expected(minor, runtime.GOOS, runtime.GOARCH) {
		witness, ok := witnesses[hook]
		if !ok {
			failures = append(failures, fmt.Errorf("hook %q is in the manifest but has no witness", hook))
			continue
		}
		if err := witness(); err != nil {
			failures = append(failures, fmt.Errorf("hook %q: %w", hook, err))
		}
	}
	return errors.Join(failures...)
}
