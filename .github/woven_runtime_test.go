// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ci_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runWovenRuntime runs woven-runtime.sh with a fake loader.go, and returns
// its output and its exit code.
func runWovenRuntime(t *testing.T, loader string, args ...string) (string, int) {
	t.Helper()
	script, err := filepath.Abs("woven-runtime.sh")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "loader.go")
	if err := os.WriteFile(path, []byte(loader), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", append([]string{script}, args...)...)
	command.Env = append(os.Environ(), "LOADER_GO="+path, "WOVEN_CACHE_DIR="+t.TempDir())
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return string(output), exitError.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(output), 0
}

func TestWovenRuntimeLinknames(t *testing.T) {
	const header = "package loader\n\nvar blockedLinknames = map[string][]string{\n"
	for _, test := range []struct {
		name   string
		loader string
		code   int
		output string
	}{
		{
			name:   "no hook name",
			loader: header + "\t\"runtime.coroswitch\": {\"iter\"},\n}\n\nvar other = \"runtime.concatstrings\"\n",
			output: "no hook name in blockedLinknames (1 entries)",
		},
		{
			name:   "bridge name",
			loader: header + "\t\"__dd_iast_rt.gate\": nil,\n}\n",
			code:   1,
			output: "blocked hook names",
		},
		{
			name:   "alias name",
			loader: header + "\t\"runtime.stringtoslicerune\": {\"x\"},\n}\n",
			code:   1,
			output: "blocked hook names",
		},
		{
			name:   "list moved",
			loader: "package loader\n",
			code:   1,
			output: "the list moved",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, code := runWovenRuntime(t, test.loader, "default", "linknames")
			if code != test.code || !strings.Contains(output, test.output) {
				t.Fatalf("exit code %d, output %q; want exit code %d, output with %q", code, output, test.code, test.output)
			}
		})
	}
}

func TestWovenRuntimeRejectsUnknownArguments(t *testing.T) {
	for _, args := range [][]string{{"fast", "linknames"}, {"default", "unknown"}} {
		output, code := runWovenRuntime(t, "", args...)
		if code != 2 || !strings.Contains(output, "unknown") {
			t.Fatalf("%v: exit code %d, output %q; want exit code 2", args, code, output)
		}
	}
}
