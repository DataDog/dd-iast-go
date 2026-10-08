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
	"testing"
)

func TestMergeCoverageIncludesEveryProfile(t *testing.T) {
	script, err := filepath.Abs("merge-coverage.py")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, profile := range map[string]string{
		"coverage.txt":    "mode: atomic\nexample.com/module/source.go:10.1,12.2 1 0\n",
		"integration.txt": "mode: atomic\nexample.com/module/source.go:10.1,12.2 1 3\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(profile), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	command := exec.Command("python3", script, "coverage.txt", "integration.txt")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("merge coverage: %v\n%s", err, output)
	}

	result, err := os.ReadFile(filepath.Join(directory, "coverage.merged.txt"))
	if err != nil {
		t.Fatal(err)
	}
	const expected = "mode: atomic\nexample.com/module/source.go:10.1,12.2 1 3\n"
	if string(result) != expected {
		t.Fatalf("merged profile = %q; want %q", result, expected)
	}
}

func TestMergeCoveragePreservesBlocks(t *testing.T) {
	script, err := filepath.Abs("merge-coverage.py")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	const profile = "mode: atomic\n" +
		"example.com/module/source.go:10.1,12.2 2 3\n" +
		"example.com/module/source.go:2.1,4.2 1 0\n" +
		"example.com/module/source.go:10.1,12.2 2 4\n" +
		"example.com/module/other.go:5.1,5.2 0 0\n"
	if err := os.WriteFile(filepath.Join(directory, "coverage.txt"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("python3", script, "coverage.txt")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("merge coverage: %v\n%s", err, output)
	}

	result, err := os.ReadFile(filepath.Join(directory, "coverage.merged.txt"))
	if err != nil {
		t.Fatal(err)
	}
	const expected = "mode: atomic\n" +
		"example.com/module/other.go:5.1,5.2 0 0\n" +
		"example.com/module/source.go:2.1,4.2 1 0\n" +
		"example.com/module/source.go:10.1,12.2 2 7\n"
	if string(result) != expected {
		t.Fatalf("merged profile = %q; want %q", result, expected)
	}
}

func TestMergeCoverageRejectsInvalidInput(t *testing.T) {
	script, err := filepath.Abs("merge-coverage.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		profiles []string
	}{
		{name: "no profiles"},
		{name: "empty profile", profiles: []string{""}},
		{name: "wrong mode", profiles: []string{"mode: set\n"}},
		{name: "invalid later profile", profiles: []string{"mode: atomic\n", "mode: count\n"}},
		{name: "malformed block", profiles: []string{"mode: atomic\ninvalid\n"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			args := []string{script}
			for index, profile := range test.profiles {
				name := filepath.Join(directory, string(rune('a'+index))+".txt")
				if err := os.WriteFile(name, []byte(profile), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, name)
			}

			command := exec.Command("python3", args...)
			command.Dir = directory
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				t.Fatalf("expected a failing merge, got %v\n%s", err, output)
			}
			if _, err := os.Stat(filepath.Join(directory, "coverage.merged.txt")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid profiles produced output: %v", err)
			}
		})
	}
}
