// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestImportGraph(t *testing.T) {
	const module = "github.com/DataDog/dd-iast-go/"
	check := func(pattern string, forbidden ...string) {
		t.Helper()
		files, err := filepath.Glob(pattern)
		if err != nil || len(files) == 0 {
			t.Fatalf("glob %q: %v, %d files", pattern, err, len(files))
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, "_inject.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range file.Imports {
				name, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				for _, bad := range forbidden {
					if name == bad || (bad == module+"internal/taint/heapranges" && strings.HasPrefix(name, bad+"/")) {
						t.Errorf("%s imports %s", path, name)
					}
				}
			}
		}
	}
	check("*.go", module+"internal/build", module+"internal/config")
	check(filepath.Join("..", "..", "config", "*.go"), module+"internal/taint/heapranges")

	output, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}
	for _, name := range strings.Fields(string(output)) {
		if name == module+"internal/build" || name == module+"internal/config" {
			t.Errorf("forbidden dependency: %s", name)
		}
	}
}
