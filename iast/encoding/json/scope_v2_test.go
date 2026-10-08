// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build go1.27 && goexperiment.jsonv2

package json

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// jsonbridgePath is the import path of the JSON bridge.
const jsonbridgePath = "github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"

// workDirectory finds the WORK line that "go build -work" writes.
var workDirectory = regexp.MustCompile(`(?m)^WORK=(.+)$`)

// TestV2ReadValueHookScope checks the scope of the "[v2] encoding/json
// Decoder.Decode value document" aspect. Its join point matches the three
// ReadValue calls of encoding/json. The template must change only the call in
// (*Decoder).Decode:
//
//  1. A woven build of testdata/scopeprobe succeeds. Thus checkValid and
//     (*Number).UnmarshalJSONFrom compile after weaving.
//  2. In the woven files of encoding/json, checkValid and
//     (*Number).UnmarshalJSONFrom have no __dd_iast code and no reference to
//     the JSON bridge, and (*Decoder).Decode has exactly one call of
//     jsonbridge.ReaderDocument.
//  3. The results of json.Valid and of the json.Number decodes of the probe
//     are the same in the woven and in the unwoven build, with an active
//     request and a bound reader.
func TestV2ReadValueHookScope(t *testing.T) {
	requireWoven(t)
	directory := t.TempDir()
	probe := "./testdata/scopeprobe"

	woven := filepath.Join(directory, "woven")
	// -a: the compile of encoding/json must run, so that Orchestrion writes
	// its woven files to WORK. A cached archive gives no files. The probe
	// needs no VCS information.
	build := exec.CommandContext(t.Context(), "go", "tool", "orchestrion", "go", "build", "-buildvcs=false", "-work", "-a", "-o", woven, probe)
	output, err := build.CombinedOutput()
	if match := workDirectory.FindSubmatch(output); match != nil {
		work := strings.TrimSpace(string(match[1]))
		t.Cleanup(func() { _ = os.RemoveAll(work) })
		if err == nil {
			checkWovenReadValueScope(t, work)
		}
	}
	require.NoError(t, err, "the woven build of the probe failed:\n%s", output)

	unwoven := filepath.Join(directory, "unwoven")
	output, err = exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", unwoven, probe).CombinedOutput()
	require.NoError(t, err, "the unwoven build of the probe failed:\n%s", output)

	wovenResults, wovenTaint := runProbe(t, woven)
	unwovenResults, unwovenTaint := runProbe(t, unwoven)
	require.NotEmpty(t, unwovenResults)
	require.Equal(t, unwovenResults, wovenResults, "the woven probe has other results than the unwoven probe")
	// A control: the Decode hook is active in the woven probe.
	require.Equal(t, []string{"taint decode object s=false", "taint decode object s=false"}, unwovenTaint)
	require.Equal(t, []string{"taint decode object s=true", "taint decode object s=true"}, wovenTaint)
}

// runProbe runs the probe binary, and returns its "result " lines and its
// "taint " lines.
func runProbe(t *testing.T, binary string) (results, taints []string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), binary)
	// The woven probe also starts the tracer. It must not try to send data.
	command.Env = append(os.Environ(), "DD_TRACE_ENABLED=false", "DD_INSTRUMENTATION_TELEMETRY_ENABLED=false", "DD_TRACE_STARTUP_LOGS=false")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	require.NoError(t, command.Run(), "the probe %s failed:\n%s", binary, stderr.String())
	for line := range strings.Lines(stdout.String()) {
		line = strings.TrimSuffix(line, "\n")
		switch {
		case strings.HasPrefix(line, "result "):
			results = append(results, line)
		case strings.HasPrefix(line, "taint "):
			taints = append(taints, line)
		}
	}
	return results, taints
}

// checkWovenReadValueScope parses each woven file of encoding/json in work,
// and checks the three functions with a ReadValue call. A function in a file
// that Orchestrion did not change is not in work: it has no woven code.
func checkWovenReadValueScope(t *testing.T, work string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(work, "b*", "orchestrion", "src", "encoding", "json", "*.go"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "no woven file of encoding/json in %s", work)
	decodes := 0
	for _, name := range files {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)
		bridge := bridgeNames(file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			switch receiverName(function) + "." + function.Name.Name {
			case ".checkValid", "Number.UnmarshalJSONFrom":
				for _, found := range wovenCode(function.Body, bridge) {
					t.Errorf("%s: %s has woven code: %s", filepath.Base(name), function.Name.Name, found)
				}
			case "Decoder.Decode":
				decodes++
				require.Equal(t, 1, readerDocumentCalls(function.Body, bridge),
					"%s: (*Decoder).Decode must have exactly one call of jsonbridge.ReaderDocument", filepath.Base(name))
			}
		}
	}
	require.Equal(t, 1, decodes, "the woven files must have exactly one (*Decoder).Decode")
}

// bridgeNames returns the names of the imports of the JSON bridge in file.
func bridgeNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, specification := range file.Imports {
		path, err := strconv.Unquote(specification.Path.Value)
		if err != nil || path != jsonbridgePath {
			continue
		}
		name := filepath.Base(path)
		if specification.Name != nil {
			name = specification.Name.Name
		}
		names[name] = true
	}
	return names
}

// receiverName returns the name of the receiver type of function, with no
// pointer, or "" for a function with no receiver.
func receiverName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	receiver := function.Recv.List[0].Type
	if star, ok := receiver.(*ast.StarExpr); ok {
		receiver = star.X
	}
	if identifier, ok := receiver.(*ast.Ident); ok {
		return identifier.Name
	}
	return ""
}

// wovenCode returns the identifiers with the prefix __dd_iast and the
// selectors on the JSON bridge in body.
func wovenCode(body *ast.BlockStmt, bridge map[string]bool) (found []string) {
	ast.Inspect(body, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Ident:
			if strings.HasPrefix(node.Name, "__dd_iast") {
				found = append(found, node.Name)
			}
		case *ast.SelectorExpr:
			if identifier, ok := node.X.(*ast.Ident); ok && bridge[identifier.Name] {
				found = append(found, identifier.Name+"."+node.Sel.Name)
			}
		}
		return true
	})
	return found
}

// readerDocumentCalls returns the number of calls of jsonbridge.ReaderDocument
// in body.
func readerDocumentCalls(body *ast.BlockStmt, bridge map[string]bool) (count int) {
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		function := call.Fun
		if index, ok := function.(*ast.IndexExpr); ok {
			// An explicit instantiation: ReaderDocument[V](...).
			function = index.X
		}
		if selector, ok := function.(*ast.SelectorExpr); ok && selector.Sel.Name == "ReaderDocument" {
			if identifier, ok := selector.X.(*ast.Ident); ok && bridge[identifier.Name] {
				count++
			}
		}
		return true
	})
	return count
}
