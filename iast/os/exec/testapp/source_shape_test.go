// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGo126OSExecStartProcessShape(t *testing.T) {
	if !strings.HasPrefix(runtime.Version(), "go1.26.") {
		t.Fatalf("toolchain = %s, want a pinned Go 1.26 patch", runtime.Version())
	}
	directory := filepath.Join(runtime.GOROOT(), "src", "os", "exec")
	path := filepath.Join(directory, "exec.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	startMethods := 0
	processCalls := 0
	packageProcessCalls := packageStartProcessCalls(t, directory)
	argvShape := false
	contextField := false
	for _, declaration := range file.Decls {
		if general, ok := declaration.(*ast.GenDecl); ok {
			for _, specification := range general.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != "Cmd" {
					continue
				}
				structure, _ := typeSpec.Type.(*ast.StructType)
				if structure != nil {
					for _, field := range structure.Fields.List {
						selector, selectorOK := field.Type.(*ast.SelectorExpr)
						if !selectorOK {
							continue
						}
						packageName, packageOK := selector.X.(*ast.Ident)
						if len(field.Names) == 1 && field.Names[0].Name == "ctx" && packageOK && packageName.Name == "context" && selector.Sel.Name == "Context" {
							contextField = true
						}
					}
				}
			}
		}
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		isStart := function.Name.Name == "Start" && commandReceiver(function) == "Cmd"
		if isStart {
			startMethods++
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			packageName, packageOK := selector.X.(*ast.Ident)
			if !packageOK || packageName.Name != "os" || selector.Sel.Name != "StartProcess" {
				return true
			}
			if !isStart {
				return true
			}
			processCalls++
			if len(call.Args) == 3 {
				argvCall, callOK := call.Args[1].(*ast.CallExpr)
				if callOK {
					argvSelector, selectorOK := argvCall.Fun.(*ast.SelectorExpr)
					argvShape = selectorOK && argvSelector.Sel.Name == "argv"
				}
			}
			return true
		})
	}
	if startMethods != 1 || processCalls != 1 || packageProcessCalls != 1 || !argvShape || !contextField {
		t.Fatalf("Cmd.Start methods = %d, Start process calls = %d, package process calls = %d, c.argv shape = %t, ctx field = %t", startMethods, processCalls, packageProcessCalls, argvShape, contextField)
	}
}

func packageStartProcessCalls(t *testing.T, directory string) int {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, entry.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "StartProcess" {
				return true
			}
			packageName, ok := selector.X.(*ast.Ident)
			if ok && packageName.Name == "os" {
				count++
			}
			return true
		})
	}
	return count
}

func commandReceiver(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	receiver := function.Recv.List[0].Type
	if pointer, ok := receiver.(*ast.StarExpr); ok {
		receiver = pointer.X
	}
	identifier, _ := receiver.(*ast.Ident)
	if identifier == nil {
		return ""
	}
	return identifier.Name
}
