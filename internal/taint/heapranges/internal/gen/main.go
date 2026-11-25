// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

func declarations(path string) (string, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, source, parser.ParseComments)
	if err != nil {
		return "", err
	}
	var first token.Pos
	var importsEnd token.Pos
	for _, decl := range file.Decls {
		if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.IMPORT {
			importsEnd = gen.End()
			continue
		}
		first = decl.Pos()
		break
	}
	if !first.IsValid() {
		return "", fmt.Errorf("%s has no declarations", path)
	}
	for _, comment := range file.Comments {
		if comment.Pos() > importsEnd && comment.Pos() < first {
			first = comment.Pos()
			break
		}
	}
	return strings.TrimSpace(string(source[set.Position(first).Offset:])), nil
}

func indent(s string) string {
	return "            " + strings.ReplaceAll(s, "\n", "\n            ")
}

func run() error {
	template, err := os.ReadFile("orchestrion.yml.tmpl")
	if err != nil {
		return err
	}
	runtime, err := declarations("runtime_inject.go")
	if err != nil {
		return err
	}
	pkg, err := declarations("heapranges_inject.go")
	if err != nil {
		return err
	}
	result := string(template)
	for _, replacement := range [][2]string{{"__RUNTIME__", runtime}, {"__PACKAGE__", pkg}} {
		if strings.Count(result, replacement[0]) != 1 {
			return fmt.Errorf("expected one %s placeholder", replacement[0])
		}
		result = strings.Replace(result, replacement[0], indent(replacement[1]), 1)
	}
	return os.WriteFile("orchestrion.yml", []byte(result), 0644)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
