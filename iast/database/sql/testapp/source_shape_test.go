// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestGo126DatabaseSQLSourceShape(t *testing.T) {
	if !strings.HasPrefix(runtime.Version(), "go1.26.") {
		t.Fatalf("toolchain = %s, want a pinned Go 1.26 patch", runtime.Version())
	}
	path := filepath.Join(runtime.GOROOT(), "src", "database", "sql", "sql.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	anchorCount := 0
	stmtQuery := false
	argumentNamesValid := true
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			receiver := receiverName(declaration)
			if receiver != "" && (declaration.Name.Name == "PrepareContext" || declaration.Name.Name == "ExecContext" || declaration.Name.Name == "QueryContext") {
				got = append(got, receiver+"."+declaration.Name.Name)
				wantArgument := "query"
				if receiver == "Stmt" {
					wantArgument = "args"
				}
				argumentNamesValid = argumentNamesValid && parameterName(declaration, 1) == wantArgument
			}
			if receiver == "DB" && declaration.Name.Name == "SetMaxIdleConns" {
				anchorCount++
			}
		case *ast.GenDecl:
			for _, specification := range declaration.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != "Stmt" {
					continue
				}
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structure.Fields.List {
					if len(field.Names) == 1 && field.Names[0].Name == "query" {
						identifier, ok := field.Type.(*ast.Ident)
						stmtQuery = ok && identifier.Name == "string"
					}
				}
			}
		}
	}
	want := []string{
		"Conn.ExecContext", "Conn.PrepareContext", "Conn.QueryContext",
		"DB.ExecContext", "DB.PrepareContext", "DB.QueryContext",
		"Stmt.ExecContext", "Stmt.QueryContext",
		"Tx.ExecContext", "Tx.PrepareContext", "Tx.QueryContext",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("context sink methods = %#v, want %#v", got, want)
	}
	if anchorCount != 1 || !stmtQuery || !argumentNamesValid {
		t.Fatalf("declaration anchor count = %d, Stmt.query string field = %t, argument names valid = %t", anchorCount, stmtQuery, argumentNamesValid)
	}
}

func parameterName(function *ast.FuncDecl, index int) string {
	current := 0
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			if current == index {
				return name.Name
			}
			current++
		}
	}
	return ""
}

func receiverName(function *ast.FuncDecl) string {
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
