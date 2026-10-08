// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package sourceshape parses standard library packages from GOROOT, so that
// shape tests can check the symbols that the aspects use. Only tests use this
// package. A shape test fails when a Go release changes a symbol that an
// aspect uses: then a person must examine the aspect again.
//
// The source root is runtime.GOROOT(). A test binary that starts with the
// GOROOT environment variable set uses that root. Thus a test can run on a
// patched copy of the standard library source.
package sourceshape

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// jsonv2Tag is the build tag of the jsonv2 experiment.
const jsonv2Tag = "goexperiment.jsonv2"

// Package is the parsed source of one standard library package. It has only
// the files that the build constraints of the context select.
type Package struct {
	// ImportPath is the import path of the package.
	ImportPath string
	// Dir is the source directory of the package.
	Dir string
	// Fset has the positions of Files.
	Fset *token.FileSet
	// Files are the parsed non-test Go files of the package.
	Files []*ast.File
}

// Load parses the standard library package importPath. The jsonv2 argument
// sets the build tag goexperiment.jsonv2. Set it to the JSON variant of the
// test binary, so that the parsed files are the files of that variant, also
// when the environment of the test process has a different GOEXPERIMENT.
func Load(importPath string, jsonv2 bool) (*Package, error) {
	buildContext := build.Default
	buildContext.GOROOT = runtime.GOROOT()
	buildContext.ToolTags = slices.DeleteFunc(slices.Clone(buildContext.ToolTags), func(tag string) bool { return tag == jsonv2Tag })
	if jsonv2 {
		buildContext.ToolTags = append(buildContext.ToolTags, jsonv2Tag)
	}
	directory := filepath.Join(buildContext.GOROOT, "src", filepath.FromSlash(importPath))
	pkg, err := buildContext.ImportDir(directory, 0)
	if err != nil {
		return nil, fmt.Errorf("import %s: %w", importPath, err)
	}
	result := &Package{ImportPath: importPath, Dir: directory, Fset: token.NewFileSet()}
	for _, name := range pkg.GoFiles {
		file, err := parser.ParseFile(result.Fset, filepath.Join(directory, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		result.Files = append(result.Files, file)
	}
	return result, nil
}

// Func returns the function or method declaration name. The receiver is the
// receiver type with no type parameters, for example "*Decoder" or
// "decodeBuffer". An empty receiver selects a function. Func returns nil when
// the package has no such declaration.
func (p *Package) Func(receiver, name string) *ast.FuncDecl {
	for _, file := range p.Files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Name.Name == name && Receiver(function) == receiver {
				return function
			}
		}
	}
	return nil
}

// Funcs returns all the function declarations of the package (with methods).
func (p *Package) Funcs() []*ast.FuncDecl {
	var result []*ast.FuncDecl
	for _, file := range p.Files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				result = append(result, function)
			}
		}
	}
	return result
}

// Type returns the type specification name, or nil.
func (p *Package) Type(name string) *ast.TypeSpec {
	for _, file := range p.Files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				if typeSpec := specification.(*ast.TypeSpec); typeSpec.Name.Name == name {
					return typeSpec
				}
			}
		}
	}
	return nil
}

// Var returns the package-level variable specification that declares name,
// or nil.
func (p *Package) Var(name string) *ast.ValueSpec {
	return find(p.Values(token.VAR), name)
}

// Const returns the package-level constant specification that declares
// name, or nil.
func (p *Package) Const(name string) *ast.ValueSpec {
	return find(p.Values(token.CONST), name)
}

// find returns the specification of specifications that declares name, or
// nil.
func find(specifications []*ast.ValueSpec, name string) *ast.ValueSpec {
	for _, specification := range specifications {
		for _, identifier := range specification.Names {
			if identifier.Name == name {
				return specification
			}
		}
	}
	return nil
}

// Values returns all the package-level variable (token.VAR) or constant
// (token.CONST) specifications.
func (p *Package) Values(kind token.Token) []*ast.ValueSpec {
	var result []*ast.ValueSpec
	for _, file := range p.Files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != kind {
				continue
			}
			for _, specification := range general.Specs {
				result = append(result, specification.(*ast.ValueSpec))
			}
		}
	}
	return result
}

// Fields returns the fields of the struct type name, from the field name to
// the type expression. An embedded field has the name of its type, with no
// package and no pointer. Fields returns nil when name is not a struct type.
func (p *Package) Fields(name string) map[string]string {
	typeSpec := p.Type(name)
	if typeSpec == nil {
		return nil
	}
	structure, ok := typeSpec.Type.(*ast.StructType)
	if !ok {
		return nil
	}
	fields := map[string]string{}
	for _, field := range structure.Fields.List {
		typeName := types.ExprString(field.Type)
		if len(field.Names) == 0 {
			embedded := strings.TrimPrefix(typeName, "*")
			if index := strings.LastIndexByte(embedded, '.'); index >= 0 {
				embedded = embedded[index+1:]
			}
			fields[embedded] = typeName
		}
		for _, identifier := range field.Names {
			fields[identifier.Name] = typeName
		}
	}
	return fields
}

// Receiver returns the receiver type of function with no type parameters,
// for example "*Decoder". It returns "" for a function that is not a method.
func Receiver(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	expression := function.Recv.List[0].Type
	pointer := ""
	if star, ok := expression.(*ast.StarExpr); ok {
		pointer, expression = "*", star.X
	}
	switch typed := expression.(type) {
	case *ast.IndexExpr:
		expression = typed.X
	case *ast.IndexListExpr:
		expression = typed.X
	}
	return pointer + types.ExprString(expression)
}

// ReceiverName returns the name of the receiver of function, or "".
func ReceiverName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
}

// Signature returns the type of function with no parameter names, for
// example "func(reflect.Type) *arshaler".
func Signature(function *ast.FuncType) string {
	return types.ExprString(&ast.FuncType{
		TypeParams: unnamed(function.TypeParams),
		Params:     unnamed(function.Params),
		Results:    unnamed(function.Results),
	})
}

// unnamed returns a copy of list with one field with no name for each name.
func unnamed(list *ast.FieldList) *ast.FieldList {
	if list == nil {
		return nil
	}
	result := &ast.FieldList{}
	for _, field := range list.List {
		count := max(len(field.Names), 1)
		for range count {
			result.List = append(result.List, &ast.Field{Type: field.Type})
		}
	}
	return result
}

// MethodCall is a call of the form X.Name(...), where X is an expression.
type MethodCall struct {
	// Call is the call expression.
	Call *ast.CallExpr
	// Receiver is the expression X, as Go source.
	Receiver string
	// Name is the method name.
	Name string
}

// MethodCalls returns, in source order, all the calls in node of the form
// X.Name(...). The result includes calls of package functions (X is then the
// package name).
func MethodCalls(node ast.Node) []MethodCall {
	var result []MethodCall
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			result = append(result, MethodCall{Call: call, Receiver: types.ExprString(selector.X), Name: selector.Sel.Name})
		}
		return true
	})
	return result
}

// MethodsCalledOn returns the names of the methods that node calls on the
// expression receiver (Go source, for example "b.rd"), in source order.
func MethodsCalledOn(node ast.Node, receiver string) []string {
	var result []string
	for _, call := range MethodCalls(node) {
		if call.Receiver == receiver {
			result = append(result, call.Name)
		}
	}
	return result
}

// FuncCalls returns, in source order, the names of the functions that node
// calls by an identifier (for example "makeString" in makeString(c, b)).
func FuncCalls(node ast.Node) []string {
	var result []string
	ast.Inspect(node, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if identifier, ok := call.Fun.(*ast.Ident); ok {
				result = append(result, identifier.Name)
			}
		}
		return true
	})
	return result
}

// String returns the Go source of expression.
func String(expression ast.Expr) string {
	return types.ExprString(expression)
}
