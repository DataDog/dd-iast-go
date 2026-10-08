// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package io_test

import (
	"bufio"
	"go/ast"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/sourceshape"
	"github.com/stretchr/testify/require"
)

// TestReaderWrapperShape checks the reader wrappers of the standard library
// that the exclusive reader bindings use (see the reader binding rules in the
// internal/taint/store package doc). A retargetable wrapper has a Reset method
// or an exported reader field: it needs a Read guard. The other wrappers keep
// their input in an unexported field, thus user code cannot change it. A
// change fails this test, so that a person examines rule (a) again.
func TestReaderWrapperShape(t *testing.T) {
	_, ok := reflect.TypeFor[*bufio.Reader]().MethodByName("Reset")
	require.True(t, ok, "bufio.Reader has no Reset method")

	field, ok := reflect.TypeFor[io.LimitedReader]().FieldByName("R")
	require.True(t, ok, "io.LimitedReader has no field R")
	require.True(t, field.IsExported())
	require.Equal(t, reflect.TypeFor[io.Reader](), field.Type)

	for name, reader := range map[string]io.Reader{
		"io.TeeReader":        io.TeeReader(strings.NewReader(""), io.Discard),
		"io.MultiReader":      io.MultiReader(strings.NewReader("")),
		"http.MaxBytesReader": http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(strings.NewReader("")), 1),
	} {
		pointer := reflect.TypeOf(reader)
		require.Equal(t, reflect.Pointer, pointer.Kind(), name)
		structure := pointer.Elem()
		require.Equal(t, reflect.Struct, structure.Kind(), name)
		require.False(t, ast.IsExported(structure.Name()), "the result type of %s is exported: %s", name, structure)
		for index := range structure.NumField() {
			require.False(t, structure.Field(index).IsExported(), "the result type of %s has the exported field %s", name, structure.Field(index).Name)
		}
		_, reset := pointer.MethodByName("Reset")
		require.False(t, reset, "the result type of %s has a Reset method", name)
	}
}

// TestReadGuardShape checks the standard library code that the Read guard
// of io.LimitReader and bufio relies on, and that the wrappers and io.ReadAll
// read their input only with Read.
func TestReadGuardShape(t *testing.T) {
	t.Run("bufio", testBufioGuardShape)
	t.Run("io", testIOGuardShape)
	t.Run("net/http", testHTTPGuardShape)
}

// loadShape parses the standard library package importPath. These packages
// have no JSON variant.
func loadShape(t *testing.T, importPath string) *sourceshape.Package {
	t.Helper()
	pkg, err := sourceshape.Load(importPath, false)
	require.NoError(t, err)
	return pkg
}

// requireFunc returns the function receiver.name of pkg, with the type
// signature.
func requireFunc(t *testing.T, pkg *sourceshape.Package, receiver, name, signature string) *ast.FuncDecl {
	t.Helper()
	function := pkg.Func(receiver, name)
	require.NotNil(t, function, "%s has no function %s.%s", pkg.ImportPath, receiver, name)
	require.Equal(t, signature, sourceshape.Signature(function.Type), "%s %s.%s", pkg.ImportPath, receiver, name)
	return function
}

// requireReadsOnlyWithRead checks that function calls the method Read of the
// expression input (Go source, the receiver name is "$"), and no other
// method of it.
func requireReadsOnlyWithRead(t *testing.T, function *ast.FuncDecl, input string) {
	t.Helper()
	input = strings.ReplaceAll(input, "$", sourceshape.ReceiverName(function))
	require.Equal(t, []string{"Read"}, slices.Compact(sourceshape.MethodsCalledOn(function.Body, input)),
		"%s.%s does not read %s only with Read", sourceshape.Receiver(function), function.Name.Name, input)
}

func testBufioGuardShape(t *testing.T) {
	pkg := loadShape(t, "bufio")
	reset := requireFunc(t, pkg, "*Reader", "reset", "func([]byte, io.Reader)")
	requireFunc(t, pkg, "*Reader", "Reset", "func(io.Reader)")
	newReaderSize := requireFunc(t, pkg, "", "NewReaderSize", "func(io.Reader, int) *Reader")
	read := requireFunc(t, pkg, "*Reader", "Read", "func([]byte) (int, error)")

	// The only change of the field rd is the assignment of a Reader literal
	// in reset. No method of Reader assigns a complete Reader in another
	// function.
	for _, function := range pkg.Funcs() {
		key := sourceshape.Receiver(function) + "." + function.Name.Name
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				for _, target := range typed.Lhs {
					if selector, ok := target.(*ast.SelectorExpr); ok && selector.Sel.Name == "rd" {
						t.Errorf("%s assigns the field rd", key)
					}
					if _, ok := target.(*ast.StarExpr); ok && sourceshape.Receiver(function) == "*Reader" && key != "*Reader.reset" {
						t.Errorf("%s assigns a complete Reader", key)
					}
				}
			case *ast.CompositeLit:
				for _, element := range typed.Elts {
					if pair, ok := element.(*ast.KeyValueExpr); ok && sourceshape.String(pair.Key) == "rd" && key != "*Reader.reset" {
						t.Errorf("%s makes a Reader literal with the field rd", key)
					}
				}
			}
			return true
		})
	}

	// reset: *b = Reader{buf: buf, rd: r, ...}, with no field r or w: the
	// buffer is discarded.
	require.Len(t, reset.Body.List, 1)
	assignment, ok := reset.Body.List[0].(*ast.AssignStmt)
	require.True(t, ok, "reset is not one assignment")
	require.Equal(t, "*"+sourceshape.ReceiverName(reset), sourceshape.String(assignment.Lhs[0]))
	literal, ok := assignment.Rhs[0].(*ast.CompositeLit)
	require.True(t, ok)
	require.Equal(t, "Reader", sourceshape.String(literal.Type))
	keys := map[string]string{}
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		require.True(t, ok, "the Reader literal of reset has an element with no key")
		keys[sourceshape.String(pair.Key)] = sourceshape.String(pair.Value)
	}
	require.Equal(t, "r", keys["rd"], "reset does not set rd to its argument")
	require.NotContains(t, keys, "r", "reset sets the read position")
	require.NotContains(t, keys, "w", "reset sets the write position")

	// reset has exactly two callers: Reset and NewReaderSize.
	var callers []string
	for _, function := range pkg.Funcs() {
		for _, call := range sourceshape.MethodCalls(function.Body) {
			if call.Name == "reset" {
				callers = append(callers, sourceshape.Receiver(function)+"."+function.Name.Name)
			}
		}
	}
	require.ElementsMatch(t, []string{"*Reader.Reset", ".NewReaderSize"}, callers)

	// NewReaderSize returns its argument when it is a *Reader of enough
	// size: b, ok := rd.(*Reader); if ok && len(b.buf) >= size { return b }.
	require.GreaterOrEqual(t, len(newReaderSize.Body.List), 2)
	first, ok := newReaderSize.Body.List[0].(*ast.AssignStmt)
	require.True(t, ok)
	require.Equal(t, "b, ok = rd.(*Reader)", sourceshape.String(first.Lhs[0])+", "+sourceshape.String(first.Lhs[1])+" = "+sourceshape.String(first.Rhs[0]))
	second, ok := newReaderSize.Body.List[1].(*ast.IfStmt)
	require.True(t, ok)
	require.Equal(t, "ok && len(b.buf) >= size", sourceshape.String(second.Cond))
	require.Len(t, second.Body.List, 1)
	result, ok := second.Body.List[0].(*ast.ReturnStmt)
	require.True(t, ok)
	require.Len(t, result.Results, 1)
	require.Equal(t, "b", sourceshape.String(result.Results[0]))

	// (*Reader).Read gets bytes only from b.buf[b.r:b.w] and b.rd.Read.
	requireReadsOnlyWithRead(t, read, "$.rd")
	receiver := sourceshape.ReceiverName(read)
	for _, call := range sourceshape.MethodCalls(read.Body) {
		if call.Receiver == receiver {
			require.Contains(t, []string{"Buffered", "readErr"}, call.Name, "(*Reader).Read calls the method %s", call.Name)
		}
	}
	copies := 0
	ast.Inspect(read.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && sourceshape.String(call.Fun) == "copy" {
			copies++
			require.Equal(t, strings.ReplaceAll("copy(p, $.buf[$.r:$.w])", "$", receiver), sourceshape.String(call))
		}
		return true
	})
	require.Equal(t, 1, copies)
}

func testIOGuardShape(t *testing.T) {
	pkg := loadShape(t, "io")
	requireReadsOnlyWithRead(t, requireFunc(t, pkg, "*LimitedReader", "Read", "func([]byte) (int, error)"), "$.R")
	requireReadsOnlyWithRead(t, requireFunc(t, pkg, "*teeReader", "Read", "func([]byte) (int, error)"), "$.r")
	requireReadsOnlyWithRead(t, requireFunc(t, pkg, "*multiReader", "Read", "func([]byte) (int, error)"), "$.readers[0]")
	requireReadsOnlyWithRead(t, requireFunc(t, pkg, "", "ReadAll", "func(Reader) ([]byte, error)"), "r")
	requireFunc(t, pkg, "", "TeeReader", "func(Reader, Writer) Reader")
	requireFunc(t, pkg, "", "MultiReader", "func(...Reader) Reader")

	// LimitReader returns &LimitedReader{r, n}.
	limitReader := requireFunc(t, pkg, "", "LimitReader", "func(Reader, int64) Reader")
	require.Len(t, limitReader.Body.List, 1)
	result, ok := limitReader.Body.List[0].(*ast.ReturnStmt)
	require.True(t, ok)
	require.Len(t, result.Results, 1)
	address, ok := result.Results[0].(*ast.UnaryExpr)
	require.True(t, ok)
	literal, ok := address.X.(*ast.CompositeLit)
	require.True(t, ok)
	require.Equal(t, "LimitedReader", sourceshape.String(literal.Type))
	require.Len(t, literal.Elts, 2)
	require.Equal(t, "r", sourceshape.String(literal.Elts[0]))
	require.Equal(t, "n", sourceshape.String(literal.Elts[1]))
}

func testHTTPGuardShape(t *testing.T) {
	pkg := loadShape(t, "net/http")
	requireFunc(t, pkg, "", "MaxBytesReader", "func(ResponseWriter, io.ReadCloser, int64) io.ReadCloser")
	requireReadsOnlyWithRead(t, requireFunc(t, pkg, "*maxBytesReader", "Read", "func([]byte) (int, error)"), "$.r")
}
