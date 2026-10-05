// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build go1.27 && goexperiment.jsonv2

package json

import (
	"go/ast"
	"go/token"
	"slices"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/sourceshape"
	"github.com/stretchr/testify/require"
)

// TestSourceShape checks the symbols of the v2 files of encoding/json, and of
// encoding/json/v2 and its internal packages, that the [shared] and [v2]
// aspects of orchestrion.yml use (plan encoding-json-v2, section 6.4). The
// build tags are the tags of the "[v2] encoding/json/v2 string unmarshal
// source" aspect: its anchor errInvalidStringTag exists only in Go 1.27.
func TestSourceShape(t *testing.T) {
	t.Run("encoding/json", testShapeJSON)
	t.Run("encoding/json/v2", testShapeV2)
	t.Run("encoding/json/jsontext", testShapeJSONText)
	t.Run("encoding/json/internal", testShapeInternal)
}

// shapeTarget is a function or a method, with its type.
type shapeTarget struct{ receiver, name, signature string }

// requireTargets checks that pkg declares each target with its type.
func requireTargets(t *testing.T, pkg *sourceshape.Package, targets ...shapeTarget) {
	t.Helper()
	for _, target := range targets {
		function := pkg.Func(target.receiver, target.name)
		if function == nil {
			t.Errorf("%s has no function %s.%s", pkg.ImportPath, target.receiver, target.name)
			continue
		}
		if got := sourceshape.Signature(function.Type); got != target.signature {
			t.Errorf("%s %s.%s has the type %q, want %q", pkg.ImportPath, target.receiver, target.name, got, target.signature)
		}
	}
}

// requireFields checks that the struct type typeName of pkg has each field
// of want with its type.
func requireFields(t *testing.T, pkg *sourceshape.Package, typeName string, want map[string]string) {
	t.Helper()
	fields := pkg.Fields(typeName)
	if fields == nil {
		t.Errorf("%s has no struct type %s", pkg.ImportPath, typeName)
		return
	}
	for field, fieldType := range want {
		if got := fields[field]; got != fieldType {
			t.Errorf("%s field %s.%s has the type %q, want %q", pkg.ImportPath, typeName, field, got, fieldType)
		}
	}
}

// loadShape parses the package importPath of this variant.
func loadShape(t *testing.T, importPath string) *sourceshape.Package {
	t.Helper()
	pkg, err := sourceshape.Load(importPath, variantJSONv2)
	require.NoError(t, err)
	require.NotEmpty(t, pkg.Files, "%s has no file in this variant", importPath)
	return pkg
}

// testShapeJSON checks the v2 files of encoding/json: the NewDecoder capture
// and the Decode value document (plan sections 6.3 and 6.7).
func testShapeJSON(t *testing.T) {
	pkg := loadShape(t, "encoding/json")
	requireTargets(t, pkg,
		shapeTarget{"", "NewDecoder", "func(io.Reader) *Decoder"},
		shapeTarget{"*Decoder", "Decode", "func(any) error"},
		shapeTarget{"", "checkValid", "func([]byte) error"},
		shapeTarget{"*Number", "UnmarshalJSONFrom", "func(*jsontext.Decoder) error"},
	)
	requireFields(t, pkg, "Decoder", map[string]string{"dec": "*jsontext.Decoder"})
	require.Nil(t, pkg.Type("decodeState"), "the v2 files of encoding/json declare decodeState: the [v1] aspects can match")

	// NewDecoder hides a *bytes.Buffer from jsontext. Thus the jsontext
	// decoder reads the reader with Read (see testShapeJSONText).
	newDecoder := pkg.Func("", "NewDecoder")
	require.NotNil(t, newDecoder)
	hides := false
	ast.Inspect(newDecoder.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || sourceshape.String(assignment.Lhs[0]) != "r" {
			return true
		}
		literal, ok := assignment.Rhs[0].(*ast.CompositeLit)
		if ok && sourceshape.String(literal.Type) == "struct{io.Reader}" && len(literal.Elts) == 1 && sourceshape.String(literal.Elts[0]) == "r" {
			hides = true
		}
		return true
	})
	require.True(t, hides, "NewDecoder does not wrap a *bytes.Buffer reader in struct{ io.Reader }")

	// The ReadValue calls that the method-call join point matches. Only the
	// call in (*Decoder).Decode reads the stream of the Decoder. The template
	// changes only a call in a function with the name Decode.
	calls := map[string]int{}
	inDecode := 0
	for _, function := range pkg.Funcs() {
		if function.Body == nil {
			continue
		}
		key := sourceshape.Receiver(function) + "." + function.Name.Name
		for _, call := range sourceshape.MethodCalls(function.Body) {
			if call.Name != "ReadValue" {
				continue
			}
			calls[key]++
			if function.Name.Name == "Decode" {
				inDecode++
				require.Equal(t, "*Decoder", sourceshape.Receiver(function), "a ReadValue call is in a Decode function that is not (*Decoder).Decode")
				require.Equal(t, sourceshape.ReceiverName(function)+".dec", call.Receiver, "the ReadValue call of (*Decoder).Decode does not read the jsontext.Decoder field dec")
				require.Empty(t, call.Call.Args)
			}
		}
	}
	require.Equal(t, map[string]int{"*Decoder.Decode": 1, ".checkValid": 1, "*Number.UnmarshalJSONFrom": 1}, calls)
	require.Equal(t, 1, inDecode)
}

// testShapeV2 checks encoding/json/v2: the string arshaler wrap, the string
// cache guard, and the string unmarshal source (plan section 6.2).
func testShapeV2(t *testing.T) {
	pkg := loadShape(t, "encoding/json/v2")
	requireTargets(t, pkg,
		shapeTarget{"", "makeStringArshaler", "func(reflect.Type) *arshaler"},
		shapeTarget{"", "makeString", "func(*stringCache, []byte) string"},
	)
	requireFields(t, pkg, "arshaler", map[string]string{"unmarshal": "unmarshaler"})
	requireFields(t, pkg, "addressableValue", map[string]string{"Value": "reflect.Value"})
	unmarshaler := pkg.Type("unmarshaler")
	require.NotNil(t, unmarshaler, "encoding/json/v2 has no type unmarshaler")
	require.Equal(t, "func(*jsontext.Decoder, addressableValue, *jsonopts.Struct) error", sourceshape.String(unmarshaler.Type))
	for _, name := range []string{"export", "errInvalidStringTag"} {
		require.NotNil(t, pkg.Var(name), "encoding/json/v2 has no package variable %s", name)
	}
	require.Equal(t, "jsontext.Internal.Export(&internal.AllowInternalUse)", sourceshape.String(pkg.Var("export").Values[0]))

	// The default string unmarshal closure: fncs.unmarshal = func(...) {...}.
	arshaler := pkg.Func("", "makeStringArshaler")
	require.NotNil(t, arshaler)
	var closure *ast.FuncLit
	ast.Inspect(arshaler.Body, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 && sourceshape.String(assignment.Lhs[0]) == "fncs.unmarshal" {
			closure, _ = assignment.Rhs[0].(*ast.FuncLit)
		}
		return true
	})
	require.NotNil(t, closure, "makeStringArshaler sets no unmarshal closure")
	require.Equal(t, "func(*jsontext.Decoder, addressableValue, *jsonopts.Struct) error", sourceshape.Signature(closure.Type))
	checkStringUnmarshalClosure(t, closure)

	// The init function of the [v2] string unmarshal source sets the wrapper.
	// No arshaler must exist before it runs: no package-level initializer
	// calls lookupArshaler, directly or through other functions.
	checkNoInitializerCalls(t, pkg, "lookupArshaler")
}

// checkStringUnmarshalClosure checks the default string unmarshal closure of
// encoding/json/v2. The wrapper reads PreviousTokenOrValue after the closure
// returned: it is the raw string token only when xd.ReadValue(&flags) is the
// last decoder read. The ,string test of the wrapper is the null test of the
// closure, right after the first UnquoteMayCopy.
func checkStringUnmarshalClosure(t *testing.T, closure *ast.FuncLit) {
	t.Helper()
	decoders := []string{closure.Type.Params.List[0].Names[0].Name, "xd"}
	readValue := token.NoPos
	setString := false
	for _, call := range sourceshape.MethodCalls(closure.Body) {
		switch {
		case call.Receiver == "xd" && call.Name == "ReadValue":
			require.Equal(t, token.NoPos, readValue, "the closure has more than one xd.ReadValue call")
			require.Len(t, call.Call.Args, 1)
			require.Equal(t, "&flags", sourceshape.String(call.Call.Args[0]))
			readValue = call.Call.Pos()
		case slices.Contains(decoders, call.Receiver) && readValue.IsValid() && call.Call.Pos() > readValue:
			switch call.Name {
			case "ReadValue", "ReadToken", "SkipValue", "PeekKind", "SkipValueRemainder", "SkipUntil":
				t.Errorf("the closure calls %s.%s after xd.ReadValue", call.Receiver, call.Name)
			}
		case call.Receiver == "va" && call.Name == "SetString" && len(call.Call.Args) == 1 && sourceshape.String(call.Call.Args[0]) == "str":
			setString = true
		}
	}
	require.True(t, readValue.IsValid(), "the closure has no xd.ReadValue(&flags) call")
	require.True(t, setString, "the closure has no va.SetString(str) call")
	ast.Inspect(closure.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && call.Pos() > readValue {
			if identifier, ok := call.Fun.(*ast.Ident); ok && (identifier.Name == "newUnmarshalErrorAfterWithSkipping" || identifier.Name == "newUnmarshalErrorBeforeWithSkipping") {
				t.Errorf("the closure calls %s after xd.ReadValue", identifier.Name)
			}
		}
		return true
	})

	// val = jsonwire.UnquoteMayCopy(val, flags.IsVerbatim()), then
	// if stringify { if string(val) == "null" { ... } ... }.
	found := false
	ast.Inspect(closure.Body, func(node ast.Node) bool {
		var list []ast.Stmt
		switch typed := node.(type) {
		case *ast.BlockStmt:
			list = typed.List
		case *ast.CaseClause:
			list = typed.Body
		default:
			return true
		}
		for index, statement := range list {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || len(assignment.Rhs) != 1 {
				continue
			}
			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if !ok || sourceshape.String(call.Fun) != "jsonwire.UnquoteMayCopy" {
				continue
			}
			require.False(t, found, "the closure has more than one UnquoteMayCopy call")
			found = true
			require.Equal(t, "val = jsonwire.UnquoteMayCopy(val, flags.IsVerbatim())", sourceshape.String(assignment.Lhs[0])+" = "+sourceshape.String(call))
			require.Less(t, index+1, len(list), "no statement follows UnquoteMayCopy")
			stringify, ok := list[index+1].(*ast.IfStmt)
			require.True(t, ok, "the statement after UnquoteMayCopy is not an if statement")
			require.Equal(t, "stringify", sourceshape.String(stringify.Cond))
			require.NotEmpty(t, stringify.Body.List)
			null, ok := stringify.Body.List[0].(*ast.IfStmt)
			require.True(t, ok, "the first statement of the stringify branch is not an if statement")
			require.Equal(t, `string(val) == "null"`, sourceshape.String(null.Cond))
		}
		return true
	})
	require.True(t, found, "the closure has no UnquoteMayCopy assignment")

	// The stringify rule of the closure is the rule of the wrapper:
	// if uo.Flags.Has(jsonflags.TagFlags) { stringify = ...; ... }.
	rule := false
	ast.Inspect(closure.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.IfStmt)
		if !ok || sourceshape.String(statement.Cond) != "uo.Flags.Has(jsonflags.TagFlags)" || len(statement.Body.List) == 0 {
			return true
		}
		assignment, ok := statement.Body.List[0].(*ast.AssignStmt)
		if ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 && sourceshape.String(assignment.Lhs[0]) == "stringify" &&
			sourceshape.String(assignment.Rhs[0]) == "uo.Flags.Get(jsonflags.StringTag) && uo.Flags.Get(jsonflags.StringifyWithLegacySemantics)" {
			rule = true
		}
		return true
	})
	require.True(t, rule, "the stringify rule of the closure changed")
}

// checkNoInitializerCalls checks that no package-level variable initializer
// and no init function of pkg calls target, directly or through the
// functions and the package-level variables of pkg.
//
// The check is conservative. A function or a variable "reaches" target when
// its body or its initializer refers to target, or to a name that reaches
// target, also as a value (not only as a call) and also in a function
// literal. Thus a function value in a variable, a field, or an argument does
// not hide a call. An initializer or an init function must not refer to a
// name that reaches target. One exception: the body of a function literal
// that is all the initializer of a variable does not run at initialization;
// only a later reference to the variable can call it. A method or a field is
// identified by its name only, thus the check can report a false finding,
// but it does not miss a call.
func checkNoInitializerCalls(t *testing.T, pkg *sourceshape.Package, target string) {
	t.Helper()
	refers := map[string][]string{}
	for _, function := range pkg.Funcs() {
		// A package init function has no name that code can refer to. A
		// method named init is an ordinary method, thus it is in the graph.
		if function.Body != nil && (function.Name.Name != "init" || function.Recv != nil) {
			refers[function.Name.Name] = append(refers[function.Name.Name], referredNames(function.Body)...)
		}
	}
	variables := pkg.Values(token.VAR)
	for _, specification := range variables {
		var names []string
		for _, value := range specification.Values {
			names = append(names, referredNames(value)...)
		}
		for _, name := range specification.Names {
			if name.Name == "_" {
				continue
			}
			refers[name.Name] = append(refers[name.Name], names...)
		}
	}
	reaches := map[string]bool{target: true}
	for changed := true; changed; {
		changed = false
		for name, referred := range refers {
			if !reaches[name] && slices.ContainsFunc(referred, func(other string) bool { return reaches[other] }) {
				reaches[name], changed = true, true
			}
		}
	}
	check := func(where string, node ast.Node) {
		if _, stored := node.(*ast.FuncLit); stored {
			return
		}
		for _, name := range referredNames(node) {
			if reaches[name] {
				t.Errorf("%s refers to %s, which can call %s", where, name, target)
			}
		}
	}
	for _, specification := range variables {
		for _, value := range specification.Values {
			check("the initializer of "+specification.Names[0].Name, value)
		}
	}
	for _, function := range pkg.Funcs() {
		if function.Name.Name == "init" && function.Recv == nil {
			check("an init function", function.Body)
		}
	}
}

// referredNames returns all the identifiers in node, also the selected
// names of selector expressions and the identifiers in function literals,
// but not the blank identifier.
func referredNames(node ast.Node) []string {
	var result []string
	ast.Inspect(node, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok && identifier.Name != "_" {
			result = append(result, identifier.Name)
		}
		return true
	})
	return result
}

// testShapeJSONText checks encoding/json/jsontext: the raw token of the
// wrapper, the Decoder methods that the aspects and the v2 Decode path use,
// and the Read of the stream reader (plan sections 6.2, 6.3, and 6.6).
func testShapeJSONText(t *testing.T) {
	pkg := loadShape(t, "encoding/json/jsontext")
	requireTargets(t, pkg,
		shapeTarget{"*decodeBuffer", "PreviousTokenOrValue", "func() []byte"},
		shapeTarget{"export", "Decoder", "func(*Decoder) *decoderState"},
		shapeTarget{"*Decoder", "ReadValue", "func() (Value, error)"},
		shapeTarget{"*Decoder", "InputOffset", "func() int64"},
		shapeTarget{"*Decoder", "UnreadBuffer", "func() []byte"},
		shapeTarget{"", "AppendUnquote", "func([]byte, Bytes) ([]byte, error)"},
		shapeTarget{"*decoderState", "fetch", "func() error"},
	)
	requireFields(t, pkg, "decoderState", map[string]string{"decodeBuffer": "decodeBuffer", "Struct": "jsonopts.Struct"})
	requireFields(t, pkg, "decodeBuffer", map[string]string{"rd": "io.Reader"})
	require.NotNil(t, pkg.Var("Internal"), "jsontext has no variable Internal")

	// fetch reads the stream reader only with Read.
	fetch := pkg.Func("*decoderState", "fetch")
	require.NotNil(t, fetch)
	methods := sourceshape.MethodsCalledOn(fetch.Body, sourceshape.ReceiverName(fetch)+".rd")
	require.Equal(t, []string{"Read"}, methods, "fetch calls other methods of the stream reader than Read")
}

// testShapeInternal checks the jsonflags and jsonopts symbols of the wrapper.
func testShapeInternal(t *testing.T) {
	flags := loadShape(t, "encoding/json/internal/jsonflags")
	for _, name := range []string{"StringTag", "StringifyWithLegacySemantics", "TagFlags"} {
		require.NotNil(t, flags.Const(name), "jsonflags has no constant %s", name)
	}
	requireTargets(t, flags,
		shapeTarget{"Flags", "Has", "func(Bools) bool"},
		shapeTarget{"Flags", "Get", "func(Bools) bool"},
	)
	requireFields(t, loadShape(t, "encoding/json/internal/jsonopts"), "Struct", map[string]string{"Flags": "jsonflags.Flags"})
}
