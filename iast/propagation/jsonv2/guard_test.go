// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package jsonv2_test

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The guard tests of this file check the rules of plan section 6.1 (rules 3
// and 6) for the hooks of orchestrion.yml (the same tests as in
// iast/propagation/stream):
//
//   - TestStdlibDrift, TestAppendUnquoteCopy, TestFetchCopy and
//     TestAspectCount read the source of the toolchain and of this package.
//     They need no weaving, and they run on all variants (the source of the
//     v2 files is read with any build constraint).
//   - The other tests build testdata/hooked (woven and not woven) and read the
//     output of the compiler and of the linker. They run only in the woven
//     test run, and not in -short mode.

var updateDrift = flag.Bool("update-drift", false, "write the golden file of the standard library inventory of the current Go minor version")

// hookRef names one function of the standard library. recv is the receiver
// type as written in the source ("*decoderState"), empty for a function.
type hookRef struct {
	pkg, recv, name string
}

// String returns the name that the compiler prints: "(*decoderState).fetch".
func (h hookRef) String() string {
	if h.recv == "" {
		return h.name
	}
	return "(" + h.recv + ")." + h.name
}

// Full returns the name with the package.
func (h hookRef) Full() string { return h.pkg + "." + h.String() }

const (
	pkgJSON     = "encoding/json"
	pkgJSONWire = "encoding/json/internal/jsonwire"
	pkgJSONText = "encoding/json/jsontext"
	pkgJSONV2   = "encoding/json/v2"
)

// hookedFuncs are the 3 hooked functions of orchestrion.yml.
var hookedFuncs = []hookRef{
	{pkgJSONWire, "", "AppendUnquote"},
	{pkgJSONText, "*decoderState", "fetch"},
	{pkgJSONV2, "", "makeString"},
}

// dependencyFuncs are the functions that the twins copy or depend on, but
// that are not hooked:
//
//   - the call paths of the encoding/json facade (Unmarshal, NewDecoder,
//     Decode, Token) and of encoding/json/v2 Unmarshal: the values are
//     decoded in place (getBufferedDecoder, reset: no copy);
//   - UnquoteMayCopy, the string arshaler, unmarshalValueAny and
//     (Token).string: the strings are a part of the raw token, or the result
//     of AppendUnquote, then makeString;
//   - jsontext AppendUnquote: it calls jsonwire AppendUnquote;
//   - previousOffsetEnd and copyQuotedBuffer: the twin of fetch calls them;
//   - invalidatePreviousRead: it writes one byte into the buffer (the bits
//     of this byte do not change).
var dependencyFuncs = []hookRef{
	{pkgJSON, "", "Unmarshal"},
	{pkgJSON, "", "NewDecoder"},
	{pkgJSON, "*Decoder", "Decode"},
	{pkgJSON, "*Decoder", "Token"},
	{pkgJSONWire, "", "UnquoteMayCopy"},
	{pkgJSONText, "", "AppendUnquote"},
	{pkgJSONText, "", "getBufferedDecoder"},
	{pkgJSONText, "*decoderState", "reset"},
	{pkgJSONText, "*decodeBuffer", "previousOffsetEnd"},
	{pkgJSONText, "*decodeBuffer", "invalidatePreviousRead"},
	{pkgJSONText, "*objectNameStack", "copyQuotedBuffer"},
	{pkgJSONText, "Token", "string"},
	{pkgJSONV2, "", "Unmarshal"},
	{pkgJSONV2, "", "makeStringArshaler"},
	{pkgJSONV2, "", "unmarshalValueAny"},
}

// structTypes are the struct types whose fields the twins use (and the
// compile-time checks of the declarations of orchestrion.yml).
var structTypes = []struct{ pkg, name string }{
	{pkgJSON, "Decoder"},
	{pkgJSONText, "decodeBuffer"},
	{pkgJSONText, "decoderState"},
	{pkgJSONText, "ioError"},
}

// stdlibPackages are the packages of the inventory. The hooks are in the
// last 3 (the hookedPackages).
var (
	stdlibPackages = []string{pkgJSON, pkgJSONWire, pkgJSONText, pkgJSONV2}
	hookedPackages = []string{pkgJSONWire, pkgJSONText, pkgJSONV2}
)

const hookedProgram = "./iast/propagation/jsonv2/testdata/hooked"

func goroot(t testing.TB) string {
	t.Helper()
	if out, err := exec.Command("go", "env", "GOROOT").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOROOT()
}

// stdlibFiles parses the source files (without the tests, and with any build
// constraint) of the v2 implementation in the standard library package pkg:
// all the files of the packages under encoding/json/, and only the files with
// the prefix "v2_" of encoding/json. The files are in the order of their
// names.
func stdlibFiles(t testing.TB, pkg string) (*token.FileSet, map[string]*ast.File, []string) {
	t.Helper()
	dir := filepath.Join(goroot(t), "src", filepath.FromSlash(pkg))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if pkg == pkgJSON && !strings.HasPrefix(name, "v2_") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		require.NoError(t, err, "parse %s/%s", pkg, name)
		files[name] = f
		names = append(names, name)
	}
	require.NotEmpty(t, names, "no v2 source in %s", pkg)
	sort.Strings(names)
	return fset, files, names
}

// receiverName returns the receiver type of fd as written ("*decoderState"),
// or "".
func receiverName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	switch x := fd.Recv.List[0].Type.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return "*" + id.Name
		}
	case *ast.IndexExpr: // a generic type
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return "?"
}

// findFuncs returns the declarations of h in the package files.
func findFuncs(files map[string]*ast.File, names []string, h hookRef) (found []*ast.FuncDecl, in []string) {
	for _, name := range names {
		for _, d := range files[name].Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == h.name && receiverName(fd) == h.recv && fd.Body != nil {
				found = append(found, fd)
				in = append(in, name)
			}
		}
	}
	return found, in
}

// goMinor returns the minor version ("go1.27") of the toolchain at goroot,
// or "go1.28-devel" for a development version.
func goMinor(t *testing.T, goroot string) string {
	t.Helper()
	v := ""
	if b, err := os.ReadFile(filepath.Join(goroot, "VERSION")); err == nil {
		v = strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)[0]
	} else if out, err := exec.Command(filepath.Join(goroot, "bin", "go"), "env", "GOVERSION").Output(); err == nil {
		v = strings.TrimSpace(string(out))
	} else {
		t.Fatalf("cannot find the Go version of %s", goroot)
	}
	if m := regexp.MustCompile(`^(?:devel )?(go1\.\d+)(-devel)?`).FindStringSubmatch(v); m != nil {
		if m[2] != "" || strings.HasPrefix(v, "devel ") {
			return m[1] + "-devel"
		}
		return m[1]
	}
	return strings.Fields(v)[0]
}

// stdlibInventory returns the inventory of the standard library code that the
// hooks depend on: the printed code (without comments) of the hooked
// functions and of the functions that the twins copy or depend on, and the
// struct types whose fields the twins use. The order is fixed.
func stdlibInventory(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	out.WriteString("# Inventory of the standard library code that the hooks of orchestrion.yml\n")
	out.WriteString("# depend on (TestStdlibDrift). Update with -update-drift after a review.\n")
	for _, pkg := range stdlibPackages {
		fset, files, names := stdlibFiles(t, pkg)
		var refs []hookRef
		for _, h := range slices.Concat(hookedFuncs, dependencyFuncs) {
			if h.pkg == pkg {
				refs = append(refs, h)
			}
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
		for _, h := range refs {
			decls, in := findFuncs(files, names, h)
			require.NotEmpty(t, decls, "%s not found in the source of %s", h.Full(), pkg)
			for i, fd := range decls {
				fmt.Fprintf(&out, "\n## func %s (%s)\n", h.Full(), in[i])
				for _, l := range printNode(fset, fd) {
					out.WriteString(l + "\n")
				}
			}
		}
		var types []string
		for _, s := range structTypes {
			if s.pkg == pkg {
				types = append(types, s.name)
			}
		}
		sort.Strings(types)
		for _, name := range types {
			found := false
			for _, file := range names {
				for _, d := range files[file].Decls {
					gd, ok := d.(*ast.GenDecl)
					if !ok || gd.Tok != token.TYPE {
						continue
					}
					for _, spec := range gd.Specs {
						ts := spec.(*ast.TypeSpec)
						if _, ok := ts.Type.(*ast.StructType); !ok || ts.Name.Name != name {
							continue
						}
						found = true
						fmt.Fprintf(&out, "\n## type %s.%s (%s)\n", pkg, name, file)
						for _, l := range printNode(fset, ts) {
							out.WriteString(l + "\n")
						}
					}
				}
			}
			require.True(t, found, "struct type %s.%s not found", pkg, name)
		}
	}
	return out.String()
}

// TestStdlibDrift is the drift detector of plan section 6.1 rule 6. It reads
// the source of the v2 implementation of encoding/json of the Go toolchain in
// use (no weaving needed, any GOEXPERIMENT), and compares an inventory of the
// code that the twins copy or depend on with a golden file for the Go minor
// version.
//
// A difference (or a new minor version without a golden file) fails the
// test. It does not mean that the twins are wrong: a human must read the new
// code, decide if the twins in orchestrion.yml are still correct, then update
// the golden file with:
//
//	go test ./iast/propagation/jsonv2 -run TestStdlibDrift -update-drift
func TestStdlibDrift(t *testing.T) {
	root := goroot(t)
	version := goMinor(t, root)
	got := stdlibInventory(t)
	golden := filepath.Join("testdata", "stdlib-"+version+".golden")
	if *updateDrift {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(golden, []byte(got), 0o644))
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("no golden file for %s (%v): read the standard library code of this Go version, re-check the twins in orchestrion.yml, then run with -update-drift", version, err)
	}
	if string(want) != got {
		t.Fatalf("the standard library code that the hooks depend on changed in %s (GOROOT %s).\n"+
			"Re-check the twins in orchestrion.yml against the new code, then run with -update-drift.\n%s",
			version, root, lineDiff(string(want), got))
	}
}

// templateFunc returns the text of the function fn in the templates of
// orchestrion.yml, without the indentation of the YAML block.
func templateFunc(t *testing.T, fn string) string {
	t.Helper()
	data, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	lines := strings.Split(string(data), "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimLeft(l, " "), "func "+fn+"(") {
			start = i
			break
		}
	}
	require.GreaterOrEqual(t, start, 0, "function %s not in orchestrion.yml", fn)
	indent := len(lines[start]) - len(strings.TrimLeft(lines[start], " "))
	var out []string
	for _, l := range lines[start:] {
		if strings.TrimSpace(l) != "" && len(l)-len(strings.TrimLeft(l, " ")) < indent {
			break
		}
		if len(l) >= indent {
			l = l[indent:]
		} else {
			l = strings.TrimSpace(l)
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// parseTemplateFunc parses the function fn of orchestrion.yml.
func parseTemplateFunc(t *testing.T, fn string) (*token.FileSet, *ast.FuncDecl) {
	t.Helper()
	src := templateFunc(t, fn)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "orchestrion.yml", "package p\n\n"+src, parser.SkipObjectResolution)
	require.NoError(t, err, "the template does not parse:\n%s", src)
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == fn {
			return fset, fd
		}
	}
	t.Fatalf("function %s not found in its template", fn)
	return nil, nil
}

// stdlibFunc returns the declaration of h in the standard library source.
func stdlibFunc(t *testing.T, h hookRef) (*token.FileSet, *ast.FuncDecl, string) {
	t.Helper()
	fset, files, names := stdlibFiles(t, h.pkg)
	decls, in := findFuncs(files, names, h)
	require.Len(t, decls, 1, "%s in the source of %s", h.Full(), h.pkg)
	return fset, decls[0], in[0]
}

// appendUnquoteHooked tells if the AppendUnquote aspect applies to the
// toolchain: its AppendUnquote is not generic (Go 1.27 and later; Go 1.26 has
// AppendUnquote[Bytes]).
func appendUnquoteHooked(t *testing.T) bool {
	t.Helper()
	_, fn, _ := stdlibFunc(t, hookRef{pkgJSONWire, "", "AppendUnquote"})
	return fn.Type.TypeParams == nil
}

// TestAppendUnquoteCopy checks that the body of
// __dd_iast_jsonwire_AppendUnquoteBody in orchestrion.yml is an exact copy of
// the body of jsonwire.AppendUnquote of the toolchain (comments and blank
// lines excluded), with the same signature.
func TestAppendUnquoteCopy(t *testing.T) {
	if !appendUnquoteHooked(t) {
		t.Skip("jsonwire.AppendUnquote of this toolchain is generic (Go 1.26): the hook does not apply")
	}
	tfset, tfn := parseTemplateFunc(t, "__dd_iast_jsonwire_AppendUnquoteBody")
	fset, fn, file := stdlibFunc(t, hookRef{pkgJSONWire, "", "AppendUnquote"})
	want := strings.Join(printNode(fset, fn.Body), "\n") + "\n"
	got := strings.Join(printNode(tfset, tfn.Body), "\n") + "\n"
	if want != got {
		t.Fatalf("the template __dd_iast_jsonwire_AppendUnquoteBody is not an exact copy of AppendUnquote (%s of %s).\n"+
			"Copy the new body into orchestrion.yml (and check the twin __dd_iast_jsonwire_AppendUnquote).\n- stdlib, + template\n%s",
			file, goMinor(t, goroot(t)), lineDiff(want, got))
	}
	require.Equal(t, printNode(fset, fn.Type), printNode(tfset, tfn.Type))
}

// TestFetchCopy checks that the twin __dd_iast_jsontext_fetch is the body of
// (*decoderState).fetch with the bit operations only: when the test removes
// the statements of the hook (the calls to a __dd_iast_ function, and the
// definitions of a __dd_iast_ variable), and changes the read rule call
// __dd_iast_jsontext_read(r, p) back to r.Read(p), the body is the same as
// the body of the toolchain (comments and blank lines excluded).
func TestFetchCopy(t *testing.T) {
	tfset, tfn := parseTemplateFunc(t, "__dd_iast_jsontext_fetch")
	fset, fn, file := stdlibFunc(t, hookRef{pkgJSONText, "*decoderState", "fetch"})

	removed, reads := 0, 0
	isHook := func(name string) bool { return strings.HasPrefix(name, "__dd_iast_") }
	var strip func(list []ast.Stmt) []ast.Stmt
	strip = func(list []ast.Stmt) []ast.Stmt {
		var out []ast.Stmt
		for _, s := range list {
			switch x := s.(type) {
			case *ast.ExprStmt:
				if call, ok := x.X.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && isHook(id.Name) {
						removed++
						continue
					}
				}
			case *ast.AssignStmt:
				if id, ok := x.Lhs[0].(*ast.Ident); ok && len(x.Lhs) == 1 && isHook(id.Name) {
					removed++
					continue
				}
			}
			out = append(out, s)
		}
		return out
	}
	ast.Inspect(tfn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BlockStmt:
			x.List = strip(x.List)
		case *ast.CaseClause:
			x.Body = strip(x.Body)
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "__dd_iast_jsontext_read" {
				require.Len(t, x.Args, 2)
				x.Fun = &ast.SelectorExpr{X: x.Args[0], Sel: ast.NewIdent("Read")}
				x.Args = x.Args[1:]
				reads++
			}
		}
		return true
	})
	require.Equal(t, 3, removed, "the hook statements of the twin (2 bit copies and 1 variable)")
	require.Equal(t, 1, reads, "the read rule calls of the twin")
	// The hook code must not stay anywhere else in the body.
	ast.Inspect(tfn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			require.False(t, isHook(id.Name), "hook identifier %s at %s", id.Name, tfset.Position(id.Pos()))
		}
		return true
	})

	want := strings.Join(printNode(fset, fn.Body), "\n") + "\n"
	got := strings.Join(printNode(tfset, tfn.Body), "\n") + "\n"
	if want != got {
		t.Fatalf("the twin __dd_iast_jsontext_fetch is not a copy of (*decoderState).fetch (%s of %s) with the bit operations only.\n"+
			"Change the twin in orchestrion.yml for the new body.\n- stdlib, + template without the hook code\n%s",
			file, goMinor(t, goroot(t)), lineDiff(want, got))
	}
	// The twin has the receiver of fetch as its only parameter, and the same
	// results.
	require.Equal(t, printNode(fset, fn.Recv), printNode(tfset, tfn.Type.Params))
	require.Equal(t, printNode(fset, fn.Type.Results), printNode(tfset, tfn.Type.Results))
}

// aspect is one aspect of orchestrion.yml (only the fields that the guard
// tests need).
type aspect struct {
	id         string
	importPath string
	recv       string // as written in the YAML: "*encoding/json/jsontext.decoderState", or ""
	name       string
	isFunction bool // a function-body join point
}

var (
	aspectIDRe     = regexp.MustCompile(`^  - id: (.+?)\s*$`)
	aspectImportRe = regexp.MustCompile(`^\s+- import-path: (\S+)\s*$`)
	aspectRecvRe   = regexp.MustCompile(`^\s+- receiver: "?([^"\s]+)"?\s*$`)
	aspectNameRe   = regexp.MustCompile(`^\s+- name: (\S+)\s*$`)
)

// readAspects returns the aspects of orchestrion.yml, in order.
func readAspects(t *testing.T) []aspect {
	t.Helper()
	data, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	var aspects []aspect
	for _, l := range strings.Split(string(data), "\n") {
		if m := aspectIDRe.FindStringSubmatch(l); m != nil {
			aspects = append(aspects, aspect{id: strings.Trim(m[1], `"'`)})
			continue
		}
		if len(aspects) == 0 {
			continue
		}
		a := &aspects[len(aspects)-1]
		if strings.TrimSpace(l) == "- function-body:" {
			a.isFunction = true
		}
		if m := aspectImportRe.FindStringSubmatch(l); m != nil && a.importPath == "" {
			a.importPath = m[1]
		}
		if m := aspectRecvRe.FindStringSubmatch(l); m != nil && a.recv == "" && a.isFunction {
			if m[1] != "false" {
				a.recv = m[1]
			}
		}
		if m := aspectNameRe.FindStringSubmatch(l); m != nil && a.name == "" && a.isFunction {
			a.name = m[1]
		}
	}
	return aspects
}

// instrumentedPoints reads the constant instrumentedPropagationPoints of
// jsonv2.go (this is an external test package).
func instrumentedPoints(t *testing.T) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "jsonv2.go", nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if id.Name != "instrumentedPropagationPoints" {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				require.True(t, ok, "instrumentedPropagationPoints is not an integer literal")
				n, err := strconv.Atoi(lit.Value)
				require.NoError(t, err)
				return n
			}
		}
	}
	t.Fatal("instrumentedPropagationPoints not found in jsonv2.go")
	return 0
}

// TestAspectCount checks that the constant instrumentedPropagationPoints of
// jsonv2.go is the number of hooked functions of orchestrion.yml (every
// aspect that is not a declaration), and that each hook names a function of
// the standard library.
func TestAspectCount(t *testing.T) {
	aspects := readAspects(t)
	require.NotEmpty(t, aspects)

	hooks := map[string]aspect{}
	for _, a := range aspects {
		if strings.HasSuffix(a.id, "-decls") {
			require.False(t, a.isFunction, "%s: a declaration aspect must not have a function join point", a.id)
			continue
		}
		_, dup := hooks[a.id]
		require.False(t, dup, "%s: two hooks with the same id", a.id)
		hooks[a.id] = a
		require.True(t, a.isFunction, "%s: a hook must have a function-body join point", a.id)
	}
	require.Equal(t, instrumentedPoints(t), len(hooks), "instrumentedPropagationPoints of jsonv2.go and the hooks of orchestrion.yml (ids: %v)", sortedKeys(hooks))
	// The aspect encoding/json/jsontext-telemetry-decls pushes the same
	// number to telemetry.
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	pushed := regexp.MustCompile(`\n *var __dd_iast_jsonv2_points uint32 = (\d+)\n`).FindStringSubmatch(string(contents))
	require.NotNil(t, pushed, "the pushed telemetry count is not in orchestrion.yml")
	require.Equal(t, strconv.Itoa(instrumentedPoints(t)), pushed[1], "the pushed telemetry count")
	require.Equal(t, len(hookedFuncs), len(hooks), "hookedFuncs of this test and the hooks of orchestrion.yml")

	seen := map[string]bool{}
	for id, a := range hooks {
		require.NotEmpty(t, a.importPath, "%s: no import-path", id)
		require.NotEmpty(t, a.name, "%s: no function name", id)
		require.Contains(t, hookedPackages, a.importPath, "%s: not a hooked package", id)
		_, files, names := stdlibFiles(t, a.importPath)
		recv := ""
		if a.recv != "" {
			require.True(t, strings.HasPrefix(strings.TrimPrefix(a.recv, "*"), a.importPath+"."), "%s: receiver %q is not of package %s", id, a.recv, a.importPath)
			recv = strings.TrimPrefix(strings.TrimPrefix(a.recv, "*"), a.importPath+".")
			if strings.HasPrefix(a.recv, "*") {
				recv = "*" + recv
			}
		}
		h := hookRef{a.importPath, recv, a.name}
		decls, _ := findFuncs(files, names, h)
		require.NotEmpty(t, decls, "%s: %s not found in the standard library source", id, h.Full())
		wantID := a.importPath + "." + strings.TrimPrefix(recv, "*") + "." + a.name
		if recv == "" {
			wantID = a.importPath + "." + a.name
		}
		require.Equal(t, wantID, id, "the id of a hook is the name of its function")
		require.Contains(t, hookedFuncs, h, "%s is not in hookedFuncs of this test", h.Full())
		seen[h.Full()] = true
	}
	require.Len(t, seen, len(hookedFuncs))
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// Build tests.
// ---------------------------------------------------------------------------

func skipBuildTest(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if testing.Short() {
		t.Skip("builds the standard library again: not in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not found")
	}
}

// moduleRoot returns the root directory of the dd-iast-go module.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	require.NoError(t, err)
	return filepath.Dir(strings.TrimSpace(string(out)))
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// goCommand returns a go command (woven with Orchestrion or not) that runs
// in root, with the extra environment env.
func goCommand(root string, woven bool, env []string, args ...string) *exec.Cmd {
	if woven {
		args = append([]string{"tool", "orchestrion", "go"}, args...)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

// jsonIsV2 tells if encoding/json of the toolchain (with the GOEXPERIMENT of
// env) is the v2 implementation: only then the hooks of this package apply.
func jsonIsV2(t *testing.T, root string, env []string) bool {
	t.Helper()
	out, err := goCommand(root, false, env, "list", "-deps", "encoding/json").Output()
	require.NoError(t, err)
	return slices.Contains(strings.Fields(string(out)), pkgJSONText)
}

// skipUnlessV2 skips a test that needs the hooks of this package.
func skipUnlessV2(t *testing.T, root string) {
	t.Helper()
	if !jsonIsV2(t, root, nil) {
		t.Skip("encoding/json is the v1 implementation (no GOEXPERIMENT=jsonv2): the hooks of this package do not apply")
	}
}

// compileHooked builds testdata/hooked, with the compiler flag gcflags for
// each of the hooked packages (for example "-m"), woven or not. It returns
// the output of the compiler. With noLink, it builds the hooked packages
// only, and does not link the program (the linker rejects a program that has
// standard library packages built with -l).
func compileHooked(t *testing.T, root string, woven bool, gcflags string, noLink bool) string {
	t.Helper()
	args := []string{"build", "-o", os.DevNull}
	for _, pkg := range hookedPackages {
		args = append(args, "-gcflags="+pkg+"="+gcflags)
	}
	if noLink {
		args = append(args, hookedPackages...)
	} else {
		args = append(args, hookedProgram)
	}
	cmd := goCommand(root, woven, nil, args...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s:\n%s", strings.Join(cmd.Args, " "), lastLines(string(out), 30))
	return string(out)
}

// requireWoven checks the output of a compiler run at the level -m: the
// woven output has lines about the code of the hooks, the plain output has
// none.
func requireWoven(t *testing.T, out string, woven bool) {
	t.Helper()
	if woven {
		require.Contains(t, out, "__dd_iast", "the woven output has no hook code: the standard library is not woven")
	} else {
		require.NotContains(t, out, "__dd_iast", "the plain output has hook code: the build is woven")
	}
}

var compilerLine = regexp.MustCompile(`^\S*/src/(encoding/json/internal/jsonwire|encoding/json/jsontext|encoding/json/v2)/([A-Za-z_0-9]+\.go):(\d+)(?::\d+)?: (.*)$`)

// inlinable returns the functions of the hooked packages that the compiler
// can inline ("package.(recv).name"), from the -m output.
func inlinable(out string) map[string]bool {
	res := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		m := compilerLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if name, ok := strings.CutPrefix(m[4], "can inline "); ok {
			name, _, _ = strings.Cut(name, " with cost")
			res[m[1]+"."+strings.TrimSpace(name)] = true
		}
	}
	return res
}

// mustInline are the functions on the decode path that must stay inlinable
// (plan section 6.1 rule 3). They are not hooked: UnquoteMayCopy calls the
// hooked AppendUnquote ("kept simple to keep this inlinable" in its source).
var mustInline = []string{pkgJSONWire + ".UnquoteMayCopy", pkgJSONText + ".(*decodeBuffer).needMore"}

// TestInliningGuard checks plan section 6.1 rule 3: no hooked function stops
// being inlinable with the hooks, and the functions of mustInline stay
// inlinable. It logs the inlining status of each hooked function.
func TestInliningGuard(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	skipUnlessV2(t, root)
	wovenOut := compileHooked(t, root, true, "-m", false)
	plainOut := compileHooked(t, root, false, "-m", false)
	requireWoven(t, wovenOut, true)
	requireWoven(t, plainOut, false)
	woven, plain := inlinable(wovenOut), inlinable(plainOut)

	var lost []string
	for _, h := range hookedFuncs {
		name := h.Full()
		t.Logf("%-55s not woven: %-5t woven: %t", name, plain[name], woven[name])
		if plain[name] && !woven[name] {
			lost = append(lost, name)
		}
	}
	require.Empty(t, lost, "the hooked functions that stop being inlined with the hooks")
	for _, name := range mustInline {
		t.Logf("%-55s not woven: %-5t woven: %t", name, plain[name], woven[name])
		require.True(t, plain[name], "%s is not inlinable without the hooks (the test is out of date)", name)
		require.True(t, woven[name], "%s must stay inlinable with the hooks (plan section 6.1 rule 3)", name)
	}
}

// funcRanges returns the line ranges of the hooked functions, by file
// ("encoding/json/jsontext/decode.go").
func funcRanges(t *testing.T) map[string][][2]int {
	t.Helper()
	ranges := map[string][][2]int{}
	for _, pkg := range hookedPackages {
		fset, files, names := stdlibFiles(t, pkg)
		for _, h := range hookedFuncs {
			if h.pkg != pkg {
				continue
			}
			decls, in := findFuncs(files, names, h)
			require.NotEmpty(t, decls, "%s not found", h.Full())
			for i, fd := range decls {
				key := pkg + "/" + in[i]
				ranges[key] = append(ranges[key], [2]int{fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line})
			}
		}
	}
	return ranges
}

var (
	autotmpRe      = regexp.MustCompile(`autotmp_\d+`)
	inlineCostRe   = regexp.MustCompile(`inline .* cost \d`)
	inlineNoticeRe = regexp.MustCompile(`^(inlining call to |can inline |cannot inline )`)
	// derefsRe matches the explanation header of -m=2 for a parameter
	// ("parameter b leaks to {heap} for makeString with derefs=0:").
	derefsRe = regexp.MustCompile(`^parameter .* leaks to .* with derefs=\d+:?$`)
)

// escapeDecisions returns the sorted -m lines of the hooked functions: the
// escape tags of the parameters and results, and the decisions about the
// values of the function. At -m=2, the compiler also prints explanations
// (the flow paths, the inlining costs and notices): the prepended code
// changes them, but they are not decisions, so they are removed.
func escapeDecisions(out string, ranges map[string][][2]int) []string {
	var kept []string
	for line := range strings.SplitSeq(out, "\n") {
		m := compilerLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		msg := m[4]
		if strings.Contains(msg, "flow:") || strings.HasPrefix(strings.TrimSpace(msg), "from ") || inlineCostRe.MatchString(msg) || inlineNoticeRe.MatchString(msg) || derefsRe.MatchString(msg) {
			continue
		}
		n, _ := strconv.Atoi(m[3])
		key := m[1] + "/" + m[2]
		for _, r := range ranges[key] {
			if n >= r[0] && n <= r[1] {
				kept = append(kept, key+":"+m[3]+": "+autotmpRe.ReplaceAllString(msg, "autotmp"))
				break
			}
		}
	}
	sort.Strings(kept)
	return kept
}

// TestEscapeUnchanged is the escape comparison (plan section 6.1 rule 3):
// the escape decisions of the hooked functions are the same with and without
// the hooks, at -m and -m=2, with and without inlining. A difference means
// that the hooks changed the escape tags of the function (the code of all its
// callers changes), or that a value now escapes to the heap.
func TestEscapeUnchanged(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	skipUnlessV2(t, root)
	ranges := funcRanges(t)
	requireWoven(t, compileHooked(t, root, true, "-m", false), true)
	for _, test := range []struct {
		name, level string
		inlining    bool
	}{
		{"m", "-m", true},
		{"m2", "-m -m", true},
		{"m-noinline", "-m -l", false},
		{"m2-noinline", "-m -m -l", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			woven := escapeDecisions(compileHooked(t, root, true, test.level, !test.inlining), ranges)
			plain := escapeDecisions(compileHooked(t, root, false, test.level, !test.inlining), ranges)
			require.NotEmpty(t, plain)
			require.Equal(t, plain, woven)
		})
	}
}

// v2Symbols returns symbols of the twins and of the bit functions in each
// hooked package (the bit functions are not inlined).
func v2Symbols(t *testing.T) []string {
	symbols := []string{pkgJSONText + ".__dd_iast_jsontext_fetch", pkgJSONV2 + ".__dd_iast_any"}
	if appendUnquoteHooked(t) {
		symbols = append(symbols, pkgJSONWire+".__dd_iast_jsonwire_AppendUnquoteBody")
	}
	return symbols
}

// v1Symbol is a twin of the v1 hooks of iast/propagation/stream.
const v1Symbol = pkgJSON + ".__dd_iast_json_refill"

// TestVariantBuilds checks that the aspects of this package are a no-op
// without GOEXPERIMENT=jsonv2 (no join point matches: Orchestrion adds
// nothing, and the build works), and that they apply with it. For each
// variant of the toolchain in use (jsonv2 and nojsonv2), it builds
// testdata/hooked woven with -ldflags=-checklinkname=1 (the linker accepts
// all the linknames of the hooks), runs it, and reads the symbols of the
// binary: the twins of this package are there only with jsonv2, and the twin
// of the v1 hooks only without it.
func TestVariantBuilds(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	for _, variant := range []string{"jsonv2", "nojsonv2"} {
		t.Run(variant, func(t *testing.T) {
			env := []string{"GOEXPERIMENT=" + variant}
			v2 := jsonIsV2(t, root, env)
			require.Equal(t, variant == "jsonv2", v2, "the variant of encoding/json with %s", env[0])
			bin := filepath.Join(t.TempDir(), "hooked")
			build := goCommand(root, true, env, "build", "-ldflags=-checklinkname=1", "-o", bin, hookedProgram)
			out, err := build.CombinedOutput()
			require.NoError(t, err, "build:\n%s", lastLines(string(out), 30))
			out, err = exec.Command(bin).Output() // stdout only: the tracer logs on stderr
			require.NoError(t, err, "run:\n%s", out)
			require.Equal(t, "ok\n", string(out))
			out, err = exec.Command("go", "tool", "nm", bin).CombinedOutput()
			require.NoError(t, err)
			symbols := strings.Fields(string(out))
			for _, symbol := range v2Symbols(t) {
				if v2 {
					require.Contains(t, symbols, symbol)
				} else {
					require.NotContains(t, symbols, symbol)
				}
			}
			if v2 {
				require.NotContains(t, symbols, v1Symbol)
			} else {
				require.Contains(t, symbols, v1Symbol)
			}
			for _, s := range symbols {
				if strings.HasPrefix(s, "encoding/json/") && strings.Contains(s, "__dd_iast") {
					require.True(t, v2, "a hook symbol of a v2 package in the v1 build: %s", s)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers of the drift golden files (the same code as in
// iast/propagation/stream/guard_test.go).
// ---------------------------------------------------------------------------

// printNode prints a node without comments, one line per line, without blank
// lines.
func printNode(fset *token.FileSet, n ast.Node) []string {
	var b bytes.Buffer
	cfg := printer.Config{Mode: printer.TabIndent, Tabwidth: 4}
	if err := cfg.Fprint(&b, fset, n); err != nil {
		return []string{"<print error: " + err.Error() + ">"}
	}
	var out []string
	for _, l := range strings.Split(b.String(), "\n") {
		if s := strings.TrimSpace(l); s == "" || strings.HasPrefix(s, "//") {
			continue
		}
		out = append(out, strings.TrimRight(l, " \t"))
	}
	return out
}

// lineDiff returns an ordered diff of want and got (the lines of a
// longest common subsequence are kept; at most 200 lines of output).
func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	lcs := make([][]int, len(w)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(g)+1)
	}
	for i := len(w) - 1; i >= 0; i-- {
		for j := len(g) - 1; j >= 0; j-- {
			if w[i] == g[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var b strings.Builder
	lines := 0
	emit := func(prefix, l string, i int) {
		if lines < 200 {
			fmt.Fprintf(&b, "%s %4d: %s\n", prefix, i+1, l)
		}
		lines++
	}
	i, j := 0, 0
	for i < len(w) || j < len(g) {
		switch {
		case i < len(w) && j < len(g) && w[i] == g[j]:
			i++
			j++
		case j < len(g) && (i == len(w) || lcs[i][j+1] >= lcs[i+1][j]):
			emit("+", g[j], j)
			j++
		default:
			emit("-", w[i], i)
			i++
		}
	}
	if lines > 200 {
		fmt.Fprintf(&b, "... %d more lines\n", lines-200)
	}
	return b.String()
}
