// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package stream_test

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
// and 6) for the hooks of orchestrion.yml:
//
//   - TestStdlibDrift, TestUnquoteBytesCopy and TestAspectCount read the source
//     of the toolchain and of this package. They need no weaving.
//   - The other tests build testdata/hooked (woven and not woven) and read the
//     output of the compiler and of the linker. They run only in the woven
//     test run, and not in -short mode.

var updateDrift = flag.Bool("update-drift", false, "write the golden file of the standard library inventory of the current Go minor version")

// hookRef names one function of the standard library. recv is the receiver
// type as written in the source ("*pp"), empty for a function.
type hookRef struct {
	pkg, recv, name string
}

// String returns the name that the compiler prints: "(*pp).free", "ReadAll".
func (h hookRef) String() string {
	if h.recv == "" {
		return h.name
	}
	return "(" + h.recv + ")." + h.name
}

// Full returns the name with the package: "fmt.(*pp).free".
func (h hookRef) Full() string { return h.pkg + "." + h.String() }

// hookedFuncs are the 18 hooked functions of orchestrion.yml.
var hookedFuncs = []hookRef{
	{"fmt", "*fmt", "pad"},
	{"fmt", "*fmt", "padString"},
	{"fmt", "*pp", "Write"},
	{"fmt", "*pp", "WriteString"},
	{"fmt", "*fmt", "writePadding"},
	{"fmt", "*pp", "free"},
	{"fmt", "*pp", "printArg"},
	{"fmt", "*pp", "fmtString"},
	{"fmt", "*pp", "fmtBytes"},
	{"fmt", "*pp", "doPrintf"},
	{"io", "", "ReadAll"},
	{"bufio", "*Reader", "Read"},
	{"bufio", "*Reader", "fill"},
	{"bufio", "*Reader", "ReadBytes"},
	{"encoding/json", "*Decoder", "refill"},
	{"encoding/json", "*decodeState", "valueQuoted"},
	{"encoding/json", "*decodeState", "literalStore"},
	{"encoding/json", "", "unquoteBytes"},
}

// dependencyFuncs are the functions that the twins copy or depend on, but
// that are not hooked.
//
//   - (*pp).handleMethods: the twin of printArg depends on its method rules.
//   - (*buffer).write and writeString: they are not hooked (they must stay
//     inlinable), but the design depends on them: every output of fmt goes
//     through them, and the twins of pad, padString, Write and WriteString
//     copy their work.
//   - (*fmt).fmtS, truncateString, fmtBs: the copy rules of %s and %v (exact
//     copy of the string or of the bytes).
//   - bufio Buffered and readErr: used by the body copy of Read.
//   - (*decodeState).object: it has the ",string" (destring) part, and calls
//     valueQuoted and literalStore.
//   - getu4: used by the body copy of unquoteBytes.
var dependencyFuncs = []hookRef{
	{"fmt", "*pp", "handleMethods"},
	{"fmt", "*buffer", "write"},
	{"fmt", "*buffer", "writeString"},
	{"fmt", "*fmt", "fmtS"},
	{"fmt", "*fmt", "truncateString"},
	{"fmt", "*fmt", "fmtBs"},
	{"bufio", "*Reader", "Buffered"},
	{"bufio", "*Reader", "readErr"},
	{"encoding/json", "*decodeState", "object"},
	{"encoding/json", "", "getu4"},
}

// structTypes are the struct types whose fields the twins use (and the
// compile-time checks of the declarations of orchestrion.yml).
var structTypes = []struct{ pkg, name string }{
	{"fmt", "pp"},
	{"fmt", "fmt"},
	{"fmt", "fmtFlags"},
	{"bufio", "Reader"},
	{"encoding/json", "Decoder"},
	{"encoding/json", "decodeState"},
}

// stdlibPackages are the packages of the hooks.
var stdlibPackages = []string{"fmt", "io", "bufio", "encoding/json"}

const hookedProgram = "./iast/propagation/stream/testdata/hooked"

func goroot(t testing.TB) string {
	t.Helper()
	if out, err := exec.Command("go", "env", "GOROOT").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOROOT()
}

// stdlibFiles parses all the source files (without the tests, and with any
// build constraint) of the standard library package pkg. The files of the v2
// implementation of encoding/json (prefix "v2_") are not read: the hooks apply
// to the v1 files only. The files are in the order of their names.
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
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "v2_") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		require.NoError(t, err, "parse %s/%s", pkg, name)
		files[name] = f
		names = append(names, name)
	}
	sort.Strings(names)
	return fset, files, names
}

// receiverName returns the receiver type of fd as written ("*pp"), or "".
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
// or "go1.28-devel" for a development version (gotip: "go1.28-devel_abcdef
// ..."; a development build can have no VERSION file).
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
// the source of fmt, io, bufio and encoding/json of the Go toolchain in use
// (no weaving needed), and compares an inventory of the code that the twins
// copy or depend on with a golden file for the Go minor version. The source
// of encoding/json is read with any build constraint: with
// GOEXPERIMENT=jsonv2, the v1 files are still in the inventory.
//
// A difference (or a new minor version without a golden file) fails the
// test. It does not mean that the twins are wrong: a human must read the new
// code, decide if the twins in orchestrion.yml are still correct, then update
// the golden file with:
//
//	go test ./iast/propagation/stream -run TestStdlibDrift -update-drift
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

// templateBody returns the text of the function fn in the templates of
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

// TestUnquoteBytesCopy checks that the body of
// __dd_iast_json_unquoteBytesBody in orchestrion.yml is an exact copy of the
// body of unquoteBytes of the toolchain (comments and blank lines excluded):
// the twin of unquoteBytes runs the copy, then looks at its result.
func TestUnquoteBytesCopy(t *testing.T) {
	src := templateFunc(t, "__dd_iast_json_unquoteBytesBody")
	tfset := token.NewFileSet()
	tf, err := parser.ParseFile(tfset, "orchestrion.yml", "package json\n\n"+src, parser.SkipObjectResolution)
	require.NoError(t, err, "the template does not parse:\n%s", src)
	var tbody *ast.BlockStmt
	for _, d := range tf.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "__dd_iast_json_unquoteBytesBody" {
			tbody = fd.Body
		}
	}
	require.NotNil(t, tbody)

	fset, files, names := stdlibFiles(t, "encoding/json")
	decls, in := findFuncs(files, names, hookRef{"encoding/json", "", "unquoteBytes"})
	require.NotEmpty(t, decls, "unquoteBytes not found in encoding/json")
	want := strings.Join(printNode(fset, decls[0].Body), "\n") + "\n"
	got := strings.Join(printNode(tfset, tbody), "\n") + "\n"
	if want != got {
		t.Fatalf("the template __dd_iast_json_unquoteBytesBody is not an exact copy of unquoteBytes (%s of %s).\n"+
			"Copy the new body into orchestrion.yml (and check the twin __dd_iast_json_unquoteBytes).\n- stdlib, + template\n%s",
			in[0], goMinor(t, goroot(t)), lineDiff(want, got))
	}
	// The signatures (the result names) are the same too.
	require.Equal(t, printNode(fset, decls[0].Type.Results), printNode(tfset, tf.Decls[0].(*ast.FuncDecl).Type.Results))
}

// aspect is one aspect of orchestrion.yml (only the fields that the guard
// tests need).
type aspect struct {
	id         string
	importPath string
	recv       string // as written in the YAML: "*fmt.buffer", or ""
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
// stream.go (this is an external test package).
func instrumentedPoints(t *testing.T) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "stream.go", nil, 0)
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
	t.Fatal("instrumentedPropagationPoints not found in stream.go")
	return 0
}

// TestAspectCount checks that the constant instrumentedPropagationPoints of
// stream.go is the number of hooked functions of orchestrion.yml (every
// aspect that is not a declaration; the aspects of a variant, with the suffix
// " [go1.27]" in the id, count with the aspect of the same function), and
// that each hook names a function of the standard library.
func TestAspectCount(t *testing.T) {
	aspects := readAspects(t)
	require.NotEmpty(t, aspects)

	hooks := map[string]aspect{}
	for _, a := range aspects {
		if strings.HasSuffix(a.id, "-decls") {
			require.False(t, a.isFunction, "%s: a declaration aspect must not have a function join point", a.id)
			continue
		}
		base, _, _ := strings.Cut(a.id, " [")
		if _, dup := hooks[base]; !dup {
			hooks[base] = a
		}
		require.True(t, a.isFunction, "%s: a hook must have a function-body join point", a.id)
	}
	require.Equal(t, instrumentedPoints(t), len(hooks), "instrumentedPropagationPoints of stream.go and the hooks of orchestrion.yml (ids: %v)", sortedKeys(hooks))
	// The aspect fmt-telemetry-decls pushes the same number to telemetry.
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	pushed := regexp.MustCompile(`\n *var __dd_iast_stream_points uint32 = (\d+)\n`).FindStringSubmatch(string(contents))
	require.NotNil(t, pushed, "the pushed telemetry count is not in orchestrion.yml")
	require.Equal(t, strconv.Itoa(instrumentedPoints(t)), pushed[1], "the pushed telemetry count")
	require.Equal(t, len(hookedFuncs), len(hooks), "hookedFuncs of this test and the hooks of orchestrion.yml")

	// Each hook names a function of the standard library source, and its id
	// is the name of this function.
	parsed := map[string]struct {
		files map[string]*ast.File
		names []string
	}{}
	seen := map[string]bool{}
	for id, a := range hooks {
		require.NotEmpty(t, a.importPath, "%s: no import-path", id)
		require.NotEmpty(t, a.name, "%s: no function name", id)
		p, ok := parsed[a.importPath]
		if !ok {
			_, p.files, p.names = stdlibFiles(t, a.importPath)
			parsed[a.importPath] = p
		}
		recv := strings.TrimPrefix(a.recv, "*")
		recv = strings.TrimPrefix(recv, a.importPath+".")
		if a.recv != "" {
			require.True(t, strings.HasPrefix(strings.TrimPrefix(a.recv, "*"), a.importPath+"."), "%s: receiver %q is not of package %s", id, a.recv, a.importPath)
			if strings.HasPrefix(a.recv, "*") {
				recv = "*" + recv
			}
		}
		h := hookRef{a.importPath, recv, a.name}
		decls, _ := findFuncs(p.files, p.names, h)
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

// compileHooked builds testdata/hooked, with the compiler flag gcflags for
// each of the 4 packages (for example "-m"), woven or not. It returns the
// output of the compiler. With noLink, it builds the 4 packages only, and
// does not link the program (the linker rejects a program that has
// standard library packages built with -l, and some tracer packages that
// import them).
func compileHooked(t *testing.T, root string, woven bool, gcflags string, noLink bool) string {
	t.Helper()
	args := []string{"build", "-o", os.DevNull}
	for _, pkg := range stdlibPackages {
		args = append(args, "-gcflags="+pkg+"="+gcflags)
	}
	if noLink {
		args = append(args, stdlibPackages...)
	} else {
		args = append(args, hookedProgram)
	}
	name := "go"
	if woven {
		args = append([]string{"tool", "orchestrion", "go"}, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %s:\n%s", name, strings.Join(args, " "), lastLines(string(out), 30))
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

// jsonIsV1 tells if encoding/json of the toolchain (with the GOEXPERIMENT in
// use) is the v1 implementation: only then the json hooks apply.
func jsonIsV1(t *testing.T, root string) bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-f", "{{.GoFiles}}", "encoding/json")
	cmd.Dir = root
	out, err := cmd.Output()
	require.NoError(t, err)
	return slices.Contains(strings.Fields(strings.Trim(strings.TrimSpace(string(out)), "[]")), "decode.go")
}

// activeHooks returns the hooked functions that apply to the toolchain.
func activeHooks(t *testing.T, root string) []hookRef {
	t.Helper()
	v1 := jsonIsV1(t, root)
	var out []hookRef
	for _, h := range hookedFuncs {
		if h.pkg != "encoding/json" || v1 {
			out = append(out, h)
		}
	}
	return out
}

var compilerLine = regexp.MustCompile(`^\S*/src/(fmt|io|bufio|encoding/json)/([A-Za-z_0-9]+\.go):(\d+)(?::\d+)?: (.*)$`)

// inlinable returns the functions of the 4 packages that the compiler can
// inline ("package.(recv).name"), from the -m output.
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

// expectedInliningLoss are the hooked functions that the compiler inlines
// without the hooks, and does not inline with them (the one extra call costs
// more than the inlining budget; accepted by decision D9, measured by the
// G-A3 benchmarks). (*pp).Write and WriteString are only called through the
// fmt.State interface, thus the loss has no effect on a direct call. A
// function that becomes inlinable again, or a new loss, fails the test.
var expectedInliningLoss = []string{"fmt.(*pp).Write", "fmt.(*pp).WriteString"}

// mustInline are the functions that the hooks must keep inlinable (plan
// section 6.1 rule 3): the buffer writes are on the path of every formatted
// output, and they are not hooked (the hooks are in their callers).
var mustInline = []string{"fmt.(*buffer).write", "fmt.(*buffer).writeString", "fmt.(*buffer).writeByte"}

// TestInliningGuard checks plan section 6.1 rule 3: the functions of
// mustInline stay inlinable with the hooks, and the hooked functions that
// stop being inlinable are those of expectedInliningLoss. It logs the
// inlining status of each hooked function (woven and not woven).
func TestInliningGuard(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	wovenOut := compileHooked(t, root, true, "-m", false)
	plainOut := compileHooked(t, root, false, "-m", false)
	requireWoven(t, wovenOut, true)
	requireWoven(t, plainOut, false)
	woven, plain := inlinable(wovenOut), inlinable(plainOut)

	var lost []string
	for _, h := range activeHooks(t, root) {
		name := h.Full()
		t.Logf("%-45s not woven: %-5t woven: %t", name, plain[name], woven[name])
		if plain[name] && !woven[name] {
			lost = append(lost, name)
		}
	}
	sort.Strings(lost)
	want := slices.Clone(expectedInliningLoss)
	sort.Strings(want)
	require.Equal(t, want, lost, "the hooked functions that stop being inlined with the hooks")
	for _, name := range mustInline {
		t.Logf("%-45s not woven: %-5t woven: %t", name, plain[name], woven[name])
		require.True(t, plain[name], "%s is not inlinable without the hooks (the test is out of date)", name)
		require.True(t, woven[name], "%s must stay inlinable with the hooks (plan section 6.1 rule 3)", name)
	}
}

// funcRanges returns the line ranges of the hooked functions, by file ("fmt/print.go").
func funcRanges(t *testing.T, hooks []hookRef) map[string][][2]int {
	t.Helper()
	ranges := map[string][][2]int{}
	for _, pkg := range stdlibPackages {
		fset, files, names := stdlibFiles(t, pkg)
		for _, h := range hooks {
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
	// ("parameter p leaks to {heap} for (*pp).fmtBytes with derefs=0:").
	derefsRe = regexp.MustCompile(`^parameter .* leaks to .* with derefs=\d+:?$`)
	// bufferCallRe matches a source line that calls (*buffer).write or
	// writeString: the compiler inlines these functions at their call sites,
	// and prints the escape lines of their bodies at the line of the call.
	bufferCallRe = regexp.MustCompile(`\.(write|writeString)\(`)
)

// decisions are the -m lines of the hooked functions.
type decisions struct {
	// kept are the escape decisions: the escape tags of the parameters and
	// results, and the decisions about the values of the function. They must be
	// the same with and without the hooks.
	kept []string
	// inlined are the lines that depend on the inlining of a callee: the
	// lines of the inlined bodies of (*buffer).write and writeString at their
	// call sites, and the explanations of the parameter flows. They are
	// only logged (TestInliningGuard checks the inlining), and they are
	// empty in the runs with the inlining off.
	inlined []string
}

// escapeDecisions returns the sorted -m lines of the hooked functions. At
// -m=2, the compiler also prints explanations (the flow paths and the
// inlining costs): the prepended code changes them, but they are not
// decisions, so they are removed. The inlining notices are checked by
// TestInliningGuard. With inlining on, the lines of the inlined callees
// (see decisions.inlined) are separated.
func escapeDecisions(t *testing.T, out string, ranges map[string][][2]int, inlining bool) decisions {
	t.Helper()
	var d decisions
	sources := map[string][]string{}
	sourceLine := func(key string, n int) string {
		lines, ok := sources[key]
		if !ok {
			data, err := os.ReadFile(filepath.Join(goroot(t), "src", filepath.FromSlash(key)))
			require.NoError(t, err)
			lines = strings.Split(string(data), "\n")
			sources[key] = lines
		}
		if n < 1 || n > len(lines) {
			return ""
		}
		return lines[n-1]
	}
	for line := range strings.SplitSeq(out, "\n") {
		m := compilerLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		msg := m[4]
		if strings.Contains(msg, "flow:") || strings.HasPrefix(strings.TrimSpace(msg), "from ") || inlineCostRe.MatchString(msg) || inlineNoticeRe.MatchString(msg) {
			continue
		}
		n, _ := strconv.Atoi(m[3])
		key := m[1] + "/" + m[2]
		for _, r := range ranges[key] {
			if n < r[0] || n > r[1] {
				continue
			}
			text := key + ":" + m[3] + ": " + autotmpRe.ReplaceAllString(msg, "autotmp")
			switch {
			case inlining && derefsRe.MatchString(msg):
				d.inlined = append(d.inlined, text)
			case inlining && strings.HasPrefix(msg, "append") && bufferCallRe.MatchString(sourceLine(key, n)):
				d.inlined = append(d.inlined, text)
			default:
				d.kept = append(d.kept, text)
			}
			break
		}
	}
	sort.Strings(d.kept)
	sort.Strings(d.inlined)
	return d
}

// TestEscapeUnchanged is the escape comparison (plan section 6.1 rule 3):
// the escape decisions of the hooked functions are the same with and without
// the hooks (at -m and -m=2). A difference means that the hooks changed the
// escape tags of the function (the code of all its callers changes), or that
// an argument now escapes to the heap.
//
// The runs "m" and "m2" use the default inlining. When a hooked function is
// no longer inlinable (TestInliningGuard), the lines of its inlined body at
// the call sites in the other hooked functions are not in the woven output:
// the test only logs them. The runs "m-noinline" and "m2-noinline" disable
// the inlining in the 4 packages, and compare all the lines.
func TestEscapeUnchanged(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	hooks := activeHooks(t, root)
	ranges := funcRanges(t, hooks)
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
			// With -l, build only the 4 packages: the linker rejects a
			// program that has standard library packages built with -l,
			// and the tracer packages that import them.
			woven := escapeDecisions(t, compileHooked(t, root, true, test.level, !test.inlining), ranges, test.inlining)
			plain := escapeDecisions(t, compileHooked(t, root, false, test.level, !test.inlining), ranges, test.inlining)
			require.NotEmpty(t, plain.kept)
			if diff := symmetricDiff(plain.inlined, woven.inlined); len(diff) > 0 {
				t.Logf("lines that depend on the inlining of a callee (- not woven, + woven):\n%s", strings.Join(diff, "\n"))
			}
			require.Equal(t, plain.kept, woven.kept)
		})
	}
}

// symmetricDiff returns the lines of a that are not in b (prefix "-") and the
// lines of b that are not in a (prefix "+").
func symmetricDiff(a, b []string) []string {
	var out []string
	for _, l := range a {
		if !slices.Contains(b, l) {
			out = append(out, "- "+l)
		}
	}
	for _, l := range b {
		if !slices.Contains(a, l) {
			out = append(out, "+ "+l)
		}
	}
	return out
}

// TestDerivedInProgram builds and runs testdata/derived: a program that
// does not import iast/propagation/*, with the hooks woven into fmt. It
// formats a tainted parameter with %q, and the attribution of the result
// must show the parameter on the whole quoted span. Thus the derived entry
// of the coarse output works through the push linkname
// __dd_iast_propbridge.derived (the hooks do not import propbridge).
func TestDerivedInProgram(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "derived")
	build := exec.Command("go", "tool", "orchestrion", "go", "build", "-ldflags=-checklinkname=1", "-o", bin, "./iast/propagation/stream/testdata/derived")
	build.Dir = root
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build:\n%s", lastLines(string(out), 30))
	out, err = exec.Command(bin).Output() // stdout only: the tracer logs on stderr
	require.NoError(t, err, "run:\n%s", out)
	require.Equal(t, "value \"robert\"\n0-8="+paramLabel("q")+"\n", string(out))
}

// TestWovenBinaryHasHooks builds testdata/hooked woven, with
// -ldflags=-checklinkname=1 (the linker accepts all the linknames of the
// hooks), runs it, and checks that the binary has the twins.
func TestWovenBinaryHasHooks(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "hooked")
	build := exec.Command("go", "tool", "orchestrion", "go", "build", "-ldflags=-checklinkname=1", "-o", bin, hookedProgram)
	build.Dir = root
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build:\n%s", lastLines(string(out), 30))
	out, err = exec.Command(bin).Output() // stdout only: the tracer logs on stderr
	require.NoError(t, err, "run:\n%s", out)
	require.Equal(t, "ok\n", string(out))
	out, err = exec.Command("go", "tool", "nm", bin).CombinedOutput()
	require.NoError(t, err)
	symbols := strings.Fields(string(out))
	// The twin of fmt padString is not inlined (the twins of write and
	// writeString can be).
	want := []string{"fmt.__dd_iast_fmt_padString", "io.__dd_iast_io_ReadAll", "bufio.__dd_iast_bufio_Read"}
	if jsonIsV1(t, root) {
		want = append(want, "encoding/json.__dd_iast_json_refill")
	}
	for _, symbol := range want {
		require.Contains(t, symbols, symbol)
	}
}

// ---------------------------------------------------------------------------
// Helpers of the drift golden files (the same code as in
// internal/taint/heapbits/drift_test.go).
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
