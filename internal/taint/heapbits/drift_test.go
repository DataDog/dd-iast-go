// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

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
	"strings"
	"testing"
)

var updateDrift = flag.Bool("update-drift", false, "write the golden file of the runtime inventory of the current Go minor version")

// TestRuntimeDrift is the drift detector of plan section 6.2. It reads the
// source of package runtime of the Go toolchain in use (no weaving needed),
// makes an inventory of the internals that the aspects of orchestrion.yml
// depend on, and compares it with a golden file for the Go minor version.
//
// A difference (or a new minor version without a golden file) fails the
// test. It does not mean that the aspects are wrong: a human must read the
// new runtime code, decide if the hooks are still complete (for example: a
// new path that frees heap memory without the sweep hook), then update the
// golden file with:
//
//	go test ./internal/taint/heapbits -run TestRuntimeDrift -update-drift
func TestRuntimeDrift(t *testing.T) {
	goroot := runtime.GOROOT()
	if out, err := exec.Command("go", "env", "GOROOT").Output(); err == nil {
		goroot = strings.TrimSpace(string(out))
	}
	version := goMinor(t, goroot)
	got := runtimeInventory(t, filepath.Join(goroot, "src", "runtime"))
	golden := filepath.Join("testdata", "runtime-"+version+".golden")
	if *updateDrift {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("no golden file for %s (%v): read the runtime code of this Go version, check the aspects of orchestrion.yml, then run with -update-drift", version, err)
	}
	if string(want) != got {
		t.Fatalf("the runtime internals that the aspects depend on changed in %s (GOROOT %s).\n"+
			"Read the new runtime code, check the aspects of orchestrion.yml, then run with -update-drift.\n%s",
			version, goroot, lineDiff(string(want), got))
	}
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

// freePaths are the functions whose call sites the inventory lists: they
// give memory back (to the heap, or for reuse), so every path that frees a
// tainted object must be known.
var freePaths = []string{"freeSpan", "freeSpanLocked", "freeManual", "freegc", "freeUserArenaChunk", "nextReusableNoScan", "addReusableNoscan", "mallocgcSmallNoscanReuse"}

// bodyFuncs are the functions whose code the inventory holds in full: the
// hooks depend on their behavior, not only on their signature.
//
//   - mark bits and span lookup: markBitsForIndex, gcUsesSpanInlineMarkBits,
//     spanOf, spanOfHeap, objIndex, heapArenaOf, arenaIndex, l1, l2;
//   - accounting: sysAlloc (the hooks copy its accounting);
//   - immediate reuse: freegc (the hook repeats its eligibility checks),
//     reusableSize, nextReusableNoScan, addReusableNoscan;
//   - the whole sweep (the hook runs at its start; the finalizer revival and
//     the specials loop after it), the order of the specials list (addspecial,
//     removespecial, specialFindSplicePoint) and ensureSwept (no special
//     changes during a sweep);
//   - mmap (the non-fatal allocator depends on its error convention).
var bodyFuncs = []string{
	"markBitsForIndex", "gcUsesSpanInlineMarkBits", "spanOf", "spanOfHeap", "objIndex", "heapArenaOf", "arenaIndex", "l1", "l2",
	"sysAlloc",
	"freegc", "reusableSize", "nextReusableNoScan", "addReusableNoscan",
	"sweep", "addspecial", "removespecial", "specialFindSplicePoint", "ensureSwept",
	"mmap",
}

// runtimeInventory returns the inventory of the runtime source in dir.
func runtimeInventory(t *testing.T, dir string) string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	add := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	bodies := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		constraint := ""
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//go:build ") {
					constraint = strings.TrimPrefix(c.Text, "//go:build ")
				}
			}
			if cg.Pos() > f.Package {
				break
			}
		}
		// _KindSpecial* constants.
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				for _, id := range spec.(*ast.ValueSpec).Names {
					if strings.HasPrefix(id.Name, "_KindSpecial") {
						add("const %s (%s)", id.Name, name)
					}
				}
			}
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn := funcName(fd)
			if fd.Name.Name == "mmap" {
				if fd.Body != nil {
					add("mmap with a Go body in %s [%s]", name, constraint)
				} else {
					add("mmap without a body in %s [%s]", name, constraint)
				}
			}
			if fd.Body == nil {
				continue
			}
			if slices.Contains(bodyFuncs, fd.Name.Name) {
				key := fmt.Sprintf("%s (%s [%s])", fn, name, constraint)
				bodies[key] = printBody(fset, fd.Body)
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					if callee := calleeName(n.Fun); slices.Contains(freePaths, callee) {
						add("call %s in %s (%s)", callee, fn, name)
					}
				case *ast.AssignStmt:
					for _, l := range n.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && (sel.Sel.Name == "freeindex" || sel.Sel.Name == "allocBits") {
							add("write %s in %s (%s)", sel.Sel.Name, fn, name)
						}
					}
				}
				return true
			})
		}
	}
	slices.Sort(lines)
	lines = slices.Compact(lines)
	var out strings.Builder
	out.WriteString("# Inventory of the runtime internals that the aspects of orchestrion.yml\n")
	out.WriteString("# depend on (TestRuntimeDrift). Update with -update-drift after a review.\n\n")
	for _, l := range lines {
		out.WriteString(l + "\n")
	}
	keys := make([]string, 0, len(bodies))
	for k := range bodies {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		out.WriteString("\n## " + k + "\n")
		for _, l := range bodies[k] {
			out.WriteString(l + "\n")
		}
	}
	return out.String()
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	var b bytes.Buffer
	printer.Fprint(&b, token.NewFileSet(), fd.Recv.List[0].Type)
	return "(" + b.String() + ")." + fd.Name.Name
}

func calleeName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// printBody prints a function body without comments, one line per line.
func printBody(fset *token.FileSet, body *ast.BlockStmt) []string {
	return printNode(fset, body)
}

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
	// LCS table (the files are a few hundred lines).
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
