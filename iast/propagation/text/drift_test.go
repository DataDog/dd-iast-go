// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

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
	"slices"
	"strings"
	"testing"
)

var updateDrift = flag.Bool("update-drift", false, "write the golden file of the standard library inventory of the current Go minor version")

// driftItems are, for each package, the declarations that the aspects of
// orchestrion.yml change, repeat or depend on (plan section 6.1 rule 6): the
// hooked functions, the functions and fields that the twins use, and the
// constants of the strings.Repeat fast path. A function is "name" or
// "(*Type).name"; a type or a constant is its name.
var driftItems = map[string][]string{
	"strings": {
		"Builder", "(*Builder).copyCheck", "(*Builder).String", "(*Builder).Len", "(*Builder).Grow",
		"(*Builder).Write", "(*Builder).WriteString", "(*Builder).grow",
		"Clone", "Repeat", "repeatedSpaces", "ToUpper", "ToLower", "ToTitle", "Map", "ToValidUTF8",
		"Replacer", "(*Replacer).Replace", "(*Replacer).buildOnce", "replacer",
	},
	"internal/stringslite": {"Clone"},
	"bytes": {
		"Buffer", "(*Buffer).Len", "(*Buffer).Reset", "(*Buffer).tryGrowByReslice", "(*Buffer).grow", "growSlice",
		"(*Buffer).Write", "(*Buffer).WriteString", "(*Buffer).WriteByte", "(*Buffer).WriteRune", "(*Buffer).ReadFrom",
		"smallBufferSize", "MinRead", "opInvalid",
		"Clone", "Join", "Repeat", "Replace", "ReplaceAll", "ToValidUTF8", "ToUpper", "ToLower", "ToTitle", "Map",
	},
	"strconv": {"quoteWith", "unquote", "Quote", "QuoteToASCII", "QuoteToGraphic", "Unquote", "QuotedPrefix"},
	"net/url": {"escape", "unescape", "QueryEscape", "PathEscape", "QueryUnescape", "PathUnescape", "EscapeError", "InvalidHostError"},
}

// TestStdlibDrift is the drift detector of plan section 6.1 rule 6. It reads
// the source of the hooked packages of the Go toolchain in use (no weaving
// needed) and compares the declarations of driftItems with a golden file for
// the Go minor version.
//
// A difference (or a new minor version without a golden file) fails the
// test. It does not mean that the aspects are wrong: a human must read the
// new code, check that each twin of orchestrion.yml still does the work of
// the body (and the same panics), then update the golden file with:
//
//	go test ./iast/propagation/text -run TestStdlibDrift -update-drift
func TestStdlibDrift(t *testing.T) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	goroot := strings.TrimSpace(string(out))
	version := goMinor(t, goroot)
	got := stdlibInventory(t, filepath.Join(goroot, "src"))
	golden := filepath.Join("testdata", "stdlib-"+version+".golden")
	if *updateDrift {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("no golden file for %s (%v): read the code of the hooked functions of this Go version, check the twins of orchestrion.yml, then run with -update-drift", version, err)
	}
	if string(want) != got {
		t.Fatalf("the standard library code that the aspects depend on changed in %s (GOROOT %s).\n"+
			"Read the new code, check the twins of orchestrion.yml, then run with -update-drift.\n%s",
			version, goroot, lineDiff(string(want), got))
	}
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

// stdlibInventory prints the declarations of driftItems from the source in
// src (the src directory of GOROOT).
func stdlibInventory(t *testing.T, src string) string {
	t.Helper()
	var out strings.Builder
	out.WriteString("# Inventory of the standard library declarations that the aspects of\n")
	out.WriteString("# orchestrion.yml depend on (TestStdlibDrift). Update with -update-drift\n")
	out.WriteString("# after a review.\n")
	pkgs := make([]string, 0, len(driftItems))
	for pkg := range driftItems {
		pkgs = append(pkgs, pkg)
	}
	slices.Sort(pkgs)
	for _, pkg := range pkgs {
		found := map[string][]string{}
		dir := filepath.Join(src, filepath.FromSlash(pkg))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", pkg, name, err)
			}
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					key := funcKey(d)
					if slices.Contains(driftItems[pkg], key) {
						found[key] = append(found[key], fmt.Sprintf("(%s)", name))
						found[key] = append(found[key], printNode(fset, d)...)
					}
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						var names []string
						switch s := spec.(type) {
						case *ast.TypeSpec:
							names = []string{s.Name.Name}
						case *ast.ValueSpec:
							for _, id := range s.Names {
								names = append(names, id.Name)
							}
						}
						for _, n := range names {
							if slices.Contains(driftItems[pkg], n) {
								// The whole declaration (a const block holds
								// the related constants).
								found[n] = append(found[n], fmt.Sprintf("(%s)", name))
								found[n] = append(found[n], printNode(fset, d)...)
							}
						}
					}
				}
			}
		}
		for _, item := range driftItems[pkg] {
			out.WriteString("\n## " + pkg + " " + item + "\n")
			lines, ok := found[item]
			if !ok {
				out.WriteString("<not found>\n")
				continue
			}
			for _, l := range lines {
				out.WriteString(l + "\n")
			}
		}
	}
	return out.String()
}

func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	var b bytes.Buffer
	printer.Fprint(&b, token.NewFileSet(), fd.Recv.List[0].Type)
	return "(" + b.String() + ")." + fd.Name.Name
}

// printNode prints a declaration without comments and empty lines.
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

// lineDiff returns an ordered diff of want and got (at most 200 lines).
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
