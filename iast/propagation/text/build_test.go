// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The tests of this file compile the hooked packages (woven and not woven)
// and read the output of the compiler. They run only in the woven test run,
// and not in -short mode.

// hookedFuncs are the functions that orchestrion.yml hooks, by package
// ("name" or "(*Type).name").
var hookedFuncs = map[string][]string{
	"strings": {"Clone", "(*Builder).Write", "(*Builder).WriteString", "(*Builder).grow", "Repeat", "ToUpper", "ToLower", "Map", "ToValidUTF8", "(*Replacer).Replace"},
	"bytes": {"Clone", "Join", "Repeat", "Replace", "ToValidUTF8", "ToUpper", "ToLower", "Map",
		"(*Buffer).grow", "(*Buffer).Write", "(*Buffer).WriteString", "(*Buffer).WriteByte", "(*Buffer).WriteRune", "(*Buffer).ReadFrom"},
	"strconv": {"quoteWith", "unquote"},
	"net/url": {"escape", "unescape"},
}

// mustInline are functions that stay inlinable with the hooks (plan section
// 6.1 rule 3): small callers of the hooked functions, and small methods of
// the hooked types. The names are those of the compiler output.
var mustInline = []string{
	"(*Builder).String", "(*Builder).Len", "(*Builder).WriteByte", "ReplaceAll", "ToTitle",
	"(*Buffer).Reset", "(*Buffer).Truncate", "(*Buffer).Grow", "(*Buffer).Len", "(*Buffer).Bytes", "(*Buffer).Read",
	"QueryEscape", "PathEscape", "QueryUnescape", "PathUnescape",
}

// lostInline are the hooked functions that stop being inlined (the one extra
// call costs more than the inlining budget; accepted by decision D9 and
// measured by the G-A3 benchmarks). A function that becomes inlinable again,
// or a new loss, fails the test.
var lostInline = []string{
	"strings.(*Builder).Write", "strings.(*Builder).WriteString", "strings.Clone", "bytes.Clone", "strconv.quoteWith",
}

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

// compileStdlib builds net/url (it imports the 3 other hooked packages) with
// the compiler flags gcflags for the 4 hooked packages, woven or not, and
// returns the output of the compiler.
func compileStdlib(t *testing.T, root string, woven bool, gcflags string) string {
	t.Helper()
	args := []string{"build", "-o", os.DevNull}
	for pkg := range hookedFuncs {
		args = append(args, "-gcflags="+pkg+"="+gcflags)
	}
	args = append(args, "net/url")
	if woven {
		args = append([]string{"tool", "orchestrion", "go"}, args...)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go %s:\n%s", strings.Join(args, " "), lastLines(string(out), 30))
	return string(out)
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

var inlineLine = regexp.MustCompile(`/src/(strings|bytes|strconv|net/url)/[^/:]+\.go:\d+(?::\d+)?: (can|cannot) inline (\S+?):?( |$)`)

// inlinable returns, for each "pkg.name" of the -m=2 output, whether the
// compiler can inline it.
func inlinable(out string) map[string]bool {
	m := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		if g := inlineLine.FindStringSubmatch(line); g != nil {
			m[g[1]+"."+g[3]] = g[2] == "can"
		}
	}
	return m
}

// TestInlining is the inlining guard of plan section 6.1 rule 3.
func TestInlining(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	plain := inlinable(compileStdlib(t, root, false, "-m -m"))
	woven := inlinable(compileStdlib(t, root, true, "-m -m"))
	require.NotEmpty(t, plain)
	for _, name := range mustInline {
		found := false
		for pkg := range hookedFuncs {
			key := pkg + "." + name
			if can, ok := plain[key]; ok && can {
				found = true
				require.True(t, woven[key], "%s must stay inlinable", key)
			}
		}
		require.True(t, found, "%s is not inlinable in the plain build", name)
	}
	var lost []string
	for key, can := range plain {
		if can && !woven[key] {
			lost = append(lost, key)
		}
	}
	sort.Strings(lost)
	want := slices.Clone(lostInline)
	sort.Strings(want)
	require.Equal(t, want, lost, "the functions that stop being inlined with the hooks")
}

// funcRanges returns the line ranges of the hooked functions, by file path
// relative to GOROOT/src.
func funcRanges(t *testing.T) map[string][][2]int {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output()
	require.NoError(t, err)
	src := filepath.Join(strings.TrimSpace(string(out)), "src")
	ranges := map[string][][2]int{}
	found := 0
	for pkg, names := range hookedFuncs {
		dir := filepath.Join(src, filepath.FromSlash(pkg))
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
			require.NoError(t, err)
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && slices.Contains(names, funcKey(fd)) {
					key := pkg + "/" + e.Name()
					ranges[key] = append(ranges[key], [2]int{fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line})
					found++
				}
			}
		}
	}
	total := 0
	for _, names := range hookedFuncs {
		total += len(names)
	}
	require.Equal(t, total, found, "hooked functions found")
	return ranges
}

var escapeLine = regexp.MustCompile(`/src/((?:strings|bytes|strconv|net/url)/[^/:]+\.go):(\d+)(?::\d+)?: (.*)$`)

// escapeDecisions returns the sorted -m lines of the hooked functions,
// without the explanations of -m=2 and without the inlining lines (the
// prepended code changes the inlining; TestInlining checks it). params are
// the lines of the declaration (the escape tags of the parameters); body are
// the other lines.
func escapeDecisions(out string, ranges map[string][][2]int) (params, body []string) {
	autotmp := regexp.MustCompile(`autotmp_\d+`)
	skip := regexp.MustCompile(`flow:|^\s*from |inline|inlining call|^parameter .* leaks to .* with derefs=`)
	for line := range strings.SplitSeq(out, "\n") {
		m := escapeLine.FindStringSubmatch(line)
		if m == nil || skip.MatchString(m[3]) {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		for _, r := range ranges[m[1]] {
			if n >= r[0] && n <= r[1] {
				l := m[1] + ":" + m[2] + ": " + autotmp.ReplaceAllString(m[3], "autotmp")
				if n == r[0] {
					params = append(params, l)
				} else {
					body = append(body, l)
				}
				break
			}
		}
	}
	sort.Strings(params)
	sort.Strings(body)
	return slices.Compact(params), slices.Compact(body)
}

// TestEscapeUnchanged is the escape comparison of plan section 6.1 rule 3
// (at -m and -m=2):
//
//   - the escape tags of the parameters of the hooked functions are the same
//     with and without the hooks. A difference changes the code of all the
//     callers (for example, a value that the application gives to a hooked
//     function moves to the heap);
//   - the hooks add no escape decision in the original body. The body can
//     lose decisions: the lines of the inlined bodies of functions that are
//     no longer inlined (TestInlining).
func TestEscapeUnchanged(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	ranges := funcRanges(t)
	for name, level := range map[string]string{"m": "-m", "m2": "-m -m"} {
		t.Run(name, func(t *testing.T) {
			wovenOut := compileStdlib(t, root, true, level)
			require.Contains(t, wovenOut, "__dd_iast_", "the woven output has no hook code: the standard library is not woven")
			wovenParams, wovenBody := escapeDecisions(wovenOut, ranges)
			plainParams, plainBody := escapeDecisions(compileStdlib(t, root, false, level), ranges)
			require.NotEmpty(t, plainParams)
			require.Equal(t, plainParams, wovenParams, "escape tags of the hooked functions")
			var added []string
			for _, l := range wovenBody {
				if !slices.Contains(plainBody, l) {
					added = append(added, l)
				}
			}
			require.Empty(t, added, "escape decisions that the hooks add in the original bodies")
		})
	}
}

// TestDerivedWithoutImport builds and runs testdata/derived: a program that
// does not import iast/propagation/text (the hooks come only from the
// orchestrion.tool.go file of the module). The derived entries of the hooks
// must work there: the hooks find propbridge.Derived through the variable
// that propbridge pushes. The test also checks that the program does not
// link iast/propagation/text.
func TestDerivedWithoutImport(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "derived")
	build := exec.Command("go", "tool", "orchestrion", "go", "build", "-ldflags=-checklinkname=1", "-o", bin, "./iast/propagation/text/testdata/derived")
	build.Dir = root
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build:\n%s", out)
	out, err = exec.Command(bin).Output() // stdout only: the tracer logs on stderr
	require.NoError(t, err, "run:\n%s", out)
	require.Equal(t, "2-15=q \n2-23=q \n2-17=q \n", string(out))
	out, err = exec.Command("go", "tool", "nm", bin).CombinedOutput()
	require.NoError(t, err)
	require.NotContains(t, string(out), "iast/propagation/text.")
	require.Contains(t, string(out), "strings.__dd_iast_toupper")
}
