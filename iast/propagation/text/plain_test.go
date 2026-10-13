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
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// The tests of this file are for the plain twin hooks (rule 5 of the header
// of orchestrion.yml): strings.Join, strings.Replace, strings.Repeat and
// strings.ToLower.

// TestPlainTwinGates checks the input checks of the plain twin hooks, with
// the gate on: when one input that the body copies is tainted, the original
// body runs and the bits are exact; when no input is tainted, the result has
// no bits.
func TestPlainTwinGates(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "VALUE")
	sep := source(t, a, "sep", "::")

	t.Run("Join with only the last element tainted", func(t *testing.T) {
		got := strings.Join([]string{"a", "b", "c", "d", value}, ",")
		require.Equal(t, "a,b,c,d,VALUE", got)
		require.Equal(t, []span{{8, 13}}, stringSpans(got))
		require.Equal(t, []string{"8-13=q"}, attributed(t, a, got))
	})
	t.Run("Join with only the separator tainted", func(t *testing.T) {
		got := strings.Join([]string{"a", "b", "c"}, sep)
		require.Equal(t, "a::b::c", got)
		require.Equal(t, []span{{1, 3}, {4, 6}}, stringSpans(got))
	})
	t.Run("Join of 1 element returns the element", func(t *testing.T) {
		got := strings.Join([]string{value}, sep)
		require.True(t, sameData(value, got))
		require.Equal(t, []span{{0, 5}}, stringSpans(got))
	})
	t.Run("Join without taint", func(t *testing.T) {
		got := strings.Join([]string{"a", "b", strings.Clone("c")}, ", ")
		require.Equal(t, "a, b, c", got)
		require.Empty(t, stringSpans(got))
	})

	t.Run("Replace with only the replacement tainted", func(t *testing.T) {
		got := strings.Replace("x=OLD;y=OLD", "OLD", value, -1)
		require.Equal(t, "x=VALUE;y=VALUE", got)
		require.Equal(t, []span{{2, 7}, {10, 15}}, stringSpans(got))
		require.Equal(t, []string{"2-7=q", "10-15=q"}, attributed(t, a, got))
	})
	t.Run("Replace with only old tainted", func(t *testing.T) {
		// old is not in the output: the plain twin runs.
		got := strings.Replace(strings.Clone("aVALUEb"), value, "-", -1)
		require.Equal(t, "a-b", got)
		require.Empty(t, stringSpans(got))
	})
	t.Run("Replace with an empty old and a tainted s", func(t *testing.T) {
		got := strings.Replace(value[:2], "", "|", -1)
		require.Equal(t, "|V|A|", got)
		require.Equal(t, []span{{1, 2}, {3, 4}}, stringSpans(got))
	})
	t.Run("Replace without taint", func(t *testing.T) {
		got := strings.ReplaceAll(strings.Clone("a-b-c"), "-", "+")
		require.Equal(t, "a+b+c", got)
		require.Empty(t, stringSpans(got))
	})

	t.Run("Repeat without taint", func(t *testing.T) {
		got := strings.Repeat(strings.Clone("ab"), 3)
		require.Equal(t, "ababab", got)
		require.Empty(t, stringSpans(got))
	})
	t.Run("Repeat of a tainted value", func(t *testing.T) {
		got := strings.Repeat(value, 2)
		require.Equal(t, "VALUEVALUE", got)
		require.Equal(t, []span{{0, 10}}, stringSpans(got))
	})

	t.Run("ToLower without taint", func(t *testing.T) {
		got := strings.ToLower(strings.Clone("ABC-déF"))
		require.Equal(t, "abc-déf", got)
		require.Empty(t, stringSpans(got))
	})
	t.Run("ToLower of a tainted value", func(t *testing.T) {
		got := strings.ToLower(value)
		require.Equal(t, "value", got)
		require.Equal(t, []span{{0, 5}}, stringSpans(got))
		require.Equal(t, []string{"0-5=q"}, attributed(t, a, got))
	})
}

// joinAnyStrs is the variable that the strings.Join hook reads: the bridge
// __dd_iast_anystrsptr that the aspects of iast/runtime push.
//
//go:linkname joinAnyStrs __dd_iast_runtime.anystrsptr
var joinAnyStrs func(p, n uintptr) bool

// TestJoinBatches checks that strings.Join itself calls the bridge of the
// runtime, in batches of at most 256 elements (the bridge is nosplit, thus a
// goroutine cannot be preempted during one call), for a large Join of 1e6
// elements. The test replaces the bridge with a wrapper that counts the
// calls for the elements of the test. For a different slice (a Join of a
// different code during the test), the wrapper returns true ("maybe
// tainted"): the hooked body then runs, which is correct for all values.
func TestJoinBatches(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "VALUE")
	bridge := joinAnyStrs
	require.NotNil(t, bridge, "the woven runtime does not push __dd_iast_runtime.anystrsptr")

	const n, batch = 1_000_000, 256
	clean := strings.Clone("a")
	elems := make([]string, n)
	for i := range elems {
		elems[i] = clean
	}
	lo := uintptr(unsafe.Pointer(unsafe.SliceData(elems)))
	hi := lo + n*unsafe.Sizeof("")
	var calls, scanned, largest uintptr
	joinAnyStrs = func(p, k uintptr) bool {
		if p < lo || p >= hi {
			return true
		}
		calls++
		scanned += k
		largest = max(largest, k)
		return bridge(p, k)
	}
	t.Cleanup(func() { joinAnyStrs = bridge })
	reset := func() { calls, scanned, largest = 0, 0, 0 }
	const batches = (n + batch - 1) / batch

	got := strings.Join(elems, ",")
	require.Len(t, got, 2*n-1)
	require.True(t, got == strings.Repeat("a,", n-1)+"a", "the result of a large clean Join")
	require.Empty(t, stringSpans(got))
	require.Equal(t, uintptr(batches), calls, "the calls of the bridge")
	require.Equal(t, uintptr(n), scanned, "the elements that the bridge scanned")
	require.Equal(t, uintptr(batch), largest, "the largest batch")

	// Only the last element is tainted: all the batches are scanned, then
	// the hooked body runs and the bits are exact.
	reset()
	elems[n-1] = value
	got = strings.Join(elems, ",")
	require.Equal(t, []span{{2 * (n - 1), 2*(n-1) + len(value)}}, stringSpans(got))
	require.Equal(t, uintptr(batches), calls)
	require.Equal(t, uintptr(n), scanned)

	// The first element is tainted: the first batch stops the scan.
	reset()
	elems[0], elems[n-1] = value, clean
	got = strings.Join(elems, ",")
	require.Equal(t, []span{{0, len(value)}}, stringSpans(got))
	require.Equal(t, uintptr(1), calls)
	require.Equal(t, uintptr(batch), scanned)

	// A tainted separator stops the check before the bridge.
	reset()
	elems[0] = clean
	got = strings.Join(elems[:3], source(t, a, "sep", "::"))
	require.Equal(t, "a::a::a", got)
	require.Equal(t, []span{{1, 3}, {4, 6}}, stringSpans(got))
	require.Zero(t, calls)
}

// TestPlainTwins is the equivalence test of the plain twins: it builds
// testdata/plaintwins without Orchestrion (the original bodies) and with
// Orchestrion (the plain twins), and compares the outputs. For each case, the
// output has the result (or the panic value), whether the result is a part
// of the input, and the allocations (count and bytes) of one call. The woven
// program runs with the gate off and with the gate on.
func TestPlainTwins(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	dir := t.TempDir()
	build := func(name string, woven bool) string {
		bin := filepath.Join(dir, name)
		args := []string{"build", "-o", bin, "./iast/propagation/text/testdata/plaintwins"}
		if woven {
			args = append([]string{"tool", "orchestrion", "go"}, args...)
		}
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "go %s:\n%s", strings.Join(args, " "), lastLines(string(out), 30))
		return bin
	}
	plain, woven := build("plain", false), build("woven", true)
	nm, err := exec.Command("go", "tool", "nm", woven).CombinedOutput()
	require.NoError(t, err)
	for _, fn := range []string{"join", "replace", "repeat", "tolower"} {
		require.Contains(t, string(nm), "strings.__dd_iast_"+fn+"_plain", "the woven program has the plain twin")
	}
	run := func(bin string, args ...string) string {
		out, err := exec.Command(bin, args...).Output() // stdout only: the tracer logs on stderr
		require.NoError(t, err, "%s %v:\n%s", filepath.Base(bin), args, out)
		require.NotContains(t, string(out), "TAINTED")
		return string(out)
	}

	want := run(plain, "-fake")
	require.Contains(t, want, "Join/overflow/elements: panic strings: Join output length overflow")
	require.Contains(t, want, "Repeat/chunks: len=15000")
	require.Equal(t, want, run(woven, "-fake"), "gate off")

	// With the gate on, the hooks read the taint bits of all the input: no
	// case with a length that is larger than its memory.
	want = run(plain)
	require.Equal(t, want, run(woven, "-live"), "gate on")
}

// TestPlainBuilderInlining checks that the methods of __dd_iast_pb (the
// plain builder) are inlinable in the woven strings package: else the plain
// twins lose the gain.
func TestPlainBuilderInlining(t *testing.T) {
	skipBuildTest(t)
	inlinable := map[string]bool{}
	for line := range strings.SplitSeq(compileStdlib(t, moduleRoot(t), true, "-m -m"), "\n") {
		if g := pbInlineLine.FindStringSubmatch(line); g != nil {
			inlinable[g[2]] = g[1] == "can"
		}
	}
	// grow is not inlinable, as strings.Builder.grow: it runs only when the
	// buffer is too small (one time in the plain twins).
	require.Equal(t, map[string]bool{"grow": false, "Grow": true, "WriteString": true, "WriteByte": true, "Len": true, "String": true}, inlinable)
}

// pbInlineLine is a line of the inlining decisions for __dd_iast_pb. Go 1.27
// writes the path of the woven file before "<generated>"; Go 1.26 does not
// (the line comes after "# strings"). Only package strings declares
// __dd_iast_pb.
var pbInlineLine = regexp.MustCompile(`(?m)(?:^|/src/strings/)<generated>:\d+: (can|cannot) inline \(\*__dd_iast_pb\)\.(\w+)`)

// plainTwins are the plain twins of orchestrion.yml, with the name of the
// function of package strings that each one is a copy of.
var plainTwins = map[string]string{
	"__dd_iast_join_plain":    "Join",
	"__dd_iast_replace_plain": "Replace",
	"__dd_iast_repeat_plain":  "Repeat",
	"__dd_iast_tolower_plain": "ToLower",
}

// TestPlainTwinSources checks that each plain twin of orchestrion.yml is a
// copy of the body of its function in the source of the Go toolchain in use:
// the two declarations are the same when the name of the twin is the name of
// the function and __dd_iast_pb is Builder. TestStdlibDrift finds a change
// of the bodies in a new Go version; this test finds a twin that is not
// updated after such a change. It does not need weaving.
func TestPlainTwinSources(t *testing.T) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	require.NoError(t, err)
	dir := filepath.Join(strings.TrimSpace(string(out)), "src", "strings")
	originals := map[string][]string{}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				originals[fd.Name.Name] = printNode(fset, fd)
			}
		}
	}

	twins := plainTwinSources(t)
	require.Len(t, twins, len(plainTwins), "the plain twins in orchestrion.yml")
	for twin, original := range plainTwins {
		src, ok := twins[twin]
		require.True(t, ok, "%s is not in orchestrion.yml", twin)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, twin+".go", "package strings\n\n"+src, 0)
		require.NoError(t, err, "parse %s:\n%s", twin, src)
		require.Len(t, f.Decls, 1)
		fd := f.Decls[0].(*ast.FuncDecl)
		fd.Name.Name = original
		ast.Inspect(fd, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "__dd_iast_pb" {
				id.Name = "Builder"
			}
			return true
		})
		want, ok := originals[original]
		require.True(t, ok, "strings.%s is not in %s", original, dir)
		got := printNode(fset, fd)
		require.Equal(t, strings.Join(want, "\n"), strings.Join(got, "\n"),
			"%s is not a copy of strings.%s: update the twin in orchestrion.yml", twin, original)
	}
}

// plainTwinSources returns the source of the plain twins in orchestrion.yml
// (the template lines from "func __dd_iast_<x>_plain(" to the closing brace
// at the same indentation, without this indentation).
func plainTwinSources(t *testing.T) map[string]string {
	t.Helper()
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	out := map[string]string{}
	lines := strings.Split(string(contents), "\n")
	for i := 0; i < len(lines); i++ {
		m := plainTwinStart.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent, name := m[1], m[2]
		var b strings.Builder
		for ; i < len(lines); i++ {
			l, ok := strings.CutPrefix(lines[i], indent)
			if !ok && strings.TrimSpace(lines[i]) != "" {
				t.Fatalf("orchestrion.yml:%d: the line is not in the template of %s", i+1, name)
			}
			b.WriteString(l + "\n")
			if l == "}" {
				break
			}
		}
		require.NotContains(t, out, name, "two declarations of %s", name)
		out[name] = b.String()
	}
	return out
}

var plainTwinStart = regexp.MustCompile(`^( +)func (__dd_iast_\w+_plain)\(`)
