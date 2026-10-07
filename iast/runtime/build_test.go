// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The tests of this file compile the runtime (woven and not woven) and read
// the output of the compiler. They check the rules of the header of
// orchestrion.yml. They run only in the woven test run (they do not need the
// woven test binary, but the plain run would do the same work again), and not
// in -short mode.

// hookedFuncs are the 8 hooked runtime functions and the callers that the
// compiler uses for 2 to 5 operands (their escape tags come from
// concatstrings and concatbytes).
var hookedFuncs = []string{
	"concatstrings", "concatbytes", "slicebytetostring", "stringtoslicebyte",
	"stringtoslicerune", "slicerunetostring", "growslice", "growsliceBuf",
	"concatstring2", "concatstring3", "concatstring4", "concatstring5",
	"concatbyte2", "concatbyte3", "concatbyte4", "concatbyte5",
}

// hookFilters is the symbol of the filter and of the wrapper (or of the next
// call) that each hooked function calls on its gate-on path.
var hookFilters = map[string][2]string{
	"concatstrings":     {"__dd_iast_runtime.concat_hit", "runtime.__dd_iast_concatstrings"},
	"concatbytes":       {"__dd_iast_runtime.concat_hit", "runtime.__dd_iast_concatbytes"},
	"slicebytetostring": {"__dd_iast_runtime.bytes_hit", "runtime.__dd_iast_slicebytetostring"},
	"stringtoslicebyte": {"__dd_iast_runtime.str_hit", "runtime.__dd_iast_stringtoslicebyte"},
	"stringtoslicerune": {"__dd_iast_runtime.str_hit_runes", "runtime.__dd_iast_stringtoslicerune"},
	"slicerunetostring": {"", "runtime.__dd_iast_slicerunetostring"},
	"growslice":         {"__dd_iast_runtime.grow_hit", "runtime.__dd_iast_growslice"},
	"growsliceBuf":      {"__dd_iast_runtime.growbuf_hit", "runtime.growslice"},
}

// leafFuncs are injected functions that must be nosplit and must not call
// another function: they run before the context check (or as the guard of
// propbridge), also on the system stack.
var leafFuncs = []string{"__dd_iast_ok", "__dd_iast_guard", "__dd_iast_strptr", "__dd_iast_count", "__dd_iast_runelen"}

func skipBuildTest(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if testing.Short() {
		t.Skip("builds the runtime again: not in -short mode")
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

// hostOrchestrion builds the Orchestrion command for the host (go tool
// orchestrion with GOOS or GOARCH set builds it for the target).
func hostOrchestrion(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "orchestrion")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/DataDog/orchestrion")
	cmd.Dir = root
	cmd.Env = withoutEnv(os.Environ(), "GOOS", "GOARCH")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build orchestrion:\n%s", out)
	return bin
}

func withoutEnv(env []string, names ...string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(names, name)
	})
}

// compileRuntime builds package heapbits (it imports the runtime), with the
// compiler flags gcflags for the runtime, for goarch (linux for a goarch that
// is not the one of the host). With woven, Orchestrion weaves the build: orch
// is the Orchestrion command for a cross build ("" for go tool orchestrion).
// It returns the output of the compiler.
func compileRuntime(t *testing.T, root string, woven bool, orch, goarch, gcflags string) string {
	t.Helper()
	args := []string{"build", "-o", os.DevNull, "-gcflags=runtime=" + gcflags, "./internal/taint/heapbits"}
	name := "go"
	switch {
	case woven && orch != "":
		name, args = orch, append([]string{"go"}, args...)
	case woven:
		args = append([]string{"tool", "orchestrion", "go"}, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	cmd.Env = append(withoutEnv(os.Environ(), "GOOS", "GOARCH"), "GOARCH="+goarch)
	if goarch != runtime.GOARCH {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %s:\n%s", name, strings.Join(args, " "), lastLines(string(out), 30))
	return string(out)
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// asmInst is one instruction of the -S output.
type asmInst struct {
	generated bool // the position is in injected code
	op, args  string
}

// asmFunc is one function of the -S output.
type asmFunc struct {
	nosplit bool
	insts   []asmInst
	calls   []string
}

var (
	asmHeader = regexp.MustCompile(`^(\S+) STEXT( dupok)?( nosplit)?`)
	asmInstRe = regexp.MustCompile(`^\t0x[0-9a-f]+ \d+ \(([^)]*)\)\t(\S+)\t?(.*)$`)
	asmNumber = regexp.MustCompile(`-?\$?(0x[0-9a-f]+|\d+)`)
	// asmSlot is a named stack slot (an argument or a local), as in
	// "runtime.buf(FP)" or "runtime..autotmp_3-8(SP)".
	asmSlot = regexp.MustCompile(`[A-Za-z_][\w.]*(\+N|-N)?\((FP|SP)\)`)
	// asmReg is a general register of amd64 (the arm64 registers are
	// "RN" after asmNumber).
	asmReg = regexp.MustCompile(`\b(AX|BX|CX|DX|SI|DI)\b`)
)

// parseAsm reads the output of -S and returns the functions by name. A
// function with a dupok symbol of the same name (a linkname alias) keeps the
// first body.
func parseAsm(out string) map[string]*asmFunc {
	funcs := make(map[string]*asmFunc)
	var cur *asmFunc
	for line := range strings.SplitSeq(out, "\n") {
		if m := asmHeader.FindStringSubmatch(line); m != nil {
			cur = nil
			if _, ok := funcs[m[1]]; !ok && m[2] == "" {
				cur = &asmFunc{nosplit: m[3] != ""}
				funcs[m[1]] = cur
			}
			continue
		}
		if cur == nil {
			continue
		}
		m := asmInstRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		op, args := m[2], m[3]
		switch op {
		case "PCDATA", "FUNCDATA", "NOP", "TEXT":
			continue
		case "CALL":
			target := strings.TrimSuffix(args, "(SB)")
			if target == args {
				target = "(indirect)"
			}
			cur.calls = append(cur.calls, target)
		}
		cur.insts = append(cur.insts, asmInst{strings.Contains(m[1], "<generated>"), op, args})
	}
	return funcs
}

// prologue returns the normalized instructions before the first injected
// instruction (woven) or the first n instructions (plain, n >= 0).
func prologue(f *asmFunc, n int) []string {
	var out []string
	for i, in := range f.insts {
		if (n < 0 && in.generated) || i == n {
			break
		}
		args := asmSlot.ReplaceAllString(asmNumber.ReplaceAllString(in.args, "N"), "SLOT")
		out = append(out, in.op+" "+asmReg.ReplaceAllString(args, "RN"))
	}
	return out
}

// TestFramesUnchanged is the gate-off frame comparison (plan section 5.2): in
// each hooked function, the code before the gate check (the prologue: stack
// check, frame setup, and the argument spills that the compiler puts at the
// entry) has the same instructions as in the runtime without hooks (a spill
// can store another argument). Thus the hooks add no spill at the entry, and
// the frame stays under the small-frame limit when it was under it (one
// stack check instruction more otherwise). The frame can be larger by a few words (the gate-on path
// stores the returned arguments in new stack slots): this does not change
// the gate-off code. The test checks arm64 and amd64.
func TestFramesUnchanged(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	orch := hostOrchestrion(t, root)
	for _, goarch := range []string{"arm64", "amd64"} {
		t.Run(goarch, func(t *testing.T) {
			woven := parseAsm(compileRuntime(t, root, true, orch, goarch, "-S"))
			plain := parseAsm(compileRuntime(t, root, false, "", goarch, "-S"))
			for _, name := range hookedFuncs {
				w, p := woven["runtime."+name], plain["runtime."+name]
				require.NotNil(t, w, "%s not in the woven -S output", name)
				require.NotNil(t, p, "%s not in the plain -S output", name)
				if _, hooked := hookFilters[name]; !hooked {
					// A caller (concatstring2..5, concatbyte2..5): the
					// same code.
					require.Equal(t, prologue(p, len(p.insts)), prologue(w, len(w.insts)), "%s: the code changed", name)
					continue
				}
				wp := prologue(w, -1)
				require.Less(t, len(wp), len(w.insts), "%s: no injected code", name)
				require.Equal(t, prologue(p, len(wp)), wp, "%s: the prologue changed", name)
				require.True(t, w.insts[len(wp)].generated, "%s: the gate check is not the first instruction after the prologue", name)
				filter, next := hookFilters[name][0], hookFilters[name][1]
				if filter != "" {
					require.Contains(t, w.calls, filter, "%s does not call its filter", name)
				}
				require.Contains(t, w.calls, next, "%s does not call %s", name, next)
			}
		})
	}
}

// nosplitFuncs are injected functions that must be nosplit and must call
// only nosplit functions: the value is the set of the functions that they
// can call with optimizations. __dd_iast_anystrs reads the addresses of its
// operands, which can be stack addresses: the stack must not move during
// the call.
var nosplitFuncs = map[string][]string{
	"__dd_iast_anystrs": {"runtime.__dd_taint_any", "runtime.__dd_taint_chunk"},
}

// TestInjectedCode checks the machine code rules of the injected runtime
// functions, with and without optimizations: the functions of leafFuncs are
// nosplit and call nothing; the functions of nosplitFuncs are nosplit and
// call only nosplit functions; with optimizations, no injected function
// calls a panic or throw function (a panic in the runtime is a fatal error of
// the application).
func TestInjectedCode(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	for name, extra := range map[string]string{"default": "", "no-optimizations": " -N -l"} {
		t.Run(name, func(t *testing.T) {
			funcs := parseAsm(compileRuntime(t, root, true, "", runtime.GOARCH, "-S"+extra))
			for _, leaf := range leafFuncs {
				f := funcs["runtime."+leaf]
				if f == nil {
					continue // inlined everywhere
				}
				require.True(t, f.nosplit, "%s must be nosplit", leaf)
				require.Empty(t, f.calls, "%s must not call a function", leaf)
			}
			for name, allowed := range nosplitFuncs {
				f := funcs["runtime."+name]
				require.NotNil(t, f, "%s not in the -S output", name)
				require.True(t, f.nosplit, "%s must be nosplit", name)
				for _, target := range f.calls {
					if extra == "" {
						require.Contains(t, allowed, target, "%s calls %s", name, target)
					}
					if extra != "" && strings.HasPrefix(target, "runtime.panic") {
						continue // bounds checks that the guards make unreachable
					}
					callee := funcs[target]
					require.NotNil(t, callee, "%s calls %s: not in the -S output (cannot prove that it is nosplit)", name, target)
					require.True(t, callee.nosplit, "%s calls %s, which has a stack check", name, target)
				}
			}
			if extra != "" {
				require.NotNil(t, funcs["runtime.__dd_iast_ok"], "with -N -l, __dd_iast_ok is a function")
				return
			}
			found := 0
			for name, f := range funcs {
				if !strings.HasPrefix(name, "runtime.__dd_iast") && !strings.HasPrefix(name, "__dd_iast_runtime.") {
					continue
				}
				found++
				for _, target := range f.calls {
					if strings.HasPrefix(target, "runtime.panic") || strings.HasPrefix(target, "runtime.goPanic") || target == "runtime.throw" || target == "runtime.fatal" {
						t.Errorf("%s calls %s", name, target)
					}
				}
			}
			require.GreaterOrEqual(t, found, 15, "injected runtime functions in the -S output")
		})
	}
}

// funcRanges returns the line ranges of the functions names in the runtime
// files string.go and slice.go of the toolchain.
func funcRanges(t *testing.T, names []string) map[string][][2]int {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output()
	require.NoError(t, err)
	dir := filepath.Join(strings.TrimSpace(string(out)), "src", "runtime")
	ranges := map[string][][2]int{}
	found := 0
	for _, file := range []string{"string.go", "slice.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, file), nil, 0)
		require.NoError(t, err)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && slices.Contains(names, fd.Name.Name) {
				ranges[file] = append(ranges[file], [2]int{fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line})
				found++
			}
		}
	}
	require.Equal(t, len(names), found, "hooked functions found in string.go and slice.go")
	return ranges
}

var escapeLine = regexp.MustCompile(`^\S*/src/runtime/(string\.go|slice\.go):(\d+)(?::\d+)?: (.*)$`)

// escapeDecisions returns the sorted -m lines of the hooked functions. At
// -m=2, the compiler also prints explanations (the flow paths and the
// inlining costs): the prepended code changes them, but they are not
// decisions, so they are removed.
func escapeDecisions(out string, ranges map[string][][2]int) []string {
	var lines []string
	autotmp := regexp.MustCompile(`autotmp_\d+`)
	for line := range strings.SplitSeq(out, "\n") {
		m := escapeLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		msg := m[3]
		if strings.Contains(msg, "flow:") || strings.HasPrefix(strings.TrimSpace(msg), "from ") || regexp.MustCompile(`inline .* cost \d`).MatchString(msg) {
			continue
		}
		n := 0
		for _, c := range m[2] {
			n = n*10 + int(c-'0')
		}
		for _, r := range ranges[m[1]] {
			if n >= r[0] && n <= r[1] {
				lines = append(lines, m[1]+":"+m[2]+": "+autotmp.ReplaceAllString(msg, "autotmp"))
				break
			}
		}
	}
	sort.Strings(lines)
	return lines
}

// TestEscapeUnchanged is the escape comparison (plan section 5.2): the escape
// decisions of the hooked functions are the same with and without the hooks
// (at -m and -m=2). A difference means, for example, that a wrapper calls the
// runtime function directly (not through its alias), or that the compiler
// sees the body of a filter: the escape tags of the hooked function changed,
// and the code of all its callers changes.
func TestEscapeUnchanged(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	ranges := funcRanges(t, hookedFuncs)
	for name, level := range map[string]string{"m": "-m", "m2": "-m -m"} {
		t.Run(name, func(t *testing.T) {
			wovenOut := compileRuntime(t, root, true, "", runtime.GOARCH, level)
			require.Contains(t, wovenOut, "__dd_iast_ok", "the woven output has no hook code: the runtime is not woven")
			woven := escapeDecisions(wovenOut, ranges)
			plain := escapeDecisions(compileRuntime(t, root, false, "", runtime.GOARCH, level), ranges)
			require.NotEmpty(t, plain)
			require.Equal(t, plain, woven)
		})
	}
}

// TestWovenProgramLinks builds a program that imports nothing from
// dd-iast-go with the woven runtime and -ldflags=-checklinkname=1, runs it,
// and checks that it has the hooks (the linker accepts all the linknames of
// the hooks).
func TestWovenProgramLinks(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "nohook")
	build := exec.Command("go", "tool", "orchestrion", "go", "build", "-ldflags=-checklinkname=1", "-o", bin, "./iast/runtime/testdata/nohook")
	build.Dir = root
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build:\n%s", out)
	out, err = exec.Command(bin).Output() // stdout only: the tracer logs on stderr
	require.NoError(t, err, "run:\n%s", out)
	require.Equal(t, "ok\n", string(out))
	out, err = exec.Command("go", "tool", "nm", bin).CombinedOutput()
	require.NoError(t, err)
	symbols := strings.Fields(string(out))
	for _, symbol := range []string{"runtime.__dd_iast_concatstrings", "runtime.__dd_iast_growslice", "runtime.__dd_iast_stringtoslicerune", "runtime.__dd_taint_any", "runtime.__dd_taint_copy"} {
		require.Contains(t, symbols, symbol)
	}
}

// TestBuildFailsWithoutHeapbits checks that a module that weaves only the
// aspects of iast/runtime (not those of internal/taint/heapbits) does not
// build, with an error that names the missing heapbits symbols.
func TestBuildFailsWithoutHeapbits(t *testing.T) {
	skipBuildTest(t)
	root := moduleRoot(t)
	dir := t.TempDir()
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	require.NoError(t, err)
	mod := regexp.MustCompile(`(?m)^module .*$`).ReplaceAllString(string(gomod), "module example.com/onlyruntime")
	mod += "\nrequire github.com/DataDog/dd-iast-go v0.0.0\n\nreplace github.com/DataDog/dd-iast-go => " + root + "\n"
	gosum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	require.NoError(t, err)
	for name, content := range map[string]string{
		"go.mod": mod,
		"go.sum": string(gosum),
		"orchestrion.tool.go": `//go:build tools

package tools

import (
	_ "github.com/DataDog/dd-iast-go/iast/runtime"
	_ "github.com/DataDog/orchestrion"
)
`,
		"main.go": "package main\n\nimport \"os\"\n\nfunc main() { println(len(os.Args[0] + \"x\")) }\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	cmd := exec.Command("go", "tool", "orchestrion", "go", "build", "-o", os.DevNull, ".")
	cmd.Dir = dir
	cmd.Env = append(withoutEnv(os.Environ(), "GOFLAGS", "GOPROXY"), "GOFLAGS=-mod=mod", "GOPROXY=off")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "the build must fail:\n%s", out)
	require.Contains(t, string(out), "undefined: __dd_taint_gate", "the error names the gate of heapbits:\n%s", out)
}
