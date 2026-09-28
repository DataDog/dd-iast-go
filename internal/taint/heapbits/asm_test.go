// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
)

const heapbitsPkg = "github.com/DataDog/dd-iast-go/internal/taint/heapbits"

// asmFunc is one function of the output of the compiler flag -S.
type asmFunc struct {
	nosplit bool
	calls   []string // direct call targets; "(indirect)" for an indirect call
}

var (
	asmHeader = regexp.MustCompile(`^(\S+) STEXT( nosplit)?`)
	asmCall   = regexp.MustCompile(`\tCALL\t(\S+)`)
)

// parseAsm reads the output of -S and returns the functions by name.
func parseAsm(out string) map[string]*asmFunc {
	funcs := make(map[string]*asmFunc)
	var cur *asmFunc
	for line := range strings.SplitSeq(out, "\n") {
		if m := asmHeader.FindStringSubmatch(line); m != nil {
			cur = &asmFunc{nosplit: m[2] != ""}
			funcs[m[1]] = cur
			continue
		}
		if cur == nil {
			continue
		}
		if m := asmCall.FindStringSubmatch(line); m != nil {
			target := m[1]
			if strings.HasPrefix(target, "(") || !strings.HasSuffix(target, "(SB)") {
				target = "(indirect)"
			} else {
				target = strings.TrimSuffix(target, "(SB)")
			}
			cur.calls = append(cur.calls, target)
		}
	}
	return funcs
}

// compileAsm builds package heapbits with Orchestrion and returns the -S
// output of the woven runtime and of heapbits. extra are more compiler flags
// for all packages (for example "-N -l").
func compileAsm(t *testing.T, extra string) string {
	t.Helper()
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	root := filepath.Dir(strings.TrimSpace(string(gomod)))
	args := []string{"tool", "orchestrion", "go", "build", "-o", os.DevNull}
	if extra != "" {
		args = append(args, "-gcflags=all="+extra)
	}
	args = append(args,
		"-gcflags=runtime=-S "+extra,
		"-gcflags="+heapbitsPkg+"=-S "+extra,
		"./internal/taint/heapbits",
	)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, lastLines(string(out), 30))
	}
	return string(out)
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// TestGeneratedCode checks the machine code rules of the pointer safety
// design (plan section 5.3):
//
//  1. every entry point is nosplit, it calls its worker, and every other call
//     in it goes to a nosplit function (the order, worker after the
//     decision, is checked at run time by TestNoWorkerForStackAddress);
//  2. the workers call the checkpoint, and the checkpoint calls Gosched (or
//     its inlined body, mcall);
//  3. the Go wrappers that convert a pointer to a uintptr have no direct call
//     (other than morestack in the prologue) between the conversion and the
//     indirect call of the runtime function.
func TestGeneratedCode(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if testing.Short() {
		t.Skip("builds the runtime again: not in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not found")
	}
	for name, extra := range map[string]string{"default": "", "no-optimizations": "-N -l"} {
		t.Run(name, func(t *testing.T) {
			checkAsm(t, parseAsm(compileAsm(t, extra)), extra != "")
		})
	}
}

// With noOpt (-N -l), the compiler does not remove the bounds checks that
// the explicit guards make unreachable, so calls to runtime.panicBounds are
// permitted. With optimizations, such a call means that a guard is missing:
// an index panic in the runtime is a fatal error of the application.
func checkAsm(t *testing.T, funcs map[string]*asmFunc, noOpt bool) {
	t.Helper()
	get := func(name string) *asmFunc {
		t.Helper()
		f := funcs[name]
		if f == nil {
			t.Fatalf("function %s not found in the -S output", name)
		}
		return f
	}

	// Rule 1: entry points and the nosplit helpers they call. The value is
	// the only call that is permitted to go to a function with a stack check.
	entries := map[string]string{
		"runtime.__dd_taint_set":           "runtime.__dd_taint_setworker",
		"runtime.__dd_taint_clear":         "runtime.__dd_taint_clearworker",
		"runtime.__dd_taint_any":           "runtime.__dd_taint_anyworker",
		"runtime.__dd_taint_classify":      "",
		"runtime.__dd_taint_arena":         "",
		"runtime.__dd_taint_classifyprobe": "runtime.__dd_taint_growstack", // test knob only
	}
	for name, worker := range entries {
		f := get(name)
		if !f.nosplit {
			t.Errorf("%s must be nosplit", name)
		}
		// The call order (worker after the decision) is not visible here:
		// TestNoWorkerForStackAddress proves it at run time.
		if worker != "" && !slices.Contains(f.calls, worker) {
			t.Errorf("%s does not call %s", name, worker)
		}
		for _, target := range f.calls {
			if target == worker {
				continue
			}
			if noOpt && target == "runtime.panicBounds" {
				continue
			}
			callee := funcs[target]
			if callee == nil {
				t.Errorf("%s calls %s: not found in the -S output (cannot prove that it is nosplit)", name, target)
				continue
			}
			if !callee.nosplit {
				t.Errorf("%s calls %s, which has a stack check", name, target)
			}
		}
	}

	// Rule 2: checkpoints.
	calls := func(f *asmFunc, target string) bool {
		for _, c := range f.calls {
			if c == target {
				return true
			}
		}
		return false
	}
	for _, name := range []string{"runtime.__dd_taint_apply", "runtime.__dd_taint_anyworker"} {
		if !calls(get(name), "runtime.__dd_taint_checkpoint") {
			t.Errorf("%s does not call the checkpoint", name)
		}
	}
	// Gosched is small: the compiler can inline it (its body calls mcall).
	if cp := get("runtime.__dd_taint_checkpoint"); !calls(cp, "runtime.Gosched") && !calls(cp, "runtime.mcall") {
		t.Error("the checkpoint does not call runtime.Gosched")
	}

	// Rule 3: Go wrappers.
	for _, name := range []string{"Set", "Clear", "Any"} {
		f := get(heapbitsPkg + "." + name)
		indirect := 0
		for _, target := range f.calls {
			switch {
			case target == "(indirect)":
				indirect++
			case strings.HasPrefix(target, "runtime.morestack"):
			default:
				t.Errorf("%s.%s calls %s: no call is permitted between the uintptr conversion and the runtime call", heapbitsPkg, name, target)
			}
		}
		if indirect != 1 {
			t.Errorf("%s.%s has %d indirect calls, want 1", heapbitsPkg, name, indirect)
		}
	}
}
