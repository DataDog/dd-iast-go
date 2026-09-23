package testapp_test

import (
	"os"
	stdexec "os/exec"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

// fxF1Count returns the number of findings recorded on the fixture's span.
func fxF1Count(f *commandFixture) int {
	f.annotation.RLock()
	defer f.annotation.RUnlock()
	return len(f.annotation.Vulnerabilities)
}

// taintedBinary is an attacker-chosen executable path taken from a request
// parameter. It points at a REAL binary (this test binary) so the process
// genuinely runs and we can prove the attacker-selected program executed.
func fxF1TaintedBinary(f *commandFixture) string {
	return taint.TaintString(f.ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "bin"}, os.Args[0])
}

func fxF1Run(t *testing.T, name string, f *commandFixture, cmd *stdexec.Cmd, want int) {
	t.Helper()
	cmd.Env = append(os.Environ(), "GO_WANT_DD_IAST_HELPER_PROCESS=1")
	out, err := cmd.Output()
	pathTainted := taint.IsTaintedString(cmd.Path)
	args0Tainted := len(cmd.Args) > 0 && taint.IsTaintedString(cmd.Args[0])
	got := fxF1Count(f)
	t.Logf("FXF1 case=%s err=%v stdout=%q path_tainted=%v args0_tainted=%v FINDINGS=%d want=%d", name, err, out, pathTainted, args0Tainted, got, want)
	if err != nil {
		t.Fatalf("process did not run: %v", err)
	}
	if got != want {
		t.Errorf("FXF1 case=%s: attacker-chosen binary executed, findings=%d want=%d", name, got, want)
	}
}

// Control: tainted binary passed through exec.Command, so Args[0] is tainted.
func TestFxF1ControlCommandTaintedName(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	bin := fxF1TaintedBinary(f)
	fxF1Run(t, "control-exec.Command(tainted)", f, stdexec.CommandContext(f.ctx, bin, "-test.run=TestHelperProcess", "--", "ran-attacker-binary"), 1)
}

// Bug: Cmd.Path reassigned to a tainted value after Command; Args[0] stays clean.
func TestFxF1PathReassigned(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	cmd := stdexec.CommandContext(f.ctx, "/usr/bin/true", "-test.run=TestHelperProcess", "--", "ran-attacker-binary")
	cmd.Path = fxF1TaintedBinary(f)
	fxF1Run(t, "cmd.Path=tainted", f, cmd, 1)
}

// Bug: struct literal with a tainted Path and a clean, conventional Args[0].
func TestFxF1StructLiteral(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	cmd := &stdexec.Cmd{Path: fxF1TaintedBinary(f), Args: []string{"worker", "-test.run=TestHelperProcess", "--", "ran-attacker-binary"}}
	fxF1Run(t, "&Cmd{Path:tainted,Args:clean}", f, cmd, 1)
}
