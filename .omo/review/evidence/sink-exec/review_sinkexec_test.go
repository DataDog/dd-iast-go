package testapp_test

import (
	"context"
	"os"
	stdexec "os/exec"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func reviewFindings(f *commandFixture) ([]model.Vulnerability, []model.Source) {
	f.annotation.RLock()
	defer f.annotation.RUnlock()
	return append([]model.Vulnerability(nil), f.annotation.Vulnerabilities...), append([]model.Source(nil), f.annotation.Sources...)
}

func reviewLog(t *testing.T, f *commandFixture) int {
	t.Helper()
	findings, sources := reviewFindings(f)
	for i, v := range findings {
		for j, p := range v.Evidence.ValueParts {
			src := -1
			if p.SourceIndex != nil {
				src = *p.SourceIndex
			}
			t.Logf("finding[%d].part[%d] value=%q pattern=%q redacted=%v source=%d", i, j, p.Value, p.Pattern, p.Redacted, src)
		}
	}
	for i, s := range sources {
		t.Logf("source[%d] origin=%v name=%q value=%q redacted=%v pattern=%q", i, s.Origin, s.Name, s.Value, s.Redacted, s.Pattern)
	}
	t.Logf("FINDINGS=%d", len(findings))
	return len(findings)
}

func reviewTaint(f *commandFixture, name, value string) string {
	return taint.TaintString(f.ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: name}, value)
}

// R1: a tainted executable path that differs from Args[0] is what
// os.StartProcess executes, but only argv reaches the sink callback.
func TestReviewTaintedPathWithCleanArgs(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	command := stdexec.CommandContext(f.ctx, "ls")
	command.Path = reviewTaint(f, "bin", "/definitely/not/a/real/attacker-binary")
	err := command.Run()
	t.Logf("run err=%v path=%q args=%q", err, command.Path, command.Args)
	if n := reviewLog(t, f); n != 1 {
		t.Errorf("tainted executed path with clean Args[0]: findings=%d, want 1 (false negative)", n)
	}
}

// R2: Cmd{Path: tainted} with nil Args uses argv() == []string{Path}.
func TestReviewTaintedPathNilArgs(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	command := &stdexec.Cmd{Path: reviewTaint(f, "bin", "/definitely/not/a/real/attacker-binary")}
	t.Logf("run err=%v", command.Run())
	if n := reviewLog(t, f); n != 1 {
		t.Errorf("findings=%d, want 1", n)
	}
}

// R3: Start twice reports at most once.
func TestReviewStartTwice(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	command := f.command()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	err := command.Start()
	t.Logf("second start err=%v", err)
	if err == nil {
		t.Fatal("second Start succeeded")
	}
	if n := reviewLog(t, f); n != 1 {
		t.Errorf("findings=%d, want 1", n)
	}
}

// R4: Env and Dir are not command evidence.
func TestReviewEnvDirNotEvidence(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	command := stdexec.CommandContext(f.ctx, os.Args[0], "-test.run=TestHelperProcess", "--", "clean")
	command.Env = append(os.Environ(), "GO_WANT_DD_IAST_HELPER_PROCESS=1", reviewTaint(f, "env", "X=secretenv"))
	command.Dir = reviewTaint(f, "dir", "/definitely/not/a/real/dir")
	t.Logf("run err=%v", command.Run())
	if n := reviewLog(t, f); n != 0 {
		t.Errorf("findings=%d, want 0", n)
	}
}

// R5: range offsets map exactly into the space-joined evidence.
func TestReviewJoinedRangeMapping(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	old := config.RedactionEnabled
	config.RedactionEnabled = false
	t.Cleanup(func() { config.RedactionEnabled = old })
	f := newCommandFixture(t)
	a := reviewTaint(f, "a", "AAAA")
	b := reviewTaint(f, "b", "b b")
	argv := []string{os.Args[0], "-test.run=TestHelperProcess", "--", "x y", a, "", "z", b, a}
	command := stdexec.CommandContext(f.ctx, argv[0], argv[1:]...)
	command.Env = append(os.Environ(), "GO_WANT_DD_IAST_HELPER_PROCESS=1")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	if n := reviewLog(t, f); n != 1 {
		t.Fatalf("findings=%d", n)
	}
	findings, sources := reviewFindings(f)
	var joined strings.Builder
	var tainted []string
	for _, p := range findings[0].Evidence.ValueParts {
		joined.WriteString(p.Value)
		if p.SourceIndex != nil {
			tainted = append(tainted, p.Value+"@"+sources[*p.SourceIndex].Name)
		}
	}
	want := strings.Join(argv, " ")
	if len(want) > 250 {
		want = want[:250]
	}
	if joined.String() != want {
		t.Errorf("joined parts=%q want %q", joined.String(), want)
	}
	if strings.Join(tainted, ",") != "AAAA@a,b b@b,AAAA@a" {
		t.Errorf("tainted parts=%q", tainted)
	}
}

// R6: bare-name LookPath keeps tainted Args[0].
func TestReviewLookPathBareTaintedName(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	command := stdexec.CommandContext(f.ctx, reviewTaint(f, "bin", "true"))
	t.Logf("path=%q args=%q err=%v", command.Path, command.Args, command.Run())
	if n := reviewLog(t, f); n != 1 {
		t.Errorf("findings=%d, want 1", n)
	}
}

// R7: canceled context returns before the process attempt.
func TestReviewCanceledContextNoAttempt(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	command := stdexec.CommandContext(ctx, os.Args[0], f.secret)
	t.Logf("err=%v", command.Run())
	if n := reviewLog(t, f); n != 0 {
		t.Errorf("findings=%d, want 0", n)
	}
}

// R8: privilege wrapper preserves one following (tainted) command.
func TestReviewSudoPreservesTaintedCommand(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	tainted := reviewTaint(f, "cmd", "rmrf")
	command := stdexec.CommandContext(f.ctx, "/definitely/not/a/real/sudo", tainted, "--flag", "value")
	t.Logf("err=%v", command.Run())
	reviewLog(t, f)
}

// R9: exec.Command without context from a goroutine-free request path, with
// a caller-supplied unrelated context via CommandContext.
func TestReviewUnrelatedContextUsesOwner(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	f := newCommandFixture(t)
	command := stdexec.CommandContext(context.Background(), "/definitely/not/a/real/x", f.secret)
	t.Logf("err=%v", command.Run())
	if n := reviewLog(t, f); n != 1 {
		t.Errorf("findings=%d, want 1", n)
	}
}
