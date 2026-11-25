// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/build"
)

func TestNestedBuildAndInit(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("not woven")
	}
	flags := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if (s.Key == "-race" || s.Key == "-asan" || s.Key == "-msan") && s.Value == "true" {
				flags[s.Key] = s.Value
			}
		}
	}
	toolPath, err := exec.Command("go", "tool", "-n", build.Tool()).Output()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "initprog")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	args := []string{"go", "build"}
	for _, flag := range []string{"-race", "-asan", "-msan"} {
		if flags[flag] == "true" {
			args = append(args, flag)
		}
	}
	args = append(args, "-o", out, "./cmd/initprog")
	cmd := exec.Command(strings.TrimSpace(string(toolPath)), args...)
	cmd.Env = append(os.Environ(), "OTELC_WORK_DIR="+t.TempDir())
	start := time.Now()
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nested build: %v\n%s", err, data)
	}
	t.Logf("nested %s build: %s", build.Tool(), time.Since(start))
	run := func(enabled bool) (uint64, string) {
		cmd := exec.Command(out)
		cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1", "GOMAXPROCS=1", "DD_TRACE_ENABLED=false", fmt.Sprintf("DD_IAST_TAINT_TRACKING_ENABLED=%t", enabled))
		data, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("program: %v\n%s", err, data)
		}
		text := string(data)
		if !strings.Contains(text, "tool="+build.Tool()) {
			t.Fatalf("wrong tool:\n%s", text)
		}
		if !strings.Contains(text, "init github.com/DataDog/dd-iast-go/internal/taint/heapranges ") {
			t.Fatalf("init did not run:\n%s", text)
		}
		for _, flag := range []string{"-race", "-asan", "-msan"} {
			if strings.Contains(text, flag+"=true") != (flags[flag] == "true") {
				t.Fatalf("wrong %s:\n%s", flag, text)
			}
		}
		for _, f := range strings.Fields(text) {
			if strings.HasPrefix(f, "other=") {
				value, err := strconv.ParseUint(strings.TrimPrefix(f, "other="), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return value, text
			}
		}
		t.Fatalf("no memory stats:\n%s", text)
		return 0, text
	}
	off, _ := run(false)
	on, _ := run(true)
	t.Logf("OtherSys: off=%d on=%d", off, on)
	if flags["-race"] != "true" && flags["-asan"] != "true" && flags["-msan"] != "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && on < off+(1<<20) {
		t.Fatalf("OtherSys did not increase by 1 MiB: off=%d on=%d", off, on)
	}
}
