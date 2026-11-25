// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/build"
)

var (
	binaryDir    string
	initOnce     sync.Once
	initBinary   string
	initBuildErr error
)

func TestMain(m *testing.M) {
	var err error
	binaryDir, err = os.MkdirTemp("", "heapranges-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := os.RemoveAll(binaryDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func buildSettings() map[string]string {
	settings := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "-race", "-asan", "-msan":
				settings[setting.Key] = setting.Value
			}
		}
	}
	return settings
}

func initProgram(t *testing.T) string {
	t.Helper()
	initOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		tool := build.Tool()
		output, err := exec.CommandContext(ctx, "go", "tool", "-n", tool).CombinedOutput()
		if err != nil {
			initBuildErr = fmt.Errorf("find %s: %w: %s", tool, err, output)
			return
		}
		initBinary = filepath.Join(binaryDir, "initprog")
		args := []string{"go", "build"}
		for _, flag := range []string{"-race", "-asan", "-msan"} {
			if buildSettings()[flag] == "true" {
				args = append(args, flag)
			}
		}
		args = append(args, "-o", initBinary, "./internal/initprog")
		cmd := exec.CommandContext(ctx, strings.TrimSpace(string(output)), args...)
		cache := filepath.Join(binaryDir, "cache")
		if err := os.Mkdir(cache, 0755); err != nil {
			initBuildErr = err
			return
		}
		cmd.Env = append(os.Environ(), "GOCACHE="+cache)
		if tool == build.ToolOtelc {
			work, err := os.MkdirTemp(binaryDir, "otelc-")
			if err != nil {
				initBuildErr = err
				return
			}
			cmd.Env = append(cmd.Env, "OTELC_WORK_DIR="+work)
		}
		output, err = cmd.CombinedOutput()
		if err != nil {
			initBuildErr = fmt.Errorf("build init program (timeout 5m): %w: %s", err, output)
		}
	})
	if initBuildErr != nil {
		t.Fatal(initBuildErr)
	}
	return initBinary
}
