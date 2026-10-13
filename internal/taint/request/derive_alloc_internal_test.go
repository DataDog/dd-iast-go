// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/stretchr/testify/require"
)

// TestDerivedCallDoesNotAllocate calls each derive rule again for an output
// that already has its derived entry. The call then only updates the entry,
// thus it must not allocate. When the attribution or the segments of
// deriveAll move to the heap, each call allocates (about 5 KB).
func TestDerivedCallDoesNotAllocate(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	a := newAnalysis(t, m)
	input := taintBytes(t, a, "q", "ab")
	owner, ok := a.Owner()
	require.True(t, ok)
	runes := make([]rune, len(input))
	cases := []struct {
		name string
		out  []byte
		call func(out []byte)
	}{
		{"positional", heapBytes("ab"), func(out []byte) {
			m.derived(unsafeData(out), uintptr(len(out)), unsafeData(input), uintptr(len(input)), propbridge.Positional)
		}},
		{"coarse", heapBytes("<ab>"), func(out []byte) {
			m.derived(unsafeData(out), uintptr(len(out)), unsafeData(input), uintptr(len(input)), propbridge.Coarse)
		}},
		{"runes", unsafe.Slice((*byte)(unsafe.Pointer(&runes[0])), 4*len(runes)), func(out []byte) {
			m.runes(unsafeData(out), uintptr(len(out)), unsafeData(input), uintptr(len(input)), propbridge.RunesFromString)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.set(uintptr(unsafeData(c.out)), uintptr(len(c.out)))
			// The first call adds the entry, and can allocate its owner
			// copy of the output.
			c.call(c.out)
			var r Attribution
			analysis, ok := m.Analysis(owner)
			require.True(t, ok)
			require.True(t, analysis.AttributeBytes(c.out, &r), "the first call added no derived entry")
			require.Zero(t, testing.AllocsPerRun(100, func() { c.call(c.out) }))
		})
	}
}

// TestDeriveAllStaysOnTheStack is the compiler guard of the test above: the
// escape analysis of this package must not move a variable of derive.go to
// the heap. It runs the compiler, thus -short skips it.
func TestDeriveAllStaysOnTheStack(t *testing.T) {
	if testing.Short() {
		t.Skip("the compiler run is slow: -short skips it")
	}
	gocmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not available")
	}
	// The go command replays the compiler output of a cached build, thus
	// the output is complete also for a cached package.
	cmd := exec.Command(gocmd, "build", "-gcflags=-m", "-o", os.DevNull, ".")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go build -gcflags=-m:\n%s", out)
	seen := false
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "derive.go:") {
			continue
		}
		seen = true
		if strings.Contains(line, "moved to heap") {
			t.Errorf("derive.go has a heap move: %s", line)
		}
	}
	require.True(t, seen, "the compiler output has no line for derive.go:\n%s", out)
}
