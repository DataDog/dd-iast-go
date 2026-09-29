// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// hookStats returns the number of sweep hooks between two counts, and the
// 99th percentile and the maximum of their durations (at most the last 4096
// hooks).
func hookStats(before, after uint64, ring [4096]uint64) (n uint64, p99, maxNs uint64) {
	n = after - before
	if n == 0 {
		return 0, 0, 0
	}
	k := min(n, uint64(len(ring)))
	d := make([]uint64, 0, k)
	for i := after - k; i < after; i++ {
		d = append(d, ring[i%uint64(len(ring))])
	}
	slices.Sort(d)
	return n, d[(len(d)*99)/100], d[len(d)-1]
}

// sweepScenarios are the worst cases of plan section 7.1 for the sweep hook:
// each one prepares tainted objects and makes some of them die, so that the
// next GC cycles run the hook on them.
var sweepScenarios = map[string]func(t testing.TB){
	// A dead 64 MiB object (the largest taintable span), fully tainted: 512
	// chunks are recycled.
	"64MiB dead, full taint": func(t testing.TB) {
		taintedObject(t, 64<<20)
	},
	// 2 dead 64 MiB objects whose chunks come from the slabs in turn (one
	// chunk for A, then one for B): 2 sweepers can recycle them at the same
	// time, on the same slab descriptors.
	"2x64MiB dead, interleaved chunks": func(t testing.TB) {
		a, b := heapBytes(64<<20), heapBytes(64<<20)
		for off := 0; off < len(a); off += 128 << 10 {
			mustSet(t, a[off:off+1])
			mustSet(t, b[off:off+1])
		}
	},
	// A dead 64 MiB object with one late tainted byte.
	"64MiB dead, one byte": func(t testing.TB) {
		b := heapBytes(64 << 20)
		mustSet(t, b[len(b)-1:])
	},
	// A live 64 MiB object with its taint cleared: the flag stays (whole
	// chunks inside), each GC runs the hook on it.
	"64MiB live, taint then clear": func(t testing.TB) {
		b := heapBytes(64 << 20)
		mustSet(t, b)
		heapbits.ClearBytes(b)
		latencyKeep = append(latencyKeep, b)
	},
	// Small objects, all tainted, every second one dies: the dead pass
	// clears words, the live check finds taint at once.
	"small, half dead": func(t testing.TB) {
		objs := make([]*[64]byte, 8192)
		for i := range objs {
			objs[i] = new64()
			mustSet(t, objs[i][:])
		}
		for i := 0; i < len(objs); i += 2 {
			objs[i] = nil
		}
		latencyKeepSmall = append(latencyKeepSmall, objs)
	},
	// Small objects with sparse taint (1 in 64), all dead.
	"small, sparse, dead": func(t testing.TB) {
		for i := range 8192 {
			o := new64()
			if i%64 == 0 {
				mustSet(t, o[:])
			}
		}
	},
	// Small objects with finalizers (the finalizer check walks the specials).
	"small, finalizers": func(t testing.TB) {
		for range 2048 {
			b := &box{}
			mustSet(t, b.data[:])
			runtime.SetFinalizer(b, func(*box) {})
		}
	},
	// Many live clean objects in flagged spans: the live check runs to its
	// work limit in each span.
	"small, live clean": func(t testing.TB) {
		objs := make([]*ptrObj, 16384)
		for i := range objs {
			objs[i] = newPtrObj()
		}
		for i := 0; i < len(objs); i += 512 {
			b := unsafe.Slice((*byte)(unsafe.Pointer(objs[i])), 8)
			mustSet(t, b)
			heapbits.ClearBytes(b)
		}
		latencyKeepPtr = append(latencyKeepPtr, objs)
	},
}

var (
	latencyKeep      [][]byte
	latencyKeepSmall [][]*[64]byte
	latencyKeepPtr   [][]*ptrObj
)

// latencyScenarioEnv selects one scenario in the child process of
// TestSweepHookLatency.
const latencyScenarioEnv = "HEAPBITS_LATENCY_SCENARIO"

// The latency gate of plan section 5.5: in the worst-case scenarios, the
// sweep hook of one span takes at most 20 µs (99th percentile of the
// measured durations: a few very long ones can be the OS, which can stop
// the thread at any time). On CI runners the limit is 50 µs (see
// latencyLimit).
//
// Each scenario runs in its own child process, so that all the sweep hooks
// that it measures are for the spans of the scenario (no other test made
// taint there). It repeats the scenario until at least 400 hooks ran (at most
// 400 repetitions), so that the 99th percentile is not the maximum.
func TestSweepHookLatency(t *testing.T) {
	need(t)
	if moveMode(t) || raceBuild {
		t.Skip("timing is not meaningful in this build")
	}
	if name := os.Getenv(latencyScenarioEnv); name != "" {
		sweepLatencyChild(t, name)
		return
	}
	if os.Getenv(storageChildEnv) != "" {
		t.Skip("in another child process")
	}
	names := make([]string, 0, len(sweepScenarios))
	for name := range sweepScenarios {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], childArgs("^TestSweepHookLatency$")...)
			cmd.Env = append(os.Environ(), latencyScenarioEnv+"="+name, childEnv+"=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child failed: %v\n%s", err, out)
			}
			for line := range strings.SplitSeq(string(out), "\n") {
				if strings.Contains(line, "sweep hooks;") {
					t.Log(strings.TrimSpace(line))
				}
			}
		})
	}
}

func sweepLatencyChild(t *testing.T, name string) {
	prepare, ok := sweepScenarios[name]
	if !ok {
		t.Fatalf("unknown scenario %q", name)
	}
	if !heapbitstest.Enabled() {
		t.Fatal("test knobs are not enabled")
	}
	heapbits.SetBudget(heapbits.MaxBudget)
	// A second attempt when the first fails: a regression fails both, a
	// burst of OS noise (other processes on a shared machine) does not.
	for attempt := 1; ; attempt++ {
		n, p99, maxNs := sweepLatencyRun(t, prepare)
		t.Logf("%s: %d sweep hooks; 99th percentile %.1f µs; max %.1f µs (attempt %d)", name, n, float64(p99)/1e3, float64(maxNs)/1e3, attempt)
		if n < latencyMinHooks {
			t.Fatalf("only %d sweep hooks ran, want at least %d", n, latencyMinHooks)
		}
		limit := latencyLimit()
		if p99 <= limit {
			return
		}
		if attempt == 2 {
			t.Fatalf("99th percentile of the sweep hook: %.1f µs, want at most %d µs", float64(p99)/1e3, limit/1000)
		}
	}
}

const (
	latencyLimitDev = 20_000 // ns: the limit of plan section 5.5
	latencyLimitCI  = 50_000 // ns: shared CI runners (3 to 5 times slower)
	latencyMinHooks = 400
)

func sweepLatencyRun(t *testing.T, prepare func(testing.TB)) (n, p99, maxNs uint64) {
	before, _ := heapbitstest.SweepDurations()
	for range 400 {
		prepare(t)
		runtime.GC()
		// Keep at most the last 2 retained sets (bounded memory).
		if len(latencyKeep) > 2 {
			latencyKeep = latencyKeep[len(latencyKeep)-2:]
		}
		if len(latencyKeepSmall) > 2 {
			latencyKeepSmall = latencyKeepSmall[len(latencyKeepSmall)-2:]
		}
		if len(latencyKeepPtr) > 2 {
			latencyKeepPtr = latencyKeepPtr[len(latencyKeepPtr)-2:]
		}
		if n, _ := heapbitstest.SweepDurations(); n-before >= latencyMinHooks {
			break
		}
	}
	runtime.GC()
	after, ring := heapbitstest.SweepDurations()
	return hookStats(before, after, ring)
}

// mustSet taints b, and stops the test if the Set fails (a scenario without
// taint would not test the hook).
func mustSet(t testing.TB, b []byte) {
	t.Helper()
	if !heapbits.SetBytes(b) {
		t.Fatalf("Set of %d bytes failed: %+v", len(b), heapbitstest.Stats())
	}
}

// latencyLimit returns the limit of the 99th percentile of the sweep hook:
// 20 µs on a developer machine; 50 µs on a CI runner (environment variable
// CI set), which is slower and shared with other jobs. There the gate finds
// large regressions only.
func latencyLimit() uint64 {
	if os.Getenv("CI") != "" {
		return latencyLimitCI
	}
	return latencyLimitDev
}
