// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"context"
	"math"
	"math/bits"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/puzpuzpuz/xsync/v4"
)

func TestOrphanRegistryStartSize(t *testing.T) {
	if os.Getenv("DD_IAST_TEST_ORPHAN_REGISTRY_CHILD") != "1" {
		t.Skip("child process only")
	}
	got := spans.OrphanRegistryStatsForTest().RootBuckets
	want := xsync.NewMap[int, int]().Stats().RootBuckets
	if got != want {
		t.Fatalf("root buckets=%d, want %d", got, want)
	}
}

func TestStartupWithLargeCapacitySettings(t *testing.T) {
	for _, capacity := range []int{1 << (bits.UintSize - 2), math.MaxInt - 16, math.MaxInt} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOrphanRegistryStartSize$", "-test.v")
			for _, env := range os.Environ() {
				if !strings.HasPrefix(env, "DD_IAST_MAX_CONCURRENT_REQUESTS=") && !strings.HasPrefix(env, "DD_IAST_TEST_ORPHAN_REGISTRY_CHILD=") {
					cmd.Env = append(cmd.Env, env)
				}
			}
			cmd.Env = append(cmd.Env, "DD_IAST_MAX_CONCURRENT_REQUESTS="+strconv.Itoa(capacity), "DD_IAST_TEST_ORPHAN_REGISTRY_CHILD=1")
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "--- PASS: TestOrphanRegistryStartSize") {
				t.Fatalf("child: %v\n%s", err, out)
			}
		})
	}
}
