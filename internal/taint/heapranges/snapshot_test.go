// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "testing"

func TestSnapshotAreaUnwoven(t *testing.T) {
	if AttachSnapshotArea(0, 1) || RetireSnapshotArea(0, 1) {
		t.Fatal("unwoven snapshot operation succeeded")
	}
}
