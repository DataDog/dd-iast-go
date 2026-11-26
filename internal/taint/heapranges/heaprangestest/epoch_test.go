// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func TestEpochAnnouncement(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires a woven build")
	}
	if knobs.CheckEpoch == nil || !knobs.CheckEpoch() {
		t.Fatal("epoch announcement was not set and cleared")
	}
}
