// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import "testing"

func TestReviewStaleOwnerCannotMisidentifyAndChargeReusedSlot(t *testing.T) {
	// Given: a completed owner slot has been acquired by a different request.
	s := New()
	stale := s.Acquire()
	previousID := stale.ID()
	stale.Finish()
	live := s.Acquire()
	defer live.Finish()
	if live.Disabled() || live.ID() == previousID {
		t.Fatal("expected a distinct live owner")
	}

	// When: a late caller queries the stale owner and records a dropped read.
	staleID := stale.ID()
	stale.RecordBytesDrop()
	t.Logf("previous ID=%d new ID=%d stale.ID()=%d new owner bytes drops=%d",
		previousID, live.ID(), staleID, live.Counters().Bytes)

	// Then: neither identity nor telemetry may be attributed to the new owner.
	if staleID != 0 || live.Counters().Bytes != 0 {
		t.Fatal("stale owner handle exposed a new identity and changed its counters")
	}
}
