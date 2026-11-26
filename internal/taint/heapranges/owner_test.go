// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "testing"

func TestOwnerEncoding(t *testing.T) {
	for _, tc := range []struct {
		slot       uint32
		generation uint64
		valid      bool
	}{
		{0, 1, true},
		{MaxOwners - 1, MaxGeneration, true},
		{MaxOwners, 1, false},
		{0, 0, false},
		{0, MaxGeneration + 1, false},
	} {
		owner := OwnerOf(tc.slot, tc.generation)
		if (owner != NoOwner) != tc.valid {
			t.Fatalf("OwnerOf(%d, %d) = %d", tc.slot, tc.generation, owner)
		}
		if tc.valid {
			origin := Origin(uint64(owner) | 0xff<<46 | 1<<54)
			if origin.Owner() != owner {
				t.Fatalf("origin %x: owner = %x, want %x", origin, origin.Owner(), owner)
			}
		}
	}
	if got := Origin(63<<40 | 1<<54).Owner(); got != Owner(63<<40) {
		t.Fatalf("owner bits = %x, want %x", got, Owner(63<<40))
	}
	if Origin(1<<54).Owner() != NoOwner {
		t.Fatal("unknown origin has a nonzero owner")
	}
}

func TestOwnerFunctionsWhenNotWoven(t *testing.T) {
	if runtimeStartOwner != nil || runtimeEndOwner != nil || runtimeOwnerLive != nil {
		t.Skip("requires an unwoven build")
	}
	if StartOwner(0, 1) || OwnerLive(0, 1) || EndOwner(0, 1) {
		t.Fatal("unwoven owner operation succeeded")
	}
}
