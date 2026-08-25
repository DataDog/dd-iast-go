// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestWholeFeaturePhase2MemoryBound(t *testing.T) {
	fixed := unsafe.Sizeof(store.Store{}) + unsafe.Sizeof(Manager{})
	total := fixed + uintptr(store.ProcessRootBytes)
	t.Logf("store=%d manager=%d fixed=%d total=%d", unsafe.Sizeof(store.Store{}), unsafe.Sizeof(Manager{}), fixed, total)
	require.LessOrEqual(t, total, uintptr(24<<20))
}

// TestCollisionComparesFullValues forces two distinct sources that hash to the
// same index slot and verifies that full equality distinguishes them.
func TestCollisionComparesFullValues(t *testing.T) {
	tab := New()
	origin := constants.OriginHttpRequestParameter
	name := "q"

	// Find two distinct values that collide on the same slot for this table's
	// randomized seed. With 512 slots the birthday bound makes this trivial.
	slotOf := func(value string) uint32 { return tab.hash(origin, name, value) }
	seen := make(map[uint32]string)
	var v1, v2 string
	for i := 0; ; i++ {
		v := fmt.Sprintf("value-%d", i)
		slot := slotOf(v)
		if prev, ok := seen[slot]; ok && prev != v {
			v1, v2 = prev, v
			break
		}
		seen[slot] = v
	}
	require.Equal(t, slotOf(v1), slotOf(v2), "the two values must collide on the same slot")
	require.NotEqual(t, v1, v2)

	r1 := tab.Add(origin, name, v1)
	r2 := tab.Add(origin, name, v2)
	require.Equal(t, AddAdded, r1.Status)
	require.Equal(t, AddAdded, r2.Status)
	require.NotEqual(t, r1.ID, r2.ID, "colliding-but-distinct sources must get distinct IDs")
	require.Equal(t, 2, tab.Len())

	// Re-adding each colliding source returns its own ID, proving full-value
	// comparison resolves the collision rather than matching on the slot alone.
	r1b := tab.Add(origin, name, v1)
	require.Equal(t, AddDuplicate, r1b.Status)
	require.Equal(t, r1.ID, r1b.ID)

	r2b := tab.Add(origin, name, v2)
	require.Equal(t, AddDuplicate, r2b.Status)
	require.Equal(t, r2.ID, r2b.ID)

	// The records are retrievable and exact.
	got1, ok := tab.Get(r1.ID)
	require.True(t, ok)
	require.Equal(t, Source{Origin: origin, Name: name, Value: v1}, got1)
	got2, ok := tab.Get(r2.ID)
	require.True(t, ok)
	require.Equal(t, Source{Origin: origin, Name: name, Value: v2}, got2)
}

// TestHashDoesNotAllocate guards the allocation-free probe path indirectly by
// checking the hash helper itself.
func TestHashDoesNotAllocate(t *testing.T) {
	tab := New()
	allocs := testing.AllocsPerRun(100, func() {
		_ = tab.hash(constants.OriginHttpRequestParameter, "name", "value")
	})
	require.Equal(t, float64(0), allocs)
}
