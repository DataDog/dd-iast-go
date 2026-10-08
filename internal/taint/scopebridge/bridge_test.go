// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package scopebridge

import "testing"

func TestFinish(t *testing.T) {
	previous := registered.Load()
	t.Cleanup(func() { registered.Store(previous) })
	registered.Store(nil)
	Finish(1, 2, 3)
	var gotIndex uint8
	var gotID, gotGeneration uint64
	Register(func(index uint8, id, generation uint64) {
		gotIndex, gotID, gotGeneration = index, id, generation
	})
	Finish(4, 5, 6)
	if gotIndex != 4 || gotID != 5 || gotGeneration != 6 {
		t.Fatalf("callback = (%d, %d, %d)", gotIndex, gotID, gotGeneration)
	}
	Finish(7, 0, 8)
	if gotIndex != 4 {
		t.Fatal("zero identity invoked callback")
	}
}
