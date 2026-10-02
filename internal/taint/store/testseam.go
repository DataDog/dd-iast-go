// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

// This file has the test seams of the store for tests in other packages. Only
// tests call the functions that end in "ForTest". The linker removes them
// from a program that does not call them. They use the testHook seam, which
// the store reads already, or the existing locks, so they add no cost to
// production code.

// ForceIndexFullForTest makes the index refuse each new root of each store:
// the first adoption fails with an indexFull drop (plan runtime-operator-hooks,
// section 9.1 item 4b). It returns false when another test hook is installed.
// Call restore to remove the seam.
func ForceIndexFullForTest() (restore func(), ok bool) {
	hook := func(stage hookStage, _ int) bool { return stage == hookFirstInsert }
	if !testHook.CompareAndSwap(nil, &hook) {
		return func() {}, false
	}
	return func() { testHook.CompareAndSwap(&hook, nil) }, true
}

// HoldBindingTableForTest takes the write lock of the binding table of owner,
// until release is called. Then each reader lookup that reaches owner is
// incomplete (plan encoding-json-v2, section 6.5, rule (b)). It returns a
// release that does nothing when owner is nil or disabled.
//
// +checklocksignore: the lock is held until release.
func HoldBindingTableForTest(owner *Owner) (release func()) {
	if owner == nil || owner.Disabled() {
		return func() {}
	}
	table := &owner.owner.bindings
	table.mu.Lock()
	return table.mu.Unlock
}
