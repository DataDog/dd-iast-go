// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

var (
	runtimeAttachSnapshot func(uint32, uint64) bool
	runtimeRetireSnapshot func(uint32, uint64) bool
)

// AttachSnapshotArea reserves an area for the given owner generation.
func AttachSnapshotArea(slot uint32, generation uint64) bool {
	return runtimeAttachSnapshot != nil && runtimeAttachSnapshot(slot, generation)
}

// RetireSnapshotArea detaches the area of the given owner generation.
func RetireSnapshotArea(slot uint32, generation uint64) bool {
	return runtimeRetireSnapshot != nil && runtimeRetireSnapshot(slot, generation)
}
