// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

const (
	// MaxOwners is the number of owner slots.
	MaxOwners = 64
	// MaxGeneration is the largest owner generation.
	MaxGeneration = 1<<40 - 1
)

// Owner identifies a request by slot and generation.
type Owner uint64

// NoOwner identifies no request.
const NoOwner Owner = 0

// OwnerOf returns the owner for a valid slot and generation.
func OwnerOf(slot uint32, generation uint64) Owner {
	if slot >= MaxOwners || generation == 0 || generation > MaxGeneration {
		return NoOwner
	}
	return Owner(uint64(slot)<<40 | generation)
}

// Owner returns the request owner of the origin.
func (origin Origin) Owner() Owner {
	return Owner(uint64(origin) & (1<<46 - 1))
}

var (
	runtimeStartOwner func(uint32, uint64) bool
	runtimeEndOwner   func(uint32, uint64) bool
	runtimeOwnerLive  func(uint32, uint64) bool
)

// StartOwner marks an unused slot and generation as live.
func StartOwner(slot uint32, generation uint64) bool {
	return runtimeStartOwner != nil && runtimeStartOwner(slot, generation)
}

// EndOwner marks the owner as ended and retires its snapshot area.
func EndOwner(slot uint32, generation uint64) bool {
	return runtimeEndOwner != nil && runtimeEndOwner(slot, generation)
}

// OwnerLive reports whether the slot has the given live generation.
func OwnerLive(slot uint32, generation uint64) bool {
	return runtimeOwnerLive != nil && runtimeOwnerLive(slot, generation)
}
