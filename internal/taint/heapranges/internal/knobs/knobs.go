// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package knobs provides test-only access to the woven runtime.
package knobs

var (
	Gate           func() uint32
	OffReason      func() string
	MapSlab        func(bool) (bool, uint64)
	InitSlabWorker func(uint64) (uint32, uint64, bool)
	QueueEntry     func(uint32) uint32
	PublishSlab    func(uintptr) bool
	AllocateUnits  func(uint32) uint32
	TailUnits      func() uint64
	SlabAddress    func(uint32) uintptr
	ReadySlabs     func() uint32
	RefillOnce     func()
	WorkerStats    func() (uint32, uint64)
	StartRefiller  func()
	PauseRefiller  func(bool)
)
