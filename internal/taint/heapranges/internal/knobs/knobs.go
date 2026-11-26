// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package knobs provides test-only access to the woven runtime.
package knobs

import "unsafe"

var (
	CheckEpoch     func() bool
	Gate           func() uint32
	SetGate        func(uint32)
	SetProbe       func(unsafe.Pointer, uintptr)
	OffReason      func() string
	MapSlab        func(bool) (bool, uint64)
	InitSlabWorker func(uint64) (uint32, uint64, bool)
	MakeRecord     func(uint32, uint32, uint32) uint32
	CompareEntry   func(unsafe.Pointer, uint32, uint32) bool
	ReadEntry      func(unsafe.Pointer) uint32
	SpanState      func(unsafe.Pointer) uint64
	BindTable      func(uint32, uintptr) bool
	SpanRead       func(uint32) bool
	TableBase      func(uint32) uint64
	TableEntry     func(uint32, uint32, uint32, bool) uint32
	Classify       func(unsafe.Pointer, uintptr) (uintptr, uintptr, uint32, bool)
	ClassifyStack  func() bool
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
