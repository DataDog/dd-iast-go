// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package scopebridge is the dependency-minimal request-scope lifecycle bridge.
package scopebridge

import "sync/atomic"

type callback struct {
	finish func(uint8, uint64, uint64)
}

var registered atomic.Pointer[callback]

// Register installs the process scope-finish callback during initialization.
func Register(finish func(uint8, uint64, uint64)) {
	if finish != nil {
		registered.Store(&callback{finish: finish})
	}
}

// Finish invalidates external state for one exact analysis owner generation.
func Finish(index uint8, id, generation uint64) {
	callback := registered.Load()
	if callback != nil && id != 0 && generation != 0 {
		callback.finish(index, id, generation)
	}
}
