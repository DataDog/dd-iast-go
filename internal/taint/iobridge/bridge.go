// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package iobridge is the dependency-minimal bridge imported into io and bufio.
package iobridge

import "sync/atomic"

type callbacks struct {
	propagate func(any, any)
	readAll   func(any, []byte)
}

var registered atomic.Pointer[callbacks]

// Register installs reader callbacks during package initialization.
func Register(propagate func(any, any), readAll func(any, []byte)) {
	if propagate == nil || readAll == nil {
		return
	}
	registered.Store(&callbacks{propagate: propagate, readAll: readAll})
}

// Propagate transfers reader ownership from input to output.
func Propagate(input, output any) {
	callback := registered.Load()
	if callback != nil {
		callback.propagate(input, output)
	}
}

// ReadAll adopts a complete owned result without changing its slice identity.
func ReadAll(input any, data []byte) {
	callback := registered.Load()
	if callback != nil {
		callback.readAll(input, data)
	}
}
