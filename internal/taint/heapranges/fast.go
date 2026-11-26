// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "unsafe"

var runtimeMayHaveTaint func(unsafe.Pointer, uintptr) bool

//go:linkname noescape runtime.noescape
//go:noescape
func noescape(unsafe.Pointer) unsafe.Pointer

// MayHaveTaint reports whether the allocation may contain taint.
func MayHaveTaint(p unsafe.Pointer, n uintptr) bool {
	if runtimeMayHaveTaint == nil {
		return false
	}
	return runtimeMayHaveTaint(noescape(p), n)
}
