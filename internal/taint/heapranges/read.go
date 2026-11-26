// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "unsafe"

var runtimeAny func(unsafe.Pointer, uintptr) bool

// Any reports whether the range might contain taint.
func Any(p unsafe.Pointer, n uintptr) bool {
	if runtimeAny == nil {
		return false
	}
	return runtimeAny(noescape(p), n)
}
