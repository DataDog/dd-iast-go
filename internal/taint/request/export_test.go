// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import "unsafe"

// AttributeBytesBusy is [Analysis.AttributeBytes] for the external tests. It
// also reports whether this call counted a busy drop (the own slot stayed
// busy for all the attempts): the reason of a miss of this call, not of a
// call of a different goroutine.
func AttributeBytesBusy(a Analysis, b []byte, r *Attribution) (strong, busy bool) {
	strong, result := a.attributeAccess(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)), r)
	return strong, result == accessBusy
}
