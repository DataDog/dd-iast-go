// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"testing"
	"unsafe"
)

func TestClearUnwoven(t *testing.T) {
	if runtimeClear != nil {
		t.Skip("requires an unwoven build")
	}
	value := [4]byte{1, 2, 3, 4}
	Clear(nil, 0)
	Clear(unsafe.Pointer(&value[0]), uintptr(len(value)))
	if value != [4]byte{1, 2, 3, 4} {
		t.Fatal("Clear changed the bytes")
	}
}
