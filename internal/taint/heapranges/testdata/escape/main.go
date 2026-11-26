// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
)

var result bool
var sink unsafe.Pointer

//go:noinline
func staysOnStack() {
	var target [1024]byte
	var ranges [heapranges.MaxRanges]heapranges.Range
	result = heapranges.MayHaveTaint(unsafe.Pointer(&target[0]), uintptr(len(target))) ||
		heapranges.Any(unsafe.Pointer(&target[0]), uintptr(len(target))) ||
		len(heapranges.Ranges(unsafe.Pointer(&target[0]), uintptr(len(target)), ranges[:0])) != 0
}

//go:noinline
func escapes() {
	var control [1024]byte
	sink = unsafe.Pointer(&control[0])
}

func main() {
	staysOnStack()
	escapes()
}
