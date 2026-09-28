// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import "sync/atomic"

var forceWriterLockFail atomic.Bool // test seam

func validKey(key Key) bool {
	return key.Pointer != 0 && key.Length > 0 && (key.Kind == KindString || key.Kind == KindBytes || key.Kind == KindRunes)
}

func inWindow(pointer uintptr, length uint32, base uintptr, span uint32) (uint32, bool) {
	rootEnd := base + uintptr(span)
	if rootEnd < base || pointer < base {
		return 0, false
	}
	valueEnd := pointer + uintptr(length)
	if valueEnd < pointer || valueEnd > rootEnd {
		return 0, false
	}
	offset := pointer - base
	if offset > uintptr(^uint32(0)) {
		return 0, false
	}
	return uint32(offset), true
}

func reserveInt64(counter *atomic.Int64, amount, limit int64) bool {
	for {
		current := counter.Load()
		if amount < 0 || amount > limit-current {
			return false
		}
		if counter.CompareAndSwap(current, current+amount) {
			return true
		}
	}
}
