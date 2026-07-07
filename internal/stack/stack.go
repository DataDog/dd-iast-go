// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package stack

import (
	"iter"
	"runtime"
)

func Frames(skip int) iter.Seq[runtime.Frame] {
	const pageSize = 8
	return func(yield func(runtime.Frame) bool) {
		// Adjust skip to remove the calls to [runtime.Callers] and this anonymous
		// function itself, as these are never what we are interested in.
		skip += 2

		var pcs [pageSize]uintptr
		for {
			cnt := runtime.Callers(skip, pcs[:])
			if cnt == 0 {
				return
			}
			frames := runtime.CallersFrames(pcs[:cnt])
			for {
				frame, more := frames.Next()
				if !yield(frame) {
					return
				}
				if !more {
					break
				}
			}
			skip += cnt
		}
	}
}
