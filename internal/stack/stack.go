// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package stack

import (
	"iter"
	"runtime"
	"strings"
)

// Frames returns an [iter.Seq] of [runtime.Frame] values starting from the
// caller's frame; and ignoring any frame located in "<generated>" files.
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
				if frame.File == "<generated>" {
					continue
				}
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

// MethodAndTypeFrom parses a [runtime.Frame.Function] name into its package,
// receiver and function using zero-allocation string operations.
//
// Handles various Go symbol formats:
//   - Simple function: pkg.Function
//   - Method with receiver: pkg.(*Type).Method or pkg.(Type).Method
//   - Lambda/closure: pkg.Function.func1 or pkg.(*Type).Method.func1
//   - Generics: pkg.(*Type[...]).Method or pkg.Function[...]
//
// Examples:
//
//	github.com/DataDog/dd-trace-go/v2/internal/stacktrace.(*Event).NewException
//	  -> package: github.com/DataDog/dd-trace-go/v2/internal/stacktrace
//	  -> receiver: *Event
//	  -> function: NewException
//	github.com/DataDog/dd-trace-go/v2/internal/stacktrace.TestFunc.func1
//	  -> package: github.com/DataDog/dd-trace-go/v2/internal/stacktrace
//	  -> receiver: ""
//	  -> function: TestFunc.func1
func MethodAndTypeFrom(name string) (receiver string, function string) {
	if idx := strings.Index(name, ".("); idx != -1 {
		receiverEnd := strings.IndexByte(name[idx+2:], ')')
		if receiverEnd != -1 {
			return name[:idx+2+receiverEnd], name[idx+2+receiverEnd+2:]
		}
	}
	return "", name
}
