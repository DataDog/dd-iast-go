// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package bufio instruments reader-wrapper provenance.
//
// A bufio.Reader that bufio.NewReader or bufio.NewReaderSize makes over a
// reader of one request is exclusive to that request, while its input does
// not change. A Read guard checks the input at each Read.
//
// Known limit: do not copy a bufio.Reader by value. If code copies a
// bufio.Reader, then resets and reads the copy, the two values share one
// buffer. Then IAST can attribute the bytes of the new reader of the copy to
// the request of the original reader.
package bufio

import (
	"bufio"
	"io"

	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
)

// Propagate transfers request-body provenance from input to output after a
// bufio.Reader is created without automatic bufio instrumentation. It requires
// an active input binding from the HTTP source instrumentation. It does nothing
// for nil outputs, reader buffer sizes larger than 4096 bytes, or inputs without
// an active binding. It does not read from either reader.
//
// An unwoven bufio package has no Read guard, thus the binding of output is
// not exclusive. io.ReadAll and the json.Decoder need an exclusive binding,
// thus they do not attribute the bytes of output (decision Q13 of plan
// encoding-json-v2).
func Propagate(input io.Reader, output *bufio.Reader) {
	if output != nil && output.Size() <= iobridge.MaxBufferedReaderSize {
		iobridge.PropagateShared(input, output)
	}
}
