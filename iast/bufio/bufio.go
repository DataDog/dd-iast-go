// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package bufio instruments reader-wrapper provenance.
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
// not exclusive. Today, io.ReadAll needs an exclusive binding, thus it does
// not attribute the bytes of output. The v1 encoding/json decoder still
// attributes them to each request that is bound to output. After step 3a of
// plan encoding-json-v2, the decoder also needs an exclusive binding.
func Propagate(input io.Reader, output *bufio.Reader) {
	if output != nil && output.Size() <= iobridge.MaxBufferedReaderSize {
		iobridge.PropagateShared(input, output)
	}
}
