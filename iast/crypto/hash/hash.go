// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hash

import (
	"context"
	"crypto"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
)

// ReportWeakHash reports use of a cryptographically weak hash algorithm.
func ReportWeakHash(ctx context.Context, hash crypto.Hash) {
	vulnerability.Report(
		ctx,
		constants.VulnerabilityTypeWeakHash,
		hash.String(),
		&telemetry.ExecutedSink.WeakHash,
		vulnerability.SkipFrame{Namespace: "crypto", ClassName: "", Function: "Hash.New"},
		// Code injected by otelc is not marked as generated, so the sink
		// function itself is the first frame, and it must be skipped.
		sinkFrame(hash, "New"),
		sinkFrame(hash, "Sum"),
	)
}

// sinkFrame returns the stack frame of the function of the standard library
// (or x/crypto) package that implements hash, which is instrumented.
func sinkFrame(hash crypto.Hash, function string) vulnerability.SkipFrame {
	var namespace string
	switch hash {
	case crypto.MD4:
		namespace = "golang.org/x/crypto/md4"
	case crypto.MD5:
		namespace = "crypto/md5"
	case crypto.SHA1:
		namespace = "crypto/sha1"
	}
	return vulnerability.SkipFrame{Namespace: namespace, Function: function}
}

// RegisterInstrumentedSinks records that count weak hash sinks were instrumented
// during the build. It is called with //go:linkname from the "init" function of
// the files that otelc copies into the instrumented packages (see
// otelc_decl_md5.go).
//
// Those init functions can run before the init functions of this package and of
// every package it imports. This function therefore MUST NOT touch any value
// that needs run-time initialization: it only adds to a fixed-size array that
// is zero at load time.
func RegisterInstrumentedSinks(count uint) {
	telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakHash] += count
}
