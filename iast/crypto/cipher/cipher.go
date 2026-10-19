// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package cipher detects cryptographically weak cipher algorithms.
package cipher

import (
	"context"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
)

// Package paths of the instrumented functions. They are also the namespace of
// the stack frames of those functions.
const (
	desPackage      = "crypto/des"
	rc4Package      = "crypto/rc4"
	blowfishPackage = "golang.org/x/crypto/blowfish"
	rc2Package      = "golang.org/x/crypto/pkcs12/internal/rc2"
	pkcs12Package   = "golang.org/x/crypto/pkcs12"
)

// maxSinkFrames is the maximum number of frames that ReportWeakCipher skips
// for one cipher: the explicit frame and the frames of the sink functions.
const maxSinkFrames = 3

// ReportWeakCipher reports use of a cryptographically weak cipher algorithm.
// If skipCallerNamespace, skipCallerClass, and skipCallerMethod identify the
// first candidate location frame, that frame is skipped in favor of its caller.
//
// Code injected by otelc is not marked as generated, so the sink function is
// the first frame of the stack. It is skipped too (see [sinkFrames]).
func ReportWeakCipher(ctx context.Context, name, skipCallerNamespace, skipCallerClass, skipCallerMethod string) {
	// This check is also in vulnerability.Report. It comes first here so that a
	// disabled IAST does not pay for the list of skipped frames.
	if !config.Enabled {
		return
	}

	var buffer [maxSinkFrames]vulnerability.SkipFrame
	skipFrames := append(buffer[:0], vulnerability.SkipFrame{
		Namespace: skipCallerNamespace,
		ClassName: skipCallerClass,
		Function:  skipCallerMethod,
	})
	skipFrames = sinkFrames(skipFrames, name)

	vulnerability.Report(
		ctx,
		constants.VulnerabilityTypeWeakCipher,
		name,
		&telemetry.ExecutedSink.WeakCipher,
		skipFrames...,
	)
}

// sinkFrames appends the stack frames of the instrumented functions that report
// the cipher called name. The list is built with a switch (and not a map) so
// that it needs no run-time initialization: a sink can run before the init
// functions of this package.
func sinkFrames(frames []vulnerability.SkipFrame, name string) []vulnerability.SkipFrame {
	switch name {
	case "DES":
		return append(frames, vulnerability.SkipFrame{Namespace: desPackage, Function: "NewCipher"})
	case "TripleDES":
		return append(frames, vulnerability.SkipFrame{Namespace: desPackage, Function: "NewTripleDESCipher"})
	case "RC4":
		return append(frames, vulnerability.SkipFrame{Namespace: rc4Package, Function: "NewCipher"})
	case "Blowfish":
		// NewSaltedCipher calls NewCipher when the salt is empty.
		return append(frames,
			vulnerability.SkipFrame{Namespace: blowfishPackage, Function: "NewCipher"},
			vulnerability.SkipFrame{Namespace: blowfishPackage, Function: "NewSaltedCipher"},
		)
	case "RC2":
		return append(frames, vulnerability.SkipFrame{Namespace: rc2Package, Function: "New"})
	case "PBEWithSHAAnd3KeyTripleDESCBC":
		return append(frames, vulnerability.SkipFrame{Namespace: pkcs12Package, ClassName: "shaWithTripleDESCBC", Function: "create"})
	case "PBEWithSHAAnd40BitRC2CBC":
		return append(frames, vulnerability.SkipFrame{Namespace: pkcs12Package, ClassName: "shaWith40BitRC2CBC", Function: "create"})
	default:
		return frames
	}
}

// RegisterInstrumentedSinks records that count weak cipher sinks were
// instrumented during the build. It is called with //go:linkname from the "init"
// function of the files that otelc copies into the instrumented packages (see
// the otelc_decl_*.go files).
//
// Those init functions can run before the init functions of this package and of
// every package it imports. This function therefore MUST NOT touch any value
// that needs run-time initialization: it only adds to a fixed-size array that
// is zero at load time.
func RegisterInstrumentedSinks(count uint) {
	telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakCipher] += count
}
