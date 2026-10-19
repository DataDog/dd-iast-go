// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command app is a minimal application that uses a weak hash. It is used to
// check that an application built with a compile-time instrumentation tool
// starts without panic, and runs the instrumented code.
package main

import (
	"context"
	"crypto/des" //nolint:gosec // Deliberately exercise weak cipher detection.
	"crypto/md5"
	"crypto/sha1"
	"fmt"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// Package-level initializers that run instrumented functions: a sink can run
// before the init functions of dd-iast-go, and it must not panic.
var (
	initialDigest     = md5.Sum([]byte("init"))
	initialSHA1       = sha1.Sum([]byte("init"))
	initialBlock, err = des.NewCipher(make([]byte, 8))
)

func main() {
	// With otelc, dd-trace-go starts the tracer at the top of main (rule
	// "create_tracer"): this code does not start it. A span only has an ID if a
	// tracer is running, and then dd-trace-go also puts the span in the
	// goroutine-local storage, so the sink below finds it with no context.
	span, _ := tracer.StartSpanFromContext(context.Background(), "app")
	tracerStarted := span != nil && span.Context().SpanID() != 0
	active, glsActive := tracer.SpanFromContext(context.Background())
	glsActive = glsActive && active == span
	digest := md5.Sum([]byte("main"))
	span.Finish()
	_, glsActiveAfterFinish := tracer.SpanFromContext(context.Background())
	if build.Tool() == build.ToolOtelc && (!tracerStarted || !glsActive || glsActiveAfterFinish) {
		panic("the tracer or its goroutine-local storage is not working")
	}

	if err != nil || initialBlock.BlockSize() != des.BlockSize {
		panic("DES cipher was not created")
	}
	fmt.Printf("tool=%q tracer_started=%t gls=%t gls_after_finish=%t weak_hash_sinks=%d weak_cipher_sinks=%d initial=%x sha1=%x main=%x\n",
		build.Tool(), tracerStarted, glsActive, glsActiveAfterFinish,
		telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakHash],
		telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakCipher],
		initialDigest[:4], initialSHA1[:4], digest[:4])
}
