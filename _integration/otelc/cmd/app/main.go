// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command app is a minimal application that uses a weak hash. It is used to
// check that an application built with a compile-time instrumentation tool
// starts without panic, and runs the instrumented code.
package main

import (
	"crypto/md5"
	"fmt"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

// A package-level initializer that runs an instrumented function.
var initialDigest = md5.Sum([]byte("init"))

func main() {
	digest := md5.Sum([]byte("main"))
	fmt.Printf("tool=%q weak_hash_sinks=%d initial=%x main=%x\n",
		build.Tool(),
		telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakHash],
		initialDigest[:4], digest[:4])
}
