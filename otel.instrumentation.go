// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

// This is the otelc "tool file" of this module. otelc reads it each time an
// application imports ANY package of this module, so the rules that every
// detection needs are always loaded, also when the application imports only a
// sub-package (for example github.com/DataDog/dd-iast-go/iast/crypto/hash).
//
// Only import the "core" rule packages here. Never import a package of a
// detection (iast/...): an application that imports the root package already
// loads all the rule files below this directory, and one that imports a single
// detection must not get the others.
//
// This needs otelc >= v1.2.1-0 (each rule file is loaded one time only). Outside
// workspace mode, otelc does not use the vendor directory (it builds with
// -mod=mod), so this file is read from the module cache. A build that has only the vendor directory
// (offline) is not supported.

package ddiast

import (
	_ "github.com/DataDog/dd-iast-go/instrumentation/spans" // Reports the vulnerabilities when a span finishes
	_ "github.com/DataDog/dd-iast-go/internal/build"        // Marks the build as instrumented
)
