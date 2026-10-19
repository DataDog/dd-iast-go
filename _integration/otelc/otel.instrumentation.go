// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

// This is the "tool file" of an application that is built with otelc. It selects
// the instrumentation rules to apply.

package otelc

import (
	_ "github.com/DataDog/dd-iast-go"                                  // IAST rules
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"               // tracer rules
	_ "github.com/DataDog/dd-trace-go/v2/instrumentation/appsec/dyngo" // AppSec GLS rules
)
