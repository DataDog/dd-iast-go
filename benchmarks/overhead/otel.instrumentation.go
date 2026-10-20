// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

// This is the otelc tool file of the benchmark module. It is the otelc
// counterpart of orchestrion.tool.go. The runner removes the dd-iast-go import
// to build the control variant.
//
// dd-trace-go does not have otelc rules for contrib/net/http yet, so this file
// cannot import it: the otelc variants do not trace net/http.

package overhead

import (
	_ "github.com/DataDog/dd-iast-go"                                  // integration
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"               // integration
	_ "github.com/DataDog/dd-trace-go/v2/instrumentation/appsec/dyngo" // integration
)
