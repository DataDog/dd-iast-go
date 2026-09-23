// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

package overhead

import (
	_ "github.com/DataDog/dd-iast-go"                      // integration
	_ "github.com/DataDog/dd-trace-go/contrib/net/http/v2" // integration
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"   // integration
	_ "github.com/DataDog/orchestrion"                     // integration
)
