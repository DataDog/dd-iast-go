// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

// This module has only the runtime aspect and one source aspect (net/http)
// of dd-iast-go. The net/http aspect does not import the propagation package,
// so the link fixture checks that the runtime aspect alone links the
// propagation callbacks (plan runtime-operator-hooks, section 3.2 rule 6).
package testapp

import (
	_ "github.com/DataDog/orchestrion" // integration

	_ "github.com/DataDog/dd-iast-go/iast/net/http"      // integration
	_ "github.com/DataDog/dd-iast-go/iast/runtime"       // integration
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer" // integration
)
