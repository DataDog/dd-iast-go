// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

// This is the tool file of an application that imports ONLY one sub-package of
// dd-iast-go. The core rules (build flag, span finish) must still be loaded.

package setup

import (
	// The rules of dd-trace-go are imported first. The order of its rule and our
	// rule on (*Span).Finish is then the reverse of the "root" setup, and the
	// result must be the same.
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"               // tracer rules
	_ "github.com/DataDog/dd-trace-go/v2/instrumentation/appsec/dyngo" // AppSec GLS rules

	_ "github.com/DataDog/dd-iast-go/iast/crypto/hash" // Weak hash detection only
)
