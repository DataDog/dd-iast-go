// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

//go:generate go run github.com/DataDog/orchestrion pin -generate

package ddiast

import (
	_ "github.com/DataDog/orchestrion" // integration

	_ "github.com/DataDog/dd-iast-go/iast/bufio"         // integration
	_ "github.com/DataDog/dd-iast-go/iast/crypto/cipher" // integration
	_ "github.com/DataDog/dd-iast-go/iast/crypto/hash"   // integration
	_ "github.com/DataDog/dd-iast-go/iast/io"            // integration
	_ "github.com/DataDog/dd-iast-go/iast/net/http"      // integration
	_ "github.com/DataDog/dd-iast-go/iast/net/url"       // integration
	_ "github.com/DataDog/dd-iast-go/iast/propagation"   // integration
	_ "github.com/DataDog/dd-iast-go/internal/spans"     // integration
	_ "github.com/DataDog/dd-iast-go/taint"              // integration
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer" // integration
)
