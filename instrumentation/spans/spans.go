// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package spans is the public anchor of the otelc rule that calls IAST when a
// tracer span finishes (see otelc.yml). It only exists because the otelc build
// tool needs a public package to copy the linkname declaration file from, and
// to link the implementation in the application. It has no API.
package spans

import (
	// Link the implementation that the injected code calls.
	_ "github.com/DataDog/dd-iast-go/internal/spans"
)
