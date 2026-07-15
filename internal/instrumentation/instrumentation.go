// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package instrumentation

import (
	"github.com/DataDog/dd-trace-go/v2/instrumentation"
)

const packageName = "DataDog/dd-iast-go"

var (
	pkg     = instrumentation.Package(packageName)
	pkgInfo = instrumentation.PackageInfo{
		TracedPackage: "github.com/DataDog/dd-iast-go",
		IsStdLib:      false,
		EnvVarPrefix:  "DD_IAST",
	}
	Instance = instrumentation.RegisterAndLoad(pkg, pkgInfo)
)

const (
	TelemetryNamespaceIAST        = "iast"
	TelemetryTagSourceType        = "source_type"
	TelemetryTagVulnerabilityType = "vulnerability_type"
)

type TelemetryMetrics = instrumentation.TelemetryMetrics
