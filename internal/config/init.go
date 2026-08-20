// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package config

import "github.com/DataDog/dd-iast-go/internal/instrumentation"

func init() {
	load()
	if Enabled {
		instrumentation.Instance.TelemetryProductStarted(instrumentation.TelemetryNamespaceIAST)
	}
}
