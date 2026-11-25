// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !js && !wasip1

package heapranges

import (
	"github.com/DataDog/dd-iast-go/internal/config/parser"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
)

func reportEnvironment(e environment, enabled bool, reason string) {
	for _, value := range e.values[:e.valueCount] {
		if value.name == envVarIASTEnabled {
			continue
		}
		origin := instrumentation.OriginDefault
		if value.origin == parser.OriginEnvVar {
			origin = instrumentation.OriginEnvVar
		}
		instrumentation.Instance.TelemetryRegisterAppConfig(value.name, value.value, origin)
	}
	for _, warning := range e.warnings[:e.warningCount] {
		instrumentation.Instance.Logger().Warn("%s", warning)
	}
	if enabled {
		instrumentation.Instance.Logger().Info("heap taint tracking: on")
	} else {
		instrumentation.Instance.Logger().Info("heap taint tracking: off (%s)", reason)
	}
}
