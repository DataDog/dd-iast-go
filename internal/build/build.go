// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package build tells whether the current binary was built with a compile-time
// instrumentation tool (Orchestrion or otelc), and with which one. It is the
// tool-neutral way for tests and telemetry to know if instrumentation is active.
package build

// Tool names returned by [Tool].
const (
	ToolNone        = ""
	ToolOrchestrion = "orchestrion"
	ToolOtelc       = "otelc"
)

// orchestrionEnabled is changed to true at build time by Orchestrion, because
// of the directive below.
//
//orchestrion:enabled
var orchestrionEnabled = false

// otelcEnabled is changed to true at build time by the "assign_value"-style
// rule in the otelc.yml file of this package.
var otelcEnabled = false

// Instrumented returns true if the current binary was built with Orchestrion or
// with otelc.
func Instrumented() bool {
	return orchestrionEnabled || otelcEnabled
}

// Tool returns the name of the tool that built the current binary: one of
// [ToolOrchestrion], [ToolOtelc], or [ToolNone].
func Tool() string {
	switch {
	case orchestrionEnabled:
		return ToolOrchestrion
	case otelcEnabled:
		return ToolOtelc
	default:
		return ToolNone
	}
}
