// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package heapranges manages taint ranges for heap objects.
// Packages imported by heapranges must not have woven tests: otelc imports
// heapranges into each test package, which would create an import cycle.
package heapranges

import (
	"fmt"

	"github.com/DataDog/dd-iast-go/internal/config/loader"
	"github.com/DataDog/dd-iast-go/internal/config/parser"
)

const (
	EnvVarTrackingEnabled = "DD_IAST_TAINT_TRACKING_ENABLED"
	EnvVarMemoryLimit     = "DD_IAST_TAINT_MEMORY_LIMIT"

	envVarIASTEnabled  = "DD_IAST_ENABLED"
	minMemoryLimit     = uint64(1 << 20)
	maxMemoryLimit     = uint64(1 << 30)
	defaultMemoryLimit = uint64(64 << 20)
)

type configValue struct {
	name   string
	value  any
	origin parser.Origin
}

type environment struct {
	iastEnabled     bool
	trackingEnabled bool
	memoryLimit     uint64
	warnings        [8]string
	warningCount    int
	values          [8]configValue
	valueCount      int
}

func (e *environment) warn(format string, args ...any) {
	if e.warningCount < len(e.warnings) {
		e.warnings[e.warningCount] = fmt.Sprintf(format, args...)
		e.warningCount++
	}
}

func (e *environment) register(name string, value any, origin parser.Origin) {
	if e.valueCount < len(e.values) {
		e.values[e.valueCount] = configValue{name, value, origin}
		e.valueCount++
	}
}

func readEnvironment() environment {
	var e environment
	observer := loader.Observer{
		Warn: e.warn,
		RegisterDefault: func(name string, value any) {
			e.register(name, value, parser.OriginDefault)
		},
		RegisterEnvironment: func(name string, value any) {
			e.register(name, value, parser.OriginEnvVar)
		},
	}
	e.iastEnabled = loader.BoolFromEnv(observer, envVarIASTEnabled, true)
	e.trackingEnabled = loader.BoolFromEnv(observer, EnvVarTrackingEnabled, false)
	value, origin, raw, err := parser.UintFromEnv(EnvVarMemoryLimit, defaultMemoryLimit)
	if err != nil {
		e.warn("invalid value for %s (expected integer): %s", EnvVarMemoryLimit, raw)
	}
	if value != 0 {
		bounded, bound := parser.ClampUnsigned(value, minMemoryLimit, maxMemoryLimit)
		if bound != parser.WithinBounds {
			e.warn("invalid value for %s (expected 0 or integer between %d and %d): %d", EnvVarMemoryLimit, minMemoryLimit, maxMemoryLimit, value)
		}
		value = bounded
	}
	e.memoryLimit = value
	e.register(EnvVarMemoryLimit, value, origin)
	return e
}
