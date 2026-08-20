// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package loader applies IAST configuration parsing, bounds, and reporting.
package loader

import "github.com/DataDog/dd-iast-go/internal/config/parser"

// Observer receives warnings and resolved configuration values.
type Observer struct {
	Warn                func(format string, args ...any)
	RegisterDefault     func(name string, value any)
	RegisterEnvironment func(name string, value any)
}

func (o Observer) warn(format string, args ...any) {
	if o.Warn != nil {
		o.Warn(format, args...)
	}
}

func (o Observer) register(name string, value any, origin parser.Origin) {
	if origin == parser.OriginEnvVar {
		if o.RegisterEnvironment != nil {
			o.RegisterEnvironment(name, value)
		}
		return
	}
	if o.RegisterDefault != nil {
		o.RegisterDefault(name, value)
	}
}

// BoolFromEnv returns a boolean environment value or its default and reports
// the resolved value through observer.
func BoolFromEnv(observer Observer, envVar string, defaultValue bool) bool {
	value, origin, raw, err := parser.BoolFromEnv(envVar, defaultValue)
	if err != nil {
		observer.warn("invalid value for %s (expected boolean): %s", envVar, raw)
	}
	observer.register(envVar, value, origin)
	return value
}

// UintFromEnv returns an unsigned environment value or its default and reports
// the resolved value through observer.
func UintFromEnv(observer Observer, envVar string, defaultValue uint64) uint64 {
	value, origin, raw, err := parser.UintFromEnv(envVar, defaultValue)
	if err != nil {
		observer.warn("invalid value for %s (expected integer): %s", envVar, raw)
	}
	observer.register(envVar, value, origin)
	return value
}

// UintFromEnvBounded returns an unsigned environment value clamped to the
// supplied bounds and reports the resolved value through observer.
func UintFromEnvBounded[T parser.Unsigned](observer Observer, envVar string, defaultValue uint64, minValue, maxValue T) T {
	value, origin, raw, err := parser.UintFromEnv(envVar, defaultValue)
	if err != nil {
		observer.warn("invalid value for %s (expected integer): %s", envVar, raw)
	}
	bounded, bound := parser.ClampUnsigned(value, minValue, maxValue)
	if bound != parser.WithinBounds {
		observer.warn("invalid value for %s (expected integer between %d and %d): %d", envVar, minValue, maxValue, value)
	}
	observer.register(envVar, bounded, origin)
	return bounded
}

// FromEnv parses an environment value with parse, falls back to defaultValue
// on error, and reports the resolved value through observer.
func FromEnv[T any](observer Observer, envVar string, defaultValue T, parse func(string) (T, error)) T {
	value, origin, raw, err := parser.FromEnv(envVar, defaultValue, parse)
	if err != nil {
		observer.warn("invalid value for %s: %s", envVar, raw)
	}
	observer.register(envVar, value, origin)
	return value
}
