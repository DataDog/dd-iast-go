// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package parser provides environment value parsing for IAST configuration.
package parser

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
)

// Origin identifies where a resolved configuration value came from.
type Origin uint8

const (
	OriginDefault Origin = iota
	OriginEnvVar
)

// LogLevel is an IAST telemetry verbosity value parsed from the environment.
type LogLevel uint8

const (
	_ LogLevel = iota
	LogLevelOff
	LogLevelMandatory
	LogLevelInformation
	LogLevelDebug
)

// ParseLogLevel parses an exact, case-sensitive telemetry verbosity value.
func ParseLogLevel(value string) (LogLevel, error) {
	switch value {
	case "OFF":
		return LogLevelOff, nil
	case "MANDATORY":
		return LogLevelMandatory, nil
	case "INFORMATION":
		return LogLevelInformation, nil
	case "DEBUG":
		return LogLevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level (expected one of OFF, MANDATORY, INFORMATION, or DEBUG): %s", value)
	}
}

// ParseRegexp compiles value as a regular expression.
func ParseRegexp(value string) (*regexp.Regexp, error) {
	return regexp.Compile(value)
}

// BoolFromEnv resolves a boolean environment variable. An unset or invalid
// value returns defaultValue with OriginDefault. raw is empty when envVar is
// unset and contains the rejected input on a parse error.
func BoolFromEnv(envVar string, defaultValue bool) (value bool, origin Origin, raw string, err error) {
	raw, ok := os.LookupEnv(envVar)
	if !ok {
		return defaultValue, OriginDefault, "", nil
	}
	value, err = strconv.ParseBool(raw)
	if err != nil {
		return defaultValue, OriginDefault, raw, err
	}
	return value, OriginEnvVar, raw, nil
}

// UintFromEnv resolves an unsigned environment variable. An unset or invalid
// value returns defaultValue with OriginDefault. raw is empty when envVar is
// unset and contains the rejected input on a parse error.
func UintFromEnv(envVar string, defaultValue uint64) (value uint64, origin Origin, raw string, err error) {
	raw, ok := os.LookupEnv(envVar)
	if !ok {
		return defaultValue, OriginDefault, "", nil
	}
	value, err = strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return defaultValue, OriginDefault, raw, err
	}
	return value, OriginEnvVar, raw, nil
}

// FromEnv resolves an environment variable with parse. An unset or invalid
// value returns defaultValue with OriginDefault. raw is empty when envVar is
// unset and contains the rejected input on a parse error.
func FromEnv[T any](envVar string, defaultValue T, parse func(string) (T, error)) (value T, origin Origin, raw string, err error) {
	raw, ok := os.LookupEnv(envVar)
	if !ok {
		return defaultValue, OriginDefault, "", nil
	}
	value, err = parse(raw)
	if err != nil {
		return defaultValue, OriginDefault, raw, err
	}
	return value, OriginEnvVar, raw, nil
}

// Unsigned is the set of unsigned integer types supported by ClampUnsigned.
type Unsigned interface {
	uint | uint8 | uint16 | uint32 | uint64
}

// Bound describes how ClampUnsigned classified its input.
type Bound uint8

const (
	WithinBounds Bound = iota
	BelowMinimum
	AboveMaximum
)

// ClampUnsigned converts value to T after clamping it to the supplied bounds.
func ClampUnsigned[T Unsigned](value uint64, minValue, maxValue T) (T, Bound) {
	if value < uint64(minValue) {
		return minValue, BelowMinimum
	}
	if value > uint64(maxValue) {
		return maxValue, AboveMaximum
	}
	return T(value), WithinBounds
}
