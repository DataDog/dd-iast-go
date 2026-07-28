// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package config

import (
	"fmt"
	"math"
	"os"
	"strconv"

	"github.com/DataDog/dd-iast-go/internal/instrumentation"
)

const (
	EnvVarEnabled                   = "DD_IAST_ENABLED"
	EnvVarRequestSampling           = "DD_IAST_REQUEST_SAMPLING"
	EnvVarMaxConcurrentRequests     = "DD_IAST_MAX_CONCURRENT_REQUESTS"
	EnvVarVulnerabilitiesPerRequest = "DD_IAST_VULNERABILITIES_PER_REQUEST"
	EnvVarDeduplicationEnabled      = "DD_IAST_DEDUPLICATION_ENABLED"
	EnvVarRedactionEnabled          = "DD_IAST_REDACTION_ENABLED"
	EnvVarRedactionNamePattern      = "DD_IAST_REDACTION_NAME_PATTERN"
	EnvVarRedactionValuePattern     = "DD_IAST_REDACTION_VALUE_PATTERN"
	EnvVarTruncationMaxValue        = "DD_IAST_TRUNCATION_MAX_VALUE"
	EnvVarMaxRangeCount             = "DD_IAST_MAX_RANGE_COUNT"
	EnvVarTelemetryVerbosity        = "DD_IAST_TELEMETRY_VERBOSITY"
	EnvVarDbRowsToTaint             = "DD_IAST_DB_ROWS_TO_TAIN"
	EnvVarStackTraceEnabled         = "DD_IAST_STACK_TRACE_ENABLED"
)

var (
	// Enabled determines whether IAST is enabled or not.
	Enabled bool = boolFromEnv(EnvVarEnabled, false)
	// RequestSamplingPct is the percentage of requests that will be sampled for IAST.
	RequestSamplingPct int = int(uintFromEnvBounded[uint8](EnvVarRequestSampling, 30, 0, 100))
	// MaxConcurrentRequests is the maximum number of concurrent requests that will be processed concurrently by IAST.
	MaxConcurrentRequests int = int(uintFromEnvBounded[uint64](EnvVarMaxConcurrentRequests, 2, 0, math.MaxInt))
	// VulnerabilitiesPerRequest determines the maximum number of vulnerabilities that will be reported per request.
	VulnerabilitiesPerRequest int = int(uintFromEnvBounded[uint64](EnvVarVulnerabilitiesPerRequest, 2, 1, math.MaxInt))
	// DeduplicationEnabled determines whether vulnerability deduplication is enabled or not.
	DeduplicationEnabled bool = boolFromEnv(EnvVarDeduplicationEnabled, true)
	// RedactionEnabled determines whether sensitive data redaction is enabled or not.
	RedactionEnabled bool = boolFromEnv(EnvVarRedactionEnabled, true)
	// RedactionNamePattern is the pattern to use for determining which source names should be redacted.
	RedactionNamePattern string = stringFromEnv(EnvVarRedactionNamePattern, "") //TODO: default value
	// RedactionValuePattern is the pattern to use for determining which source values should be redacted.
	RedactionValuePattern string = stringFromEnv(EnvVarRedactionValuePattern, "") //TODO: default value
	// TruncationMaxValue is the maximum number of characters that will allowed for a source value before it is truncated.
	TruncationMaxValue uint64 = uintFromEnv(EnvVarTruncationMaxValue, 250)
	// MaxRangeCount is the maximum number of ranges a tainted object can hold.
	MaxRangeCount uint64 = uintFromEnv(EnvVarMaxRangeCount, 10)
	// TelemetryVerbosity determines the verbosity of the telemetry.
	TelemetryVerbosity LogLevel = parseFromEnv(EnvVarTelemetryVerbosity, LogLevelInformation, parseLogLevel)
	// DbRowsToTaint determines the number of database rows that will be tainted for each request.
	DbRowsToTaint uint64 = uintFromEnv(EnvVarDbRowsToTaint, 1)
	// StackTraceEnabled determines whether stack traces will be included in vulnerability reports.
	StackTraceEnabled bool = boolFromEnv(EnvVarStackTraceEnabled, true)
)

type LogLevel uint8

const (
	_ LogLevel = iota
	LogLevelOff
	LogLevelMandatory
	LogLevelInformation
	LogLevelDebug
)

func parseLogLevel(val string) (LogLevel, error) {
	switch val {
	case "OFF":
		return LogLevelOff, nil
	case "MANDATORY":
		return LogLevelMandatory, nil
	case "INFORMATION":
		return LogLevelInformation, nil
	case "DEBUG":
		return LogLevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level (expected one of OFF, MANDATORY, INFORMATION, or DEBUG): %s", val)
	}
}

func boolFromEnv(envVar string, defaultValue bool) bool {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		instrumentation.Instance.TelemetryRegisterAppConfig(envVar, defaultValue, instrumentation.OriginDefault)
		return defaultValue
	}
	res, err := strconv.ParseBool(val)
	if err != nil {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected boolean): %s", envVar, val)
		instrumentation.Instance.TelemetryRegisterAppConfig(envVar, defaultValue, instrumentation.OriginDefault)
		return defaultValue
	}
	instrumentation.Instance.TelemetryRegisterAppConfig(envVar, res, instrumentation.OriginEnvVar)
	return res
}

type unsigned interface {
	uint | uint8 | uint16 | uint32 | uint64
}

func uintFromEnvBounded[T unsigned](envVar string, defaultValue uint64, min T, max T) T {
	val, origin := uintFromEnvNoTelemetry(envVar, defaultValue)
	if val < uint64(min) {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected integer between %d and %d): %d", envVar, min, max, val)
		instrumentation.Instance.TelemetryRegisterAppConfig(envVar, min, origin)
		return min
	}
	if val > uint64(max) {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected integer between %d and %d): %d", envVar, min, max, val)
		instrumentation.Instance.TelemetryRegisterAppConfig(envVar, max, origin)
		return max
	}
	instrumentation.Instance.TelemetryRegisterAppConfig(envVar, T(val), origin)
	return T(val)
}

func uintFromEnv(envVar string, defaultValue uint64) uint64 {
	val, origin := uintFromEnvNoTelemetry(envVar, defaultValue)
	instrumentation.Instance.TelemetryRegisterAppConfig(envVar, val, origin)
	return val
}

func uintFromEnvNoTelemetry(envVar string, defaultValue uint64) (uint64, instrumentation.TelemetryOrigin) {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return defaultValue, instrumentation.OriginDefault
	}
	res, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected integer): %s", envVar, val)
		return defaultValue, instrumentation.OriginDefault
	}
	return res, instrumentation.OriginEnvVar
}

func stringFromEnv(envVar string, defaultValue string) string {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		instrumentation.Instance.TelemetryRegisterAppConfig(envVar, defaultValue, instrumentation.OriginDefault)
		return defaultValue
	}
	instrumentation.Instance.TelemetryRegisterAppConfig(envVar, val, instrumentation.OriginEnvVar)
	return val
}

func parseFromEnv[T any](envVar string, defaultValue T, parse func(string) (T, error)) T {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		instrumentation.Instance.TelemetryRegisterAppConfig(envVar, defaultValue, instrumentation.OriginDefault)
		return defaultValue
	}
	res, err := parse(val)
	if err != nil {
		instrumentation.Instance.Logger().Warn("invalid value for %s: %s", envVar, val)
		instrumentation.Instance.TelemetryRegisterAppConfig(envVar, defaultValue, instrumentation.OriginDefault)
		return defaultValue
	}
	instrumentation.Instance.TelemetryRegisterAppConfig(envVar, res, instrumentation.OriginEnvVar)
	return res
}
