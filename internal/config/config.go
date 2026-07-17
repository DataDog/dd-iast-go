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
	envVarIastEnabled                   = "DD_IAST_ENABLED"
	envVarIastRequestSampling           = "DD_IAST_REQUEST_SAMPLING"
	envVarIastMaxConcurrentRequests     = "DD_IAST_MAX_CONCURRENT_REQUESTS"
	envVarIastVulnerabilitiesPerRequest = "DD_IAST_VULNERABILITIES_PER_REQUEST"
	envVarIastDeduplicationEnabled      = "DD_IAST_DEDUPLICATION_ENABLED"
	envVarIastRedactionEnabled          = "DD_IAST_REDACTION_ENABLED"
	envVarIastRedactionNamePattern      = "DD_IAST_REDACTION_NAME_PATTERN"
	envVarIastRedactionValuePattern     = "DD_IAST_REDACTION_VALUE_PATTERN"
	envVarIastTruncationMaxValue        = "DD_IAST_TRUNCATION_MAX_VALUE"
	envVarIastMaxRangeCount             = "DD_IAST_MAX_RANGE_COUNT"
	envVarIastTelemetryVerbosity        = "DD_IAST_TELEMETRY_VERBOSITY"
	envVarIastDbRowsToTaint             = "DD_IAST_DB_ROWS_TO_TAIN"
	envVarIastStackTraceEnabled         = "DD_IAST_STACK_TRACE_ENABLED"
)

var (
	// Enabled determines whether IAST is enabled or not.
	Enabled bool = boolFromEnv(envVarIastEnabled, false)
	// RequestSamplingPct is the percentage of requests that will be sampled for IAST.
	RequestSamplingPct int = int(uintFromEnvBounded[uint8](envVarIastRequestSampling, 30, 0, 100))
	// MaxConcurrentRequests is the maximum number of concurrent requests that will be processed concurrently by IAST.
	MaxConcurrentRequests int = int(uintFromEnvBounded[uint64](envVarIastMaxConcurrentRequests, 2, 0, math.MaxInt))
	// VulnerabilitiesPerRequest determines the maximum number of vulnerabilities that will be reported per request.
	VulnerabilitiesPerRequest int = int(uintFromEnv(envVarIastVulnerabilitiesPerRequest, 2))
	// DeduplicationEnabled determines whether vulnerability deduplication is enabled or not.
	DeduplicationEnabled bool = boolFromEnv(envVarIastDeduplicationEnabled, true)
	// RedactionEnabled determines whether sensitive data redaction is enabled or not.
	RedactionEnabled bool = boolFromEnv(envVarIastRedactionEnabled, true)
	// RedactionNamePattern is the pattern to use for determining which source names should be redacted.
	RedactionNamePattern string = stringFromEnv(envVarIastRedactionNamePattern, "") //TODO: default value
	// RedactionValuePattern is the pattern to use for determining which source values should be redacted.
	RedactionValuePattern string = stringFromEnv(envVarIastRedactionValuePattern, "") //TODO: default value
	// TruncationMaxValue is the maximum number of characters that will allowed for a source value before it is truncated.
	TruncationMaxValue uint64 = uintFromEnv(envVarIastTruncationMaxValue, 250)
	// MaxRangeCount is the maximum number of ranges a tainted object can hold.
	MaxRangeCount uint64 = uintFromEnv(envVarIastMaxRangeCount, 10)
	// TelemetryVerbosity determines the verbosity of the telemetry.
	TelemetryVerbosity LogLevel = parseFromEnv(envVarIastTelemetryVerbosity, LogLevelInformation, parseLogLevel)
	// DbRowsToTaint determines the number of database rows that will be tainted for each request.
	DbRowsToTaint uint64 = uintFromEnv(envVarIastDbRowsToTaint, 1)
	// StackTraceEnabled determines whether stack traces will be included in vulnerability reports.
	StackTraceEnabled bool = boolFromEnv(envVarIastStackTraceEnabled, true)
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
		return defaultValue
	}
	res, err := strconv.ParseBool(val)
	if err != nil {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected boolean): %s", envVar, val)
		return defaultValue
	}
	return res
}

type unsigned interface {
	uint | uint8 | uint16 | uint32 | uint64
}

func uintFromEnvBounded[T unsigned](envVar string, defaultValue uint64, min T, max T) T {
	val := uintFromEnv(envVar, defaultValue)
	if val < uint64(min) {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected integer between %d and %d): %d", envVar, min, max, val)
		return min
	}
	if val > uint64(max) {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected integer between %d and %d): %d", envVar, min, max, val)
		return max
	}
	return T(val)
}

func uintFromEnv(envVar string, defaultValue uint64) uint64 {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return defaultValue
	}
	res, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		instrumentation.Instance.Logger().Warn("invalid value for %s (expected integer): %s", envVar, val)
		return defaultValue
	}
	return res
}

func stringFromEnv(envVar string, defaultValue string) string {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return defaultValue
	}
	return val
}

func parseFromEnv[T any](envVar string, defaultValue T, parse func(string) (T, error)) T {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return defaultValue
	}
	res, err := parse(val)
	if err != nil {
		instrumentation.Instance.Logger().Warn("invalid value for %s: %s", envVar, val)
	}
	return res
}
