// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package config

import (
	"math"
	"regexp"

	"github.com/DataDog/dd-iast-go/internal/config/loader"
	"github.com/DataDog/dd-iast-go/internal/config/parser"
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
	EnvVarDbRowsToTaint             = "DD_IAST_DB_ROWS_TO_TAINT"
	EnvVarStackTraceEnabled         = "DD_IAST_STACK_TRACE_ENABLED"
)

var (
	defaultRedactionNamePattern  = regexp.MustCompile(`(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|(?:api_?|private_?|public_?|access_?|secret_?)key(?:_?id)?|token|consumer_?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?)`)
	defaultRedactionValuePattern = regexp.MustCompile(`(?:bearer\s+[a-z0-9\._\-]+|glpat-[\w\-]{20}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L][\w=\-]+\.ey[I-L][\w=\-]+(?:\.[\w.+/=\-]+)?|(?:[\-]{5}BEGIN[a-z\s]+PRIVATE\sKEY[\-]{5}[^\-]+[\-]{5}END[a-z\s]+PRIVATE\sKEY[\-]{5}|ssh-rsa\s*[a-z0-9/\.+]{100,}))`)
)

var configObserver = loader.Observer{
	Warn: func(format string, args ...any) {
		instrumentation.Instance.Logger().Warn(format, args...)
	},
	RegisterDefault: func(name string, value any) {
		instrumentation.Instance.TelemetryRegisterAppConfig(name, value, instrumentation.OriginDefault)
	},
	RegisterEnvironment: func(name string, value any) {
		instrumentation.Instance.TelemetryRegisterAppConfig(name, value, instrumentation.OriginEnvVar)
	},
}

var (
	// Enabled determines whether IAST is enabled or not.
	Enabled bool = loader.BoolFromEnv(configObserver, EnvVarEnabled, true)
	// RequestSamplingPct is the percentage of requests that will be sampled for IAST.
	RequestSamplingPct int = int(loader.UintFromEnvBounded(configObserver, EnvVarRequestSampling, 30, uint8(0), uint8(100)))
	// MaxConcurrentRequests is the maximum number of concurrent requests that will be processed concurrently by IAST.
	MaxConcurrentRequests int = int(loader.UintFromEnvBounded(configObserver, EnvVarMaxConcurrentRequests, 2, uint64(0), uint64(math.MaxInt)))
	// VulnerabilitiesPerRequest determines the maximum number of vulnerabilities that will be reported per request.
	VulnerabilitiesPerRequest int = int(loader.UintFromEnvBounded(configObserver, EnvVarVulnerabilitiesPerRequest, 2, uint64(1), uint64(math.MaxInt)))
	// DeduplicationEnabled determines whether vulnerability deduplication is enabled or not.
	DeduplicationEnabled bool = loader.BoolFromEnv(configObserver, EnvVarDeduplicationEnabled, true)
	// RedactionEnabled determines whether sensitive data redaction is enabled or not.
	RedactionEnabled bool = loader.BoolFromEnv(configObserver, EnvVarRedactionEnabled, true)
	// RedactionNamePattern is the pattern to use for determining which source names should be redacted.
	RedactionNamePattern *regexp.Regexp = loader.FromEnv(configObserver, EnvVarRedactionNamePattern, defaultRedactionNamePattern, parser.ParseRegexp)
	// RedactionValuePattern is the pattern to use for determining which source values should be redacted.
	RedactionValuePattern *regexp.Regexp = loader.FromEnv(configObserver, EnvVarRedactionValuePattern, defaultRedactionValuePattern, parser.ParseRegexp)
	// TruncationMaxValue is the maximum number of Unicode characters retained in report values before truncation.
	TruncationMaxValue uint64 = loader.UintFromEnv(configObserver, EnvVarTruncationMaxValue, 250)
	// MaxRangeCount is the maximum number of ranges a tainted object can hold.
	MaxRangeCount uint64 = loader.UintFromEnv(configObserver, EnvVarMaxRangeCount, 10)
	// TelemetryVerbosity determines the verbosity of the telemetry.
	TelemetryVerbosity LogLevel = loader.FromEnv(configObserver, EnvVarTelemetryVerbosity, LogLevelInformation, parser.ParseLogLevel)
	// DbRowsToTaint determines the number of database rows that will be tainted for each request.
	DbRowsToTaint uint64 = loader.UintFromEnv(configObserver, EnvVarDbRowsToTaint, 1)
	// StackTraceEnabled determines whether stack traces will be included in vulnerability reports.
	StackTraceEnabled bool = loader.BoolFromEnv(configObserver, EnvVarStackTraceEnabled, true)
)

type LogLevel = parser.LogLevel

const (
	LogLevelOff         = parser.LogLevelOff
	LogLevelMandatory   = parser.LogLevelMandatory
	LogLevelInformation = parser.LogLevelInformation
	LogLevelDebug       = parser.LogLevelDebug
)
