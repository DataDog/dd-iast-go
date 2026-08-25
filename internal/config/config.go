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
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
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

var (
	// Enabled determines whether IAST is enabled or not.
	Enabled bool
	// RequestSamplingPct is the percentage of requests that will be sampled for IAST.
	RequestSamplingPct int
	// MaxConcurrentRequests is the maximum number of concurrent requests that will be processed concurrently by IAST.
	MaxConcurrentRequests int
	// VulnerabilitiesPerRequest determines the maximum number of vulnerabilities that will be reported per request.
	VulnerabilitiesPerRequest int
	// DeduplicationEnabled determines whether vulnerability deduplication is enabled or not.
	DeduplicationEnabled bool
	// RedactionEnabled determines whether sensitive data redaction is enabled or not.
	RedactionEnabled bool
	// RedactionNamePattern is the pattern to use for determining which source names should be redacted.
	RedactionNamePattern *regexp.Regexp
	// RedactionValuePattern is the pattern to use for determining which source values should be redacted.
	RedactionValuePattern *regexp.Regexp
	// TruncationMaxValue is the maximum number of Unicode characters retained in report values before truncation.
	TruncationMaxValue uint64
	// MaxRangeCount is the maximum number of ranges a tainted object can hold.
	MaxRangeCount uint64
	// TelemetryVerbosity determines the verbosity of the telemetry.
	TelemetryVerbosity LogLevel
	// DbRowsToTaint determines the number of database rows that will be tainted for each request.
	DbRowsToTaint uint64
	// StackTraceEnabled determines whether stack traces will be included in vulnerability reports.
	StackTraceEnabled bool
)

func load(observer loader.Observer) {
	Enabled = loader.BoolFromEnv(observer, EnvVarEnabled, true)
	RequestSamplingPct = int(loader.UintFromEnvBounded(observer, EnvVarRequestSampling, 30, uint8(0), uint8(100)))
	MaxConcurrentRequests = int(loader.UintFromEnvBounded(observer, EnvVarMaxConcurrentRequests, uint64(2), uint8(0), uint8(64)))
	VulnerabilitiesPerRequest = int(loader.UintFromEnvBounded(observer, EnvVarVulnerabilitiesPerRequest, 2, uint64(1), uint64(math.MaxInt)))
	DeduplicationEnabled = loader.BoolFromEnv(observer, EnvVarDeduplicationEnabled, true)
	RedactionEnabled = loader.BoolFromEnv(observer, EnvVarRedactionEnabled, true)
	RedactionNamePattern = loader.FromEnv(observer, EnvVarRedactionNamePattern, defaultRedactionNamePattern, parser.ParseRegexp)
	RedactionValuePattern = loader.FromEnv(observer, EnvVarRedactionValuePattern, defaultRedactionValuePattern, parser.ParseRegexp)
	TruncationMaxValue = loader.UintFromEnv(observer, EnvVarTruncationMaxValue, 250)
	MaxRangeCount = loader.UintFromEnvBounded(observer, EnvVarMaxRangeCount, uint64(ranges.DefaultLimit), uint64(1), uint64(ranges.HardLimit))
	TelemetryVerbosity = loader.FromEnv(observer, EnvVarTelemetryVerbosity, LogLevelInformation, parser.ParseLogLevel)
	DbRowsToTaint = loader.UintFromEnv(observer, EnvVarDbRowsToTaint, 1)
	StackTraceEnabled = loader.BoolFromEnv(observer, EnvVarStackTraceEnabled, true)
}

type LogLevel = parser.LogLevel

const (
	LogLevelOff         = parser.LogLevelOff
	LogLevelMandatory   = parser.LogLevelMandatory
	LogLevelInformation = parser.LogLevelInformation
	LogLevelDebug       = parser.LogLevelDebug
)
