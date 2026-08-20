// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package config

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

// setOrUnsetEnv sets envVar to *value when value is non-nil, or ensures it is
// unset otherwise. Cleanup is registered so that the modification does not
// leak into other tests.
func setOrUnsetEnv(t *testing.T, envVar string, value *string) {
	t.Helper()
	if value == nil {
		// Ensure a clean slate: capture and restore any pre-existing value.
		if prev, ok := os.LookupEnv(envVar); ok {
			t.Cleanup(func() { _ = os.Setenv(envVar, prev) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(envVar) })
		}
		require.NoError(t, os.Unsetenv(envVar))
		return
	}
	t.Setenv(envVar, *value)
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    LogLevel
		wantErr bool
	}{
		{name: "off", input: "OFF", want: LogLevelOff},
		{name: "mandatory", input: "MANDATORY", want: LogLevelMandatory},
		{name: "information", input: "INFORMATION", want: LogLevelInformation},
		{name: "debug", input: "DEBUG", want: LogLevelDebug},
		{name: "lowercase rejected", input: "off", wantErr: true},
		{name: "mixed case rejected", input: "Debug", wantErr: true},
		{name: "unknown value rejected", input: "VERBOSE", wantErr: true},
		{name: "empty value rejected", input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLogLevel(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				require.Zero(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseRegexp(t *testing.T) {
	t.Run("valid pattern compiles and matches", func(t *testing.T) {
		re, err := parseRegexp(`^abc\d+$`)
		require.NoError(t, err)
		require.True(t, re.MatchString("abc123"))
		require.False(t, re.MatchString("xyz123"))
	})

	t.Run("invalid pattern is rejected", func(t *testing.T) {
		re, err := parseRegexp(`(unterminated`)
		require.Error(t, err)
		require.Nil(t, re)
	})

	t.Run("explicitly empty pattern matches every string", func(t *testing.T) {
		re, err := parseRegexp("")
		require.NoError(t, err)
		require.True(t, re.MatchString(""))
		require.True(t, re.MatchString("any string whatsoever"))
	})
}

func TestBoolFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_BOOL"

	tests := []struct {
		name         string
		value        *string
		defaultValue bool
		want         bool
	}{
		{name: "unset uses default true", value: nil, defaultValue: true, want: true},
		{name: "unset uses default false", value: nil, defaultValue: false, want: false},
		{name: "true accepted", value: strPtr("true"), defaultValue: false, want: true},
		{name: "false accepted", value: strPtr("false"), defaultValue: true, want: false},
		{name: "numeric one accepted", value: strPtr("1"), defaultValue: false, want: true},
		{name: "numeric zero accepted", value: strPtr("0"), defaultValue: true, want: false},
		{name: "empty value falls back to default", value: strPtr(""), defaultValue: true, want: true},
		{name: "malformed value falls back to default", value: strPtr("yes"), defaultValue: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, tt.value)
			got := boolFromEnv(envVar, tt.defaultValue)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestUintFromEnvNoTelemetry(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_UINT_NO_TELEMETRY"

	tests := []struct {
		name         string
		value        *string
		defaultValue uint64
		want         uint64
		wantOrigin   instrumentation.TelemetryOrigin
	}{
		{name: "unset uses default", value: nil, defaultValue: 7, want: 7, wantOrigin: instrumentation.OriginDefault},
		{name: "valid lexical form", value: strPtr("42"), defaultValue: 7, want: 42, wantOrigin: instrumentation.OriginEnvVar},
		{name: "zero is valid", value: strPtr("0"), defaultValue: 7, want: 0, wantOrigin: instrumentation.OriginEnvVar},
		{name: "explicitly empty falls back to default", value: strPtr(""), defaultValue: 7, want: 7, wantOrigin: instrumentation.OriginDefault},
		{name: "malformed lexical form falls back to default", value: strPtr("not-a-number"), defaultValue: 7, want: 7, wantOrigin: instrumentation.OriginDefault},
		{name: "negative value falls back to default", value: strPtr("-1"), defaultValue: 7, want: 7, wantOrigin: instrumentation.OriginDefault},
		{name: "overflowing value falls back to default", value: strPtr("99999999999999999999999999"), defaultValue: 7, want: 7, wantOrigin: instrumentation.OriginDefault},
		{name: "max uint64 boundary is accepted", value: strPtr(strconv.FormatUint(math.MaxUint64, 10)), defaultValue: 7, want: math.MaxUint64, wantOrigin: instrumentation.OriginEnvVar},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, tt.value)
			got, origin := uintFromEnvNoTelemetry(envVar, tt.defaultValue)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantOrigin, origin)
		})
	}
}

func TestUintFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_UINT"

	tests := []struct {
		name         string
		value        *string
		defaultValue uint64
		want         uint64
	}{
		{name: "unset uses default", value: nil, defaultValue: 10, want: 10},
		{name: "valid value used verbatim", value: strPtr("123"), defaultValue: 10, want: 123},
		{name: "malformed value falls back to default", value: strPtr("nope"), defaultValue: 10, want: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, tt.value)
			got := uintFromEnv(envVar, tt.defaultValue)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestUintFromEnvBounded(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_UINT_BOUNDED"

	tests := []struct {
		name         string
		value        *string
		defaultValue uint64
		min, max     uint8
		want         uint8
	}{
		{name: "unset default within bounds", value: nil, defaultValue: 5, min: 0, max: 100, want: 5},
		{name: "valid value within bounds", value: strPtr("42"), defaultValue: 5, min: 0, max: 100, want: 42},
		{name: "value at lower bound is kept", value: strPtr("10"), defaultValue: 5, min: 10, max: 100, want: 10},
		{name: "value at upper bound is kept", value: strPtr("100"), defaultValue: 5, min: 0, max: 100, want: 100},
		{name: "value below lower bound is clamped up", value: strPtr("2"), defaultValue: 5, min: 10, max: 100, want: 10},
		{name: "value above upper bound is clamped down", value: strPtr("500"), defaultValue: 5, min: 0, max: 100, want: 100},
		{name: "malformed value falls back to default then bounds", value: strPtr("nope"), defaultValue: 5, min: 0, max: 100, want: 5},
		{name: "default below bounds is itself clamped", value: nil, defaultValue: 5, min: 10, max: 100, want: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, tt.value)
			got := uintFromEnvBounded[uint8](envVar, tt.defaultValue, tt.min, tt.max)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_PARSE"

	tests := []struct {
		name         string
		value        *string
		defaultValue int
		want         int
	}{
		{name: "unset uses default", value: nil, defaultValue: 9, want: 9},
		{name: "valid value is parsed", value: strPtr("42"), defaultValue: 9, want: 42},
		{name: "parse failure falls back to default", value: strPtr("not-an-int"), defaultValue: 9, want: 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, tt.value)
			got := parseFromEnv(envVar, tt.defaultValue, strconv.Atoi)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseFromEnvEmptyRedactionPatternMatchesEverything(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_REDACTION_PATTERN"
	setOrUnsetEnv(t, envVar, strPtr(""))

	got := parseFromEnv(envVar, regexp.MustCompile("default-only-pattern"), parseRegexp)
	require.True(t, got.MatchString(""), "an explicitly empty redaction pattern must match the empty string")
	require.True(t, got.MatchString("any string whatsoever"), "an explicitly empty redaction pattern must match every string")
}
