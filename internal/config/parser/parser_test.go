// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package parser_test

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stringPointer(value string) *string { return &value }

func setOrUnsetEnv(t *testing.T, envVar string, value *string) {
	t.Helper()
	if value != nil {
		t.Setenv(envVar, *value)
		return
	}

	previous, wasSet := os.LookupEnv(envVar)
	require.NoError(t, os.Unsetenv(envVar))
	t.Cleanup(func() {
		if wasSet {
			assert.NoError(t, os.Setenv(envVar, previous))
		} else {
			assert.NoError(t, os.Unsetenv(envVar))
		}
	})
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    parser.LogLevel
		wantErr bool
	}{
		{name: "off", input: "OFF", want: parser.LogLevelOff},
		{name: "mandatory", input: "MANDATORY", want: parser.LogLevelMandatory},
		{name: "information", input: "INFORMATION", want: parser.LogLevelInformation},
		{name: "debug", input: "DEBUG", want: parser.LogLevelDebug},
		{name: "lowercase rejected", input: "off", wantErr: true},
		{name: "mixed case rejected", input: "Debug", wantErr: true},
		{name: "unknown value rejected", input: "VERBOSE", wantErr: true},
		{name: "empty value rejected", input: "", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parser.ParseLogLevel(test.input)
			if test.wantErr {
				require.Error(t, err)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestParseRegexp(t *testing.T) {
	t.Run("valid pattern", func(t *testing.T) {
		parsed, err := parser.ParseRegexp(`^abc\d+$`)
		require.NoError(t, err)
		assert.True(t, parsed.MatchString("abc123"))
		assert.False(t, parsed.MatchString("xyz123"))
	})

	t.Run("invalid pattern", func(t *testing.T) {
		parsed, err := parser.ParseRegexp(`(unterminated`)
		require.Error(t, err)
		assert.Nil(t, parsed)
	})

	t.Run("empty pattern", func(t *testing.T) {
		parsed, err := parser.ParseRegexp("")
		require.NoError(t, err)
		assert.True(t, parsed.MatchString(""))
		assert.True(t, parsed.MatchString("any string"))
	})
}

func TestBoolFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_BOOL"
	tests := []struct {
		name         string
		value        *string
		defaultValue bool
		want         bool
		wantOrigin   parser.Origin
		wantErr      bool
	}{
		{name: "unset uses true default", defaultValue: true, want: true, wantOrigin: parser.OriginDefault},
		{name: "unset uses false default", defaultValue: false, want: false, wantOrigin: parser.OriginDefault},
		{name: "true accepted", value: stringPointer("true"), want: true, wantOrigin: parser.OriginEnvVar},
		{name: "false accepted", value: stringPointer("false"), defaultValue: true, want: false, wantOrigin: parser.OriginEnvVar},
		{name: "numeric one accepted", value: stringPointer("1"), want: true, wantOrigin: parser.OriginEnvVar},
		{name: "numeric zero accepted", value: stringPointer("0"), defaultValue: true, want: false, wantOrigin: parser.OriginEnvVar},
		{name: "empty falls back", value: stringPointer(""), defaultValue: true, want: true, wantOrigin: parser.OriginDefault, wantErr: true},
		{name: "malformed falls back", value: stringPointer("yes"), defaultValue: true, want: true, wantOrigin: parser.OriginDefault, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, test.value)
			got, origin, raw, err := parser.BoolFromEnv(envVar, test.defaultValue)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantOrigin, origin)
			if test.value != nil {
				assert.Equal(t, *test.value, raw)
			}
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
		wantOrigin   parser.Origin
		wantErr      bool
	}{
		{name: "unset uses default", defaultValue: 7, want: 7, wantOrigin: parser.OriginDefault},
		{name: "valid value", value: stringPointer("42"), defaultValue: 7, want: 42, wantOrigin: parser.OriginEnvVar},
		{name: "zero", value: stringPointer("0"), defaultValue: 7, want: 0, wantOrigin: parser.OriginEnvVar},
		{name: "empty falls back", value: stringPointer(""), defaultValue: 7, want: 7, wantOrigin: parser.OriginDefault, wantErr: true},
		{name: "malformed falls back", value: stringPointer("nope"), defaultValue: 7, want: 7, wantOrigin: parser.OriginDefault, wantErr: true},
		{name: "negative falls back", value: stringPointer("-1"), defaultValue: 7, want: 7, wantOrigin: parser.OriginDefault, wantErr: true},
		{name: "overflow falls back", value: stringPointer("99999999999999999999999999"), defaultValue: 7, want: 7, wantOrigin: parser.OriginDefault, wantErr: true},
		{name: "max uint64", value: stringPointer(strconv.FormatUint(math.MaxUint64, 10)), defaultValue: 7, want: math.MaxUint64, wantOrigin: parser.OriginEnvVar},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, test.value)
			got, origin, raw, err := parser.UintFromEnv(envVar, test.defaultValue)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantOrigin, origin)
			if test.value != nil {
				assert.Equal(t, *test.value, raw)
			}
		})
	}
}

func TestClampUnsigned(t *testing.T) {
	tests := []struct {
		name      string
		value     uint64
		min, max  uint8
		want      uint8
		wantBound parser.Bound
	}{
		{name: "within bounds", value: 42, min: 0, max: 100, want: 42, wantBound: parser.WithinBounds},
		{name: "at lower bound", value: 10, min: 10, max: 100, want: 10, wantBound: parser.WithinBounds},
		{name: "at upper bound", value: 100, min: 0, max: 100, want: 100, wantBound: parser.WithinBounds},
		{name: "below minimum", value: 2, min: 10, max: 100, want: 10, wantBound: parser.BelowMinimum},
		{name: "above maximum", value: 500, min: 0, max: 100, want: 100, wantBound: parser.AboveMaximum},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, bound := parser.ClampUnsigned(test.value, test.min, test.max)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantBound, bound)
		})
	}
}

func TestFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_PARSE"
	tests := []struct {
		name         string
		value        *string
		defaultValue int
		want         int
		wantOrigin   parser.Origin
		wantErr      bool
	}{
		{name: "unset uses default", defaultValue: 9, want: 9, wantOrigin: parser.OriginDefault},
		{name: "valid value", value: stringPointer("42"), defaultValue: 9, want: 42, wantOrigin: parser.OriginEnvVar},
		{name: "parse failure", value: stringPointer("not-an-int"), defaultValue: 9, want: 9, wantOrigin: parser.OriginDefault, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setOrUnsetEnv(t, envVar, test.value)
			got, origin, raw, err := parser.FromEnv(envVar, test.defaultValue, strconv.Atoi)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantOrigin, origin)
			if test.value != nil {
				assert.Equal(t, *test.value, raw)
			}
		})
	}
}

func TestFromEnvEmptyRegexpMatchesEverything(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_REGEXP"
	setOrUnsetEnv(t, envVar, stringPointer(""))

	got, origin, _, err := parser.FromEnv(envVar, regexp.MustCompile("default-only-pattern"), parser.ParseRegexp)
	require.NoError(t, err)
	assert.Equal(t, parser.OriginEnvVar, origin)
	assert.True(t, got.MatchString(""))
	assert.True(t, got.MatchString("any string"))
}
