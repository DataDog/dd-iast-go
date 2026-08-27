// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package config

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config/loader"
	"github.com/stretchr/testify/require"
)

func TestDefaultRedactionPatternsMatchAcceptedSensitiveForms(t *testing.T) {
	for _, name := range []string{"password", "API_KEY", "Authorization", "consumer_secret"} {
		if !defaultRedactionNamePattern.MatchString(name) {
			t.Errorf("name pattern did not match %q", name)
		}
	}
	for _, value := range []string{"Bearer ABC.def-123", "token:abcdefghijklm", "ghp_123456789012345678901234567890123456"} {
		if !defaultRedactionValuePattern.MatchString(value) {
			t.Errorf("value pattern did not match %q", value)
		}
	}
	for _, name := range []string{"username", "limit", "plain"} {
		if defaultRedactionNamePattern.MatchString(name) {
			t.Errorf("name pattern unexpectedly matched %q", name)
		}
	}
	for _, value := range []string{"plain text", "token:short", "Bearer"} {
		if defaultRedactionValuePattern.MatchString(value) {
			t.Errorf("value pattern unexpectedly matched %q", value)
		}
	}
}

func TestObserveReplaysInitialConfiguration(t *testing.T) {
	count := 0
	observer := loader.Observer{
		Warn:                func(string, ...any) { count++ },
		RegisterDefault:     func(string, any) { count++ },
		RegisterEnvironment: func(string, any) { count++ },
	}
	require.Equal(t, Enabled, Observe(observer))
	require.NotZero(t, count)
	firstCount := count
	count = 0
	require.Equal(t, Enabled, Observe(observer))
	require.Equal(t, firstCount, count)
}
