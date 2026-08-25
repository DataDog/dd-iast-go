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
