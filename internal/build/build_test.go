// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package build_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/stretchr/testify/assert"
)

func TestToolMatchesInstrumented(t *testing.T) {
	t.Logf("built with: %q", build.Tool())
	assert.Equal(t, build.Tool() != build.ToolNone, build.Instrumented())
	assert.Contains(t, []string{build.ToolNone, build.ToolOrchestrion, build.ToolOtelc}, build.Tool())
}
