// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package otelc_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/_integration/otelc/internal/suite"
)

// TestLateReportAfterRootFinish checks the reports that come after the root
// span finished (see [suite.CheckLateReportAfterRootFinish]).
func TestLateReportAfterRootFinish(t *testing.T) {
	suite.CheckLateReportAfterRootFinish(t)
}
