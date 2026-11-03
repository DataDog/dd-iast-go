// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package otelc_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/_integration/otelc/internal/suite"
)

// TestSuite runs the checks with the tool file of this module, which imports the
// root package of dd-iast-go ("root" setup).
func TestSuite(t *testing.T) {
	suite.Run(t, suite.Config{Cipher: true})
}
