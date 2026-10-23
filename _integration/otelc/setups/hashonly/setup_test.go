// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package setup_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/_integration/otelc/internal/suite"
)

func TestSuite(t *testing.T) {
	suite.Run(t, suite.Config{Cipher: false})
}
