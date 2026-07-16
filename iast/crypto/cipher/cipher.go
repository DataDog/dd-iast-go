// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package cipher detects cryptographically weak cipher algorithms.
package cipher

import (
	"context"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
)

// ReportWeakCipher reports use of a cryptographically weak cipher algorithm.
// If skipCallerFunction identifies the first candidate location frame, that
// frame is skipped in favor of its caller.
func ReportWeakCipher(ctx context.Context, name, skipCallerFunction string) {
	vulnerability.Report(
		ctx,
		constants.VulnerabilityTypeWeakCipher,
		name,
		&telemetry.ExecutedSink.WeakCipher,
		skipCallerFunction,
	)
}
