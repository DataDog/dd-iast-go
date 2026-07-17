// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hash

import (
	"context"
	"crypto"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
)

// ReportWeakHash reports use of a cryptographically weak hash algorithm.
func ReportWeakHash(ctx context.Context, hash crypto.Hash) {
	vulnerability.Report(
		ctx,
		constants.VulnerabilityTypeWeakHash,
		hash.String(),
		&telemetry.ExecutedSink.WeakHash,
		"",
	)
}
