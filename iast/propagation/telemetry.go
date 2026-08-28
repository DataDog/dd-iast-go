// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import "github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"

// instrumentedPropagationPoints is the number of named call-site and
// standard-library invalidation point shapes registered by orchestrion.yml.
const instrumentedPropagationPoints = 123

func init() {
	telemetry.InstrumentedPropagation += instrumentedPropagationPoints
}
