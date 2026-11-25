// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

var (
	settings       environment
	offReason      string
	runtimeEnabled func() bool
)

// Enabled reports whether heap taint tracking is active.
func Enabled() bool {
	return settings.iastEnabled && settings.trackingEnabled && settings.memoryLimit != 0 && runtimeEnabled != nil && runtimeEnabled()
}

func init() {
	settings = readEnvironment()
	offReason = "not woven"
	if runtimeEnabled != nil {
		offReason = "not initialized"
	}
	switch {
	case !settings.iastEnabled:
		offReason = "IAST disabled"
	case !settings.trackingEnabled:
		offReason = "taint tracking disabled"
	case settings.memoryLimit == 0:
		offReason = "memory limit is zero"
	}
	reportEnvironment(settings, false, offReason)
}
