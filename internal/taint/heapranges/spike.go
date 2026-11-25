// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "os"

var runtimeProbe func() uint64
var runtimeAccount func(int64)

func init() {
	if os.Getenv("DD_IAST_TAINT_TRACKING_ENABLED") == "true" && runtimeAccount != nil {
		if reserve() {
			runtimeAccount(1 << 20)
		}
	}
}

func Probe() uint64 {
	if runtimeProbe == nil {
		return 0
	}
	return runtimeProbe()
}
