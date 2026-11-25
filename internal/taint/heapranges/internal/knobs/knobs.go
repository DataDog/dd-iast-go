// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package knobs provides test-only access to the woven runtime.
package knobs

var (
	Gate      func() uint32
	OffReason func() string
	MapSlab   func() (bool, uint64)
)
