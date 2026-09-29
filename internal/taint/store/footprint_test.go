// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

// The measured sizes of the fixed store layout on 64-bit platforms (arm64 and
// amd64 have the same layout). TestStoreFootprint fails when a field change
// changes them.
const (
	expectedOwnerSize = 183_376
	expectedStoreSize = 14_040_768
)
