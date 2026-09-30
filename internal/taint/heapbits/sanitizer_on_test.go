// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build asan || msan

package heapbits_test

// sanitizer is true in ASan and MSan builds, where the feature is off.
const sanitizer = true
