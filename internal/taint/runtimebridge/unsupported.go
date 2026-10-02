// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build go1.28

package runtimebridge

// supported is false for Go releases after go1.27 (plan section 3.10). Then
// Bind refuses every binding, the gates stay zero, and each runtime hook costs
// one atomic load. The unsupportedGo counter records the refusal.
const supported = false
