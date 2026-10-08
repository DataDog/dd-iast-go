// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !go1.28

package runtimebridge

// supported is true for the Go releases that the runtime hooks support:
// go1.26.x and go1.27.x (see "Supported releases" in the package doc).
const supported = true
