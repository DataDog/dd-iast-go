// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !goexperiment.jsonv2 || go1.27

package jsonv2_test

// coarseUnquote tells if the strings with escapes are coarse: with the v1
// hooks of iast/propagation/stream, and with the hooks of this package from Go
// 1.27 (see variant_go126_jsonv2_test.go).
const coarseUnquote = true
