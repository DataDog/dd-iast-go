// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2 && !go1.27

package jsonv2_test

// Go 1.26 with GOEXPERIMENT=jsonv2 is not supported: the AppendUnquote hook
// does not apply (Go 1.26 has a generic AppendUnquote), thus the strings with
// escapes have no bits. The build compiles (TestVariantBuilds).
const coarseUnquote = false
