// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package bench holds the benchmarks of the runtime hooks of iast/runtime
// (gate group G-B of plan heapbits-sqli-cmdi, section 10). See bench_test.go.
//
// The benchmarks are in a separate package because the tests of iast/runtime
// link package heapbits/heapbitstest. That package turns on the test knobs of
// the woven runtime, and the bit checks then do more work than in a
// production program.
package bench
