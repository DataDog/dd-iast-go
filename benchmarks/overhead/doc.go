// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package overhead holds the IAST runtime overhead benchmarks. The runner in
// ./runner builds them with Orchestrion or with otelc.
//
// The benchmarks are in the test files. This file is necessary for otelc: otelc
// does not apply its rules to a package that has only test files (and files
// with the "tools" build constraint).
package overhead
