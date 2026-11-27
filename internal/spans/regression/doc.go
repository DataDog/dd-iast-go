// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package regression holds the tests of the annotation lifecycle that must run
// with the compile-time instrumentation of both tools. They are not in the
// package spans: otelc adds imports to the package under test, which would make
// an import cycle with the packages that import spans.
package regression
