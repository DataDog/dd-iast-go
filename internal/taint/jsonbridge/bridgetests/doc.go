// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package bridgetests has the tests of the jsonbridge package. They are not in
// the jsonbridge directory: in a woven test build of jsonbridge, Orchestrion v1.13.1
// cannot link the test binary. The standard library packages that the
// aspects weave have a synthetic dependency on jsonbridge, and Orchestrion then
// requires a test variant of those packages ("requires a test variant ...
// cannot safely use the variant"). The test binary of this package does not
// test jsonbridge itself, so it does not need a test variant.
package bridgetests
