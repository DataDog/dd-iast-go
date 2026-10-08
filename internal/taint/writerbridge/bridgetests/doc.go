// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package bridgetests has the tests of the writerbridge package. They are not in
// the writerbridge directory: in a woven test build of writerbridge, Orchestrion v1.13.1
// cannot link the test binary. The standard library packages that the
// aspects weave have a synthetic dependency on writerbridge, and Orchestrion then
// requires a test variant of those packages ("requires a test variant ...
// cannot safely use the variant"). The test binary of this package does not
// test writerbridge itself, so it does not need a test variant.
package bridgetests
