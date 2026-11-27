// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package saturation holds the test of the annotation store when more finished
// roots are reachable than it can remember. It is a package of its own because
// the test leaves the store full: no other test can run in the same process.
package saturation
