// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2

package request

// jsonv2Experiment tells if the build has GOEXPERIMENT=jsonv2 (the default
// of Go 1.27).
const jsonv2Experiment = true
