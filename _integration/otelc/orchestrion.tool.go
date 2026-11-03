// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

package otelc

// This is the tool file of the same application when it is built with
// Orchestrion, so that both tools run the same tests on the same code.

import (
	_ "github.com/DataDog/orchestrion" // Orchestrion itself

	_ "github.com/DataDog/dd-iast-go" // IAST aspects
)
