// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package operatorbridge provides the allocation-free operator fast gate.
package operatorbridge

import "sync/atomic"

var activeValues atomic.Int32

// ActiveValues returns the counter owned by the process request store.
func ActiveValues() *atomic.Int32 { return &activeValues }

// HasValues reports whether any process-store value can carry provenance.
func HasValues() bool { return activeValues.Load() != 0 }
