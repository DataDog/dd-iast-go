// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package commandbridge is the dependency-minimal bridge imported into os/exec.
package commandbridge

import (
	"context"
	"os"
	"sync/atomic"
)

type callback struct {
	report func(context.Context, []string)
}

var registered atomic.Pointer[callback]
var activeOwners atomic.Pointer[atomic.Uint64]

// Register installs the process command sink callback during initialization.
func Register(report func(context.Context, []string)) {
	if report != nil {
		registered.Store(&callback{report: report})
	}
}

// BindActiveOwners binds the process request-owner bitset used by the fast gate.
func BindActiveOwners(owners *atomic.Uint64) {
	if owners != nil {
		activeOwners.Store(owners)
	}
}

// Active reports whether any request analysis can own taint.
func Active() bool {
	owners := activeOwners.Load()
	return owners != nil && owners.Load() != 0
}

// StartProcess evaluates one OS process attempt and then reports its captured
// argv. The original process and error are returned unchanged; a host panic
// bypasses reporting and propagates unchanged.
func StartProcess(ctx context.Context, path string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	process, err := os.StartProcess(path, argv, attr)
	Report(ctx, argv)
	return process, err
}

// Report invokes the registered callback when analysis is active. Callback
// panics are recovered so instrumentation cannot replace a host result.
func Report(ctx context.Context, argv []string) {
	if !Active() {
		return
	}
	callback := registered.Load()
	if callback == nil {
		return
	}
	defer func() { _ = recover() }()
	callback.report(ctx, argv)
}
