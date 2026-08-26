// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package iobridge_test

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
)

func TestCallbacksCannotReplaceReadAllResult(t *testing.T) {
	propagated := false
	adopted := false
	iobridge.Register(
		func(input, output any) { propagated = input != nil && output != nil },
		func(_ any, data []byte) { adopted = string(data) == "body" },
	)
	input, output := new(int), new(int)
	iobridge.Propagate(input, output)
	if !propagated {
		t.Fatal("propagation callback was not called")
	}
	data := []byte("body")
	pointer := unsafe.SliceData(data)
	iobridge.ReadAll(input, data)
	if !adopted {
		t.Fatal("read-all callback was not called")
	}
	if pointer != unsafe.SliceData(data) || string(data) != "body" {
		t.Fatal("read-all callback changed its input slice")
	}
}
