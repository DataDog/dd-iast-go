// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.arenas

package main

import (
	"arena"
	"fmt"
	"runtime/debug"

	"github.com/DataDog/dd-iast-go/internal/build"
)

func main() {
	a := arena.NewArena()
	defer a.Free()
	p := arena.New[int](a)
	*p = 17
	if *p != 17 || !build.Instrumented() {
		panic("failed")
	}
	info, _ := debug.ReadBuildInfo()
	for _, s := range info.Settings {
		if s.Key == "GOEXPERIMENT" {
			fmt.Printf("tool=%s %s=%s\n", build.Tool(), s.Key, s.Value)
		}
	}
}
