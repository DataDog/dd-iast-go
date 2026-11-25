// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/DataDog/dd-iast-go/internal/build"
)

func main() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("tool=%s other=%d\n", build.Tool(), m.OtherSys)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-race" || setting.Key == "-asan" || setting.Key == "-msan" || setting.Key == "GOEXPERIMENT" {
				fmt.Printf("%s=%s\n", setting.Key, setting.Value)
			}
		}
	}
}
