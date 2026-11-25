// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func main() {
	settings := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "-race", "-asan", "-msan":
				settings[setting.Key] = setting.Value
			}
		}
	}
	result := struct {
		Enabled  bool              `json:"enabled"`
		Gate     uint32            `json:"gate"`
		Reason   string            `json:"reason"`
		Settings map[string]string `json:"settings"`
		Mapped   uint64            `json:"mapped"`
		OtherSys uint64            `json:"other_sys"`
		MapOK    bool              `json:"map_ok"`
	}{Enabled: heapranges.Enabled(), Settings: settings}
	if knobs.Gate != nil {
		result.Gate = knobs.Gate()
	}
	if knobs.OffReason != nil {
		result.Reason = knobs.OffReason()
	}
	if len(os.Args) > 1 && os.Args[1] == "slab" && knobs.MapSlab != nil {
		result.MapOK, result.Mapped = knobs.MapSlab()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		result.OtherSys = stats.OtherSys
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}
