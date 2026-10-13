// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package config

import (
	"fmt"

	"github.com/DataDog/dd-iast-go/internal/config/loader"
)

type observation struct {
	name        string
	value       any
	environment bool
}

var (
	observations []observation
	warnings     []string
)

func init() {
	load(loader.Observer{
		Warn: func(format string, args ...any) {
			warnings = append(warnings, fmt.Sprintf(format, args...))
		},
		RegisterDefault: func(name string, value any) {
			observations = append(observations, observation{name: name, value: value})
		},
		RegisterEnvironment: func(name string, value any) {
			observations = append(observations, observation{name: name, value: value, environment: true})
		},
	})
}

// Observe reports the immutable configuration resolved during package
// initialization. Repeated calls replay the same values without reloading or
// changing process configuration.
func Observe(observer loader.Observer) bool {
	for _, warning := range warnings {
		if observer.Warn != nil {
			observer.Warn("%s", warning)
		}
	}
	for _, item := range observations {
		if item.environment {
			if observer.RegisterEnvironment != nil {
				observer.RegisterEnvironment(item.name, item.value)
			}
		} else if observer.RegisterDefault != nil {
			observer.RegisterDefault(item.name, item.value)
		}
	}
	return Enabled
}
