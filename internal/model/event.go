// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"log/slog"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
)

type Event struct {
	// Sources is the list of sources where the input data for the vulnerabilities
	// originated (request parameters, headers ...).
	Sources []Source `json:"sources,omitempty"`
	// Vulnerabilities is the list of vulnerabilities found in the current
	// execution context.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

func NewEvent() *Event {
	return &Event{
		Vulnerabilities: make([]Vulnerability, 0, config.VulnerabilitiesPerRequest),
	}
}

// AddVulnerability tries to add a new vulnerability to the event. Returns true
// if the vulnerability was added, false otherwise.
func (e *Event) AddVulnerability(vuln Vulnerability) bool {
	if len(e.Vulnerabilities) >= config.VulnerabilitiesPerRequest {
		instrumentation.Instance.TelemetryLog().Warn("max vulnerabilities per request reached, dropping", slog.Any("vulnerability", vuln))
		return false
	}

	if config.DeduplicationEnabled {
		vuln.ComputeHash()
		for i := range e.Vulnerabilities {
			e.Vulnerabilities[i].ComputeHash() // In case [config.DeduplicationEnabled] changed...
			if e.Vulnerabilities[i].Hash == vuln.Hash {
				instrumentation.Instance.TelemetryLog().Debug("de-duplicated vulnerability: %#v", slog.Any("vulnerability", vuln))
				return false
			}
		}
	}

	e.Vulnerabilities = append(e.Vulnerabilities, vuln)
	return true
}
