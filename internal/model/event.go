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

//go:generate go tool msgp -io=false -tests=false

type Event struct {
	// Sources is the list of sources where the input data for the vulnerabilities
	// originated (request parameters, headers ...).
	Sources []Source `json:"sources,omitempty" msg:"sources,omitempty"`
	// Vulnerabilities is the list of vulnerabilities found in the current
	// execution context.
	Vulnerabilities []Vulnerability `json:"vulnerabilities" msg:"vulnerabilities"`
}

// MaxVulnerabilities is the non-configurable hard event vulnerability bound.
const MaxVulnerabilities = config.MaxVulnerabilitiesPerRequest

func NewEvent() *Event {
	return &Event{
		Vulnerabilities: make([]Vulnerability, 0, min(config.VulnerabilitiesPerRequest, MaxVulnerabilities)),
	}
}

// AddVulnerability tries to add a new vulnerability to the event. Returns true
// if the vulnerability was added, false otherwise.
func (e *Event) AddVulnerability(vuln Vulnerability) bool {
	if !e.CanAddVulnerability(vuln) {
		return false
	}
	e.Vulnerabilities = append(e.Vulnerabilities, vuln)
	return true
}

// CanAddVulnerability reports whether vuln passes the configured hard capacity
// and event-local de-duplication checks. It does not mutate the event.
func (e *Event) CanAddVulnerability(vuln Vulnerability) bool {
	if e == nil {
		return false
	}
	if len(e.Vulnerabilities) >= min(config.VulnerabilitiesPerRequest, MaxVulnerabilities) {
		instrumentation.Instance.TelemetryLog().Warn("max vulnerabilities per request reached, dropping", slog.Any("vulnerability", vuln))
		return false
	}
	if config.DeduplicationEnabled {
		for i := range e.Vulnerabilities {
			if e.Vulnerabilities[i].Hash == vuln.Hash {
				instrumentation.Instance.TelemetryLog().Debug("de-duplicated vulnerability: %#v", slog.Any("vulnerability", vuln))
				return false
			}
		}
	}
	return true
}
