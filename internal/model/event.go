// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"log/slog"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
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

// AtCapacity reports whether the event has the maximum number of
// vulnerabilities (the configured capacity, or [MaxVulnerabilities]). Then
// [Event.CanAddVulnerability] returns false for all vulnerabilities. A nil
// event is at capacity. AtCapacity does not log and does not mutate the event.
func (e *Event) AtCapacity() bool {
	return e == nil || len(e.Vulnerabilities) >= min(config.VulnerabilitiesPerRequest, MaxVulnerabilities)
}

// capacityWarning is the message of the telemetry log for a vulnerability
// that an event at capacity cannot get.
const capacityWarning = "max vulnerabilities per request reached, dropping"

// WarnAtCapacity sends the capacity log of [Event.CanAddVulnerability] for a
// report of vulnerabilityType that a sink drops before it makes the
// vulnerability, because the event is at capacity (see [Event.AtCapacity]).
// The log has the same level and message. The telemetry log sends one log for
// each level and message, thus the number of logs is bounded.
func WarnAtCapacity(vulnerabilityType constants.VulnerabilityType) {
	instrumentation.Instance.TelemetryLog().Warn(capacityWarning, slog.String("vulnerability_type", vulnerabilityType.String()))
}

// CanAddVulnerability reports whether vuln passes the configured hard capacity
// and event-local de-duplication checks. It does not mutate the event.
func (e *Event) CanAddVulnerability(vuln Vulnerability) bool {
	if e == nil {
		return false
	}
	if e.AtCapacity() {
		instrumentation.Instance.TelemetryLog().Warn(capacityWarning, slog.Any("vulnerability", vuln))
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
