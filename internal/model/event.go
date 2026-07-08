// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

type Event struct {
	// Sources is the list of sources where the input data for the vulnerabilities
	// originated (request parameters, headers ...).
	Sources []*Source `json:"sources,omitempty"`
	// Vulnerabilities is the list of vulnerabilities found in the current
	// execution context.
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
}
