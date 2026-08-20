// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package truncation provides bounded string retention for IAST model values.
package truncation

import "strings"

// String returns value unchanged when it contains at most maxCharacters Unicode
// characters. Otherwise, it returns a cloned prefix and reports truncation.
func String(value string, maxCharacters uint64) (result string, truncated bool) {
	if uint64(len(value)) <= maxCharacters {
		return value, false
	}

	var characters uint64
	for index := range value {
		if characters == maxCharacters {
			return strings.Clone(value[:index]), true
		}
		characters++
	}
	return value, false
}
