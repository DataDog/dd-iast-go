// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp

import "strings"

// CommandChainValues exposes the native transformations of a command path.
type CommandChainValues struct {
	Trimmed  string
	Replaced string
	Path     string
}

// BuildCommandChain transforms input through trimming, replacement, and a writer.
func BuildCommandChain(input string) CommandChainValues {
	result := CommandChainValues{Trimmed: strings.TrimSpace(input)}
	result.Replaced = strings.Replace(result.Trimmed, "not-present", "missing", 1)
	var writer strings.Builder
	writer.WriteString(result.Replaced)
	writer.WriteString("-chain")
	result.Path = writer.String()
	return result
}
