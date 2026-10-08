// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import "strings"

// AnalyzeCommand joins argv with one ASCII space and marks everything after the
// initial command as sensitive. sudo and doas preserve one following command.
func AnalyzeCommand(argv []string) Analysis {
	if len(argv) == 0 {
		return Analysis{}
	}
	if len(argv) > MaxCommandArguments {
		return Analysis{Status: AnalysisOversized}
	}
	length := len(argv) - 1
	for _, argument := range argv {
		if len(argument) > MaxAnalyzerBytes-length {
			return Analysis{Status: AnalysisOversized}
		}
		length += len(argument)
	}
	value := strings.Join(argv, " ")
	analysis := Analysis{Value: value}
	preserved := len(argv[0])
	if isPrivilegeCommand(argv[0]) && len(argv) > 1 {
		preserved += 1 + len(argv[1])
	}
	if preserved+1 < len(value) {
		analysis.Sensitive = []Interval{{Start: uint32(preserved + 1), Length: uint32(len(value) - preserved - 1)}}
	}
	return analysis
}

func isPrivilegeCommand(command string) bool {
	base := command
	if index := strings.LastIndexAny(base, "/\\"); index >= 0 {
		base = base[index+1:]
	}
	return base == "sudo" || base == "doas"
}
