// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package exec provides os/exec command injection instrumentation.
package exec

import (
	"context"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/commandbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
)

var _ [redaction.MaxCommandArguments - evidence.MaxJoinedValues]struct{}
var _ [evidence.MaxJoinedValues - redaction.MaxCommandArguments]struct{}

var commandSkip = vulnerability.SkipWhile{
	Namespaces: []string{
		"github.com/DataDog/dd-iast-go/iast/os/exec",
		"github.com/DataDog/dd-iast-go/internal/taint/commandbridge",
		"github.com/DataDog/dd-iast-go/internal/vulnerability",
		"github.com/DataDog/dd-iast-go/internal/spans",
		"github.com/DataDog/dd-trace-go",
		"os/exec",
		"os",
	},
	MaxDepth:    32,
	MaxFrameGap: 1, // Cmd.Start can be compiler-elided between bridge and Run.
}

// Report analyzes one attempted os.StartProcess operation. The minimal bridge
// shields callback panics so this function cannot replace a host result.
func Report(ctx context.Context, argv []string) {
	telemetry.ExecutedSink.CommandInjection.Add(1)
	if !mayContainArgument(argv) {
		return
	}
	analysis := redaction.AnalyzeCommand(argv)
	value := analysis.Value
	if analysis.Status != redaction.AnalysisOK {
		var ok bool
		value, ok = boundedJoin(argv)
		if !ok {
			return
		}
	}
	snapshot, status := evidence.CollectJoinedStrings(argv, " ", value, constants.VulnerabilityTypeCommandInjection)
	if status != evidence.StatusCollected {
		return
	}
	vulnerability.ReportTainted(ctx, constants.VulnerabilityTypeCommandInjection, snapshot, analysis, 2, commandSkip)
}

func mayContainArgument(argv []string) bool {
	if len(argv) == 0 || len(argv) > evidence.MaxJoinedValues {
		return false
	}
	active := request.ActiveStore()
	if active == nil {
		return false
	}
	for _, argument := range argv {
		key, ok := store.StringKey(argument)
		if ok && active.MayContain(key) {
			return true
		}
	}
	return false
}

func boundedJoin(argv []string) (string, bool) {
	if len(argv) == 0 || len(argv) > evidence.MaxJoinedValues {
		return "", false
	}
	length := len(argv) - 1
	for _, argument := range argv {
		if len(argument) > store.MaxRootBytes-length {
			return "", false
		}
		length += len(argument)
	}
	return strings.Join(argv, " "), true
}

func init() {
	commandbridge.Register(Report)
}
