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
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
)

// maxJoinedBytes is the largest joined command line that the fallback join
// makes. It is the largest value that an evidence collection examines.
const maxJoinedBytes = 64 << 10

var _ [redaction.MaxCommandArguments - evidence.MaxJoinedValues]struct{}
var _ [evidence.MaxJoinedValues - redaction.MaxCommandArguments]struct{}
var _ [maxJoinedBytes - evidence.MaxValueBytes]struct{}
var _ [evidence.MaxValueBytes - maxJoinedBytes]struct{}

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
	MaxFrameGap: 2, // The source IIFE and Cmd.Start can both be compiler-elided.
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
	snapshot, status := vulnerability.CollectJoinedStrings(ctx, argv, " ", value, constants.VulnerabilityTypeCommandInjection)
	if status != evidence.StatusCollected {
		return
	}
	vulnerability.ReportTainted(ctx, constants.VulnerabilityTypeCommandInjection, snapshot, analysis, 2, commandSkip)
}

// mayContainArgument is the cheap gate of Report: it returns true only when a
// request analysis is active and at least one argument has a taint bit. It
// does not allocate.
func mayContainArgument(argv []string) bool {
	if len(argv) == 0 || len(argv) > evidence.MaxJoinedValues || !request.ProcessManager().Active() {
		return false
	}
	for _, argument := range argv {
		if heapbits.AnyString(argument) {
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
		if len(argument) > maxJoinedBytes-length {
			return "", false
		}
		length += len(argument)
	}
	return strings.Join(argv, " "), true
}

func init() {
	// The pinned source-shape test guarantees one process-attempt call site.
	telemetry.InstrumentedSink[constants.VulnerabilityTypeCommandInjection] += 1
	commandbridge.Register(Report)
}
