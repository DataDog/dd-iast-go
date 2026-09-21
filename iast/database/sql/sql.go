// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package sql provides database/sql injection instrumentation.
package sql

import (
	"context"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/sqlbridge"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
)

var sqlSkip = vulnerability.SkipWhile{
	Namespaces: []string{
		"github.com/DataDog/dd-iast-go/iast/database/sql",
		"github.com/DataDog/dd-iast-go/internal/vulnerability",
		"github.com/DataDog/dd-iast-go/internal/spans",
		"github.com/DataDog/dd-iast-go/internal/taint/sqlbridge",
		"github.com/DataDog/dd-trace-go",
		"database/sql",
	},
	MaxDepth: 32,
}

// Report analyzes one completed database/sql operation. The minimal bridge
// shields callback panics so this function cannot replace a host result.
func Report(ctx context.Context, query string, kind sqlbridge.Kind) {
	_ = kind
	telemetry.ExecutedSink.SqlInjection.Add(1)
	snapshot, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	if status != evidence.StatusCollected {
		return
	}
	vulnerability.ReportTainted(
		ctx,
		constants.VulnerabilityTypeSqlInjection,
		snapshot,
		redaction.AnalyzeSQL(query),
		2,
		sqlSkip,
	)
}

func init() {
	// The source-shape test keeps this link-time total aligned with the
	// three prepare, four exec, and four query method bodies.
	telemetry.InstrumentedSink[constants.VulnerabilityTypeSqlInjection] += 11
	sqlbridge.Register(Report)
}
