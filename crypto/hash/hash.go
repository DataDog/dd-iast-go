// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hash

import (
	"context"
	"crypto"

	"github.com/DataDog/dd-iast-go/internal/constants"
	"github.com/DataDog/dd-trace-go/v2/instrumentation/appsec/dyngo"
	"github.com/DataDog/dd-trace-go/v2/instrumentation/appsec/trace"
)

func ReportWeakHash(ctx context.Context, hash crypto.Hash) {
	op, _ := dyngo.FromContext(ctx)
	if op == nil {
		// No dyngo context, cannot report the finding...
		return
	}
	dyngo.EmitData(op, trace.SpanTag{Key: constants.SpanTagEnabled, Value: 1})
	dyngo.EmitData(op, trace.SpanTag{Key: constants.SpanTagEnabled, Value: `{"":""}`})
}
