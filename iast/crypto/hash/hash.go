// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hash

import (
	"context"
	"crypto"
	"encoding/json"
	"runtime"

	"github.com/DataDog/dd-iast-go/internal/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/instrumentation/appsec/dyngo"
	"github.com/DataDog/dd-trace-go/v2/instrumentation/appsec/trace"
)

func ReportWeakHash(ctx context.Context, hash crypto.Hash) {
	op, _ := dyngo.FindOperation[trace.SpanOperation](ctx)
	if op == nil {
		op, ctx = trace.StartSpanOperation(ctx)

		defer func() {
			span := spans.NewOrphanVulnerabilitySpan()
			defer span.Finish()
			op.Finish(span)
		}()
	}

	dyngo.EmitData(op, trace.SpanTag{Key: constants.SpanTagEnabled, Value: 1})

	//TODO: Figure out a way to slap the SpanID properly.
	var location *model.Location
	if _, file, line, ok := runtime.Caller(1); ok {
		location = &model.Location{Path: file, Line: &line}
	}

	event, err := json.Marshal(model.Event{
		Sources: []model.Source{{
			Origin: model.Origin(model.WEAK_HASH),
			Value:  hash.String(),
		}},
		Vulnerabilities: []model.Vulnerability{{
			Type:     model.WEAK_HASH,
			Evidence: &model.UnredactedStringValue{Value: hash.String()},
			Location: location,
		}},
	})
	if err != nil {
		//TODO: Log something?
		return
	}

	dyngo.EmitData(op, trace.SpanTag{Key: constants.SpanTagJson, Value: string(event)})
}
