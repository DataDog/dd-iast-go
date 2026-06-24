// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package constants

const (
	// Whether a request was analyzed by IAST:
	// - Not present when IAST is not enabled
	// - 0 when the request was dropped (i.e, because of sampling)
	// - 1 when the request was analyzed
	SpanTagEnabled = "_dd.iast.enabled"
	// JSON-encoded metadata about IAST findings for the request.
	SpanTagJson = "_dd.iast.json"
)
