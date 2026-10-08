// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2

package json

// instrumentedPropagationPoints is the number of propagation points of
// orchestrion.yml on the v2 variant of encoding/json: the aspects with the tag
// [v2] or [shared] that change code of encoding/json or encoding/json/v2, and
// that move taint on this variant (TestInstrumentedPropagationTelemetry). They
// are the NewDecoder owner capture, the string arshaler wrap (string
// materialization), and the Decode value document. The Decode reader binding
// and the string cache guard are not propagation points on this variant.
//
// Go 1.26 with GOEXPERIMENT=jsonv2 is not supported. It reports the same
// count, but it has no wrapper and no consumer of the owner token.
const instrumentedPropagationPoints = 3
