// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !goexperiment.jsonv2

package json

// instrumentedPropagationPoints is the number of propagation points of
// orchestrion.yml on the v1 variant of encoding/json: the aspects with the tag
// [v1] or [shared] that change code of encoding/json, and that move taint on
// this variant (TestInstrumentedPropagationTelemetry). They are the Decode
// reader binding, the NewDecoder owner capture, and the four decodeState
// aspects (lifetime, quoted string, document, typed string).
const instrumentedPropagationPoints = 6
