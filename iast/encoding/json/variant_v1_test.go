// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !goexperiment.jsonv2

package json

// decoderPropagates reports whether (*json.Decoder).Decode propagates taint
// on this variant of encoding/json. The v1 variant does.
const decoderPropagates = true

// newDecoderAllocations is the number of allocations of json.NewDecoder in
// the unwoven v1 variant: the Decoder.
const newDecoderAllocations = 1

// unmarshalTaintsKeysAndAny reports whether json.Unmarshal taints map keys
// and interface{} strings on this variant. The v1 variant does not (plan
// encoding-json-v2, decision Q1).
const unmarshalTaintsKeysAndAny = false

// activeStringTagAllocations is the number of allocations that the JSON
// aspects add for one ,string field of clean bytes while the gate is open.
// The v1 Quoted aspect records the outer token of each ,string value.
const activeStringTagAllocations = 1

// unmarshalHasStringCache reports whether the decoder of json.Unmarshal keeps
// a string cache across calls. Only the decoder of the v2 variant does.
const unmarshalHasStringCache = false

// unmarshalCleanAllocations is the number of allocations of one json.Unmarshal
// of unmarshalAllocationDocument in the unwoven build of this variant
// (TestUnmarshalAllocationBaseline). With the gate off, the woven build must
// have the same number.
const unmarshalCleanAllocations = 16
