// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !goexperiment.jsonv2

package json

// decoderPropagates reports whether (*json.Decoder).Decode propagates taint
// on this variant of encoding/json. The v1 variant does.
const decoderPropagates = true

// decoderSourceHasLeadingWhitespace reports whether the source value of a
// Decode can start with the whitespace before the value. The v1 decoder
// reads a value from the end of the previous value (stream.go, readValue).
const decoderSourceHasLeadingWhitespace = true

// decoderTaintsNumberTokens reports whether a json.Number that Decode makes
// from a number token has taint. The v1 decoder decodes its clean buffer,
// and the v1 Literal path takes only string tokens.
const decoderTaintsNumberTokens = false

// newDecoderAllocations is the number of allocations of json.NewDecoder in
// the unwoven v1 variant: the Decoder.
const newDecoderAllocations = 1

// unmarshalTaintsKeysAndAny reports whether json.Unmarshal taints map keys
// and interface{} strings on this variant. The v1 variant does not (see "JSON
// decoding" in the README).
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

// variantTag is the tag of the aspect ids of orchestrion.yml that apply only
// to this variant (TestInstrumentedPropagationTelemetry).
const variantTag = "[v1]"

// variantJSONv2 reports whether the test binary has the v2 files of
// encoding/json. The shape tests parse the files of this variant.
const variantJSONv2 = false
