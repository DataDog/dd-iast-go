// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2

package json

// decoderPropagates reports whether (*json.Decoder).Decode propagates taint
// on this variant of encoding/json. The v2 variant does: the ReadValue
// wrapper of Decode gives the value bytes to the owner of the reader (plan
// encoding-json-v2, section 6.3).
const decoderPropagates = true

// decoderSourceHasLeadingWhitespace reports whether the source value of a
// Decode can start with the whitespace before the value. The v2 decoder
// reads the whitespace before it reads the value (jsontext ReadValue), thus
// the source value starts at the first byte of the value.
const decoderSourceHasLeadingWhitespace = false

// decoderTaintsNumberTokens reports whether a json.Number that Decode makes
// from a number token has taint. The v2 decoder decodes the tainted clone,
// and the runtime hooks taint the string conversion of
// (*Number).UnmarshalJSONFrom.
const decoderTaintsNumberTokens = true

// newDecoderAllocations is the number of allocations of json.NewDecoder in
// the unwoven v2 variant: the Decoder and its jsontext.Decoder.
const newDecoderAllocations = 2

// unmarshalTaintsKeysAndAny reports whether json.Unmarshal taints map keys
// and interface{} strings on this variant. The v2 variant does: they use the
// default string arshaler (plan encoding-json-v2, decision Q1).
const unmarshalTaintsKeysAndAny = true

// activeStringTagAllocations is the number of allocations that the JSON
// aspects add for one ,string field of clean bytes while the gate is open.
// The v2 string wrapper adds none.
const activeStringTagAllocations = 0

// unmarshalHasStringCache reports whether the decoder of json.Unmarshal keeps
// a string cache across calls. Only the decoder of the v2 variant does.
const unmarshalHasStringCache = true

// unmarshalCleanAllocations is the number of allocations of one json.Unmarshal
// of unmarshalAllocationDocument in the unwoven build of this variant
// (TestUnmarshalAllocationBaseline). With the gate off, the woven build must
// have the same number.
const unmarshalCleanAllocations = 5

// variantTag is the tag of the aspect ids of orchestrion.yml that apply only
// to this variant (TestInstrumentedPropagationTelemetry).
const variantTag = "[v2]"

// variantJSONv2 reports whether the test binary has the v2 files of
// encoding/json. The shape tests parse the files of this variant.
const variantJSONv2 = true
