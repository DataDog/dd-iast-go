// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2

package testapp_test

// The constants of this file give the expected results of the v2-backed
// variant of encoding/json (Go 1.27 default). The v1 variant has the same
// constants in json_variant_v1_test.go (plan encoding-json-v2, step 7).

// jsonV2 reports whether encoding/json is the v2-backed variant.
const jsonV2 = true

// jsonTaintsKeysAndAny reports whether the JSON aspects taint map keys and
// interface{} strings. The v2 aspects do: they use the default string
// unmarshaler, with the exact token of each string (decision Q1).
const jsonTaintsKeysAndAny = true

// decoderSourcePrefix is the part of the bytes before a value that the source
// value of a Decode keeps. The v2 decoder reads the whitespace before it
// reads the value (jsontext ReadValue), thus the source value starts at the
// first byte of the value.
func decoderSourcePrefix(string) string { return "" }

// decoderTaintsNumberTokens reports whether a json.Number that Decode makes
// from a number token has taint. The v2 decoder decodes the tainted clone of
// the value, and the runtime hooks taint the string conversion of
// (*Number).UnmarshalJSONFrom. The bytes come from the body, thus the taint
// is accurate.
const decoderTaintsNumberTokens = true

// unmarshalHasStringCache reports whether the decoder of json.Unmarshal keeps
// a string cache across calls. The v2 decoder does (encoding/json/v2,
// intern.go).
const unmarshalHasStringCache = true
