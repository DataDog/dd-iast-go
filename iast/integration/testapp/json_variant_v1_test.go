// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !goexperiment.jsonv2

package testapp_test

// The constants of this file give the expected results of the v1 variant of
// encoding/json (Go 1.26, and Go 1.27 with GOEXPERIMENT=nojsonv2). The v2
// variant has the same constants in json_variant_v2_test.go.

// jsonV2 reports whether encoding/json is the v2-backed variant.
const jsonV2 = false

// jsonTaintsKeysAndAny reports whether the JSON aspects taint map keys and
// interface{} strings. The v1 aspects do not (see "JSON decoding" in the
// README). The runtime hooks can still taint a verbatim key or interface{}
// string of json.Unmarshal (a conversion of the tainted input bytes). Thus the
// tests use escaped keys and strings for this case.
const jsonTaintsKeysAndAny = false

// decoderSourcePrefix is the part of the bytes before a value that the source
// value of a Decode keeps. The v1 decoder reads a value from the end of the
// previous value (stream.go, readValue), thus the source value starts with
// the whitespace between the two values.
func decoderSourcePrefix(whitespace string) string { return whitespace }

// decoderTaintsNumberTokens reports whether a json.Number that Decode makes
// from a number token has taint. The v1 decoder decodes its clean buffer.
const decoderTaintsNumberTokens = false

// unmarshalHasStringCache reports whether the decoder of json.Unmarshal keeps
// a string cache across calls. The v1 decoder does not.
const unmarshalHasStringCache = false
