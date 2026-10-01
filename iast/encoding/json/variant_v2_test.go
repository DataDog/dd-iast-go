// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2

package json

// decoderPropagates reports whether (*json.Decoder).Decode propagates taint
// on this variant of encoding/json. The v2 variant does not propagate yet
// (plan encoding-json-v2, step 5).
const decoderPropagates = false

// newDecoderAllocations is the number of allocations of json.NewDecoder in
// the unwoven v2 variant: the Decoder and its jsontext.Decoder.
const newDecoderAllocations = 2
