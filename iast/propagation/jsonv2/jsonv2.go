// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package jsonv2 weaves taint propagation hooks into the encoding/json/v2
// implementation of encoding/json (plan heapbits-sqli-cmdi, section 6). This
// implementation is the default from Go 1.27 (GOEXPERIMENT=jsonv2). Import it
// through the repository's Orchestrion tool package.
//
// The hooks are in the bodies of the standard library functions. Thus they
// do not change the application source code. They do nothing until the
// first taint is set in the process (the sticky gate heapbits.Live).
//
// What the hooks do (json.Unmarshal and (*json.Decoder).Decode get the same
// results as with the v1 hooks of iast/propagation/stream):
//
//   - encoding/json/jsontext (*decoderState).fetch: the slide and the growth
//     of the Decoder buffer keep the bits, and the delegated Read uses the
//     read rule of iast/propagation/stream.
//   - encoding/json/internal/jsonwire AppendUnquote: a string with escapes is
//     tainted as a whole (coarse), with a derived entry of the source of the
//     raw string. A clean raw string clears the bits of the appended bytes.
//   - encoding/json/v2 makeString: a tainted string does not use the string
//     cache of the decoder (a cache hit gives a string of an earlier call).
//
// The other strings are free: Unmarshal decodes its input in place, a string
// without escapes is a part of the input, and string(b) is a runtime hook.
//
// Without GOEXPERIMENT=jsonv2 (Go 1.26 by default, Go 1.27 with
// GOEXPERIMENT=nojsonv2), the hooked packages are not in the build: the hooks
// do nothing, and the v1 hooks of iast/propagation/stream apply.
//
// Known limits (the same as the v1 hooks): []byte values (base64),
// json.RawMessage, numbers and the results of custom unmarshalers have no
// propagation. The direct users of encoding/json/v2 and jsontext get the same
// hooks.
package jsonv2

// instrumentedPropagationPoints is the number of hooked standard library
// functions in orchestrion.yml (the aspects that are not declarations).
const instrumentedPropagationPoints = 3
