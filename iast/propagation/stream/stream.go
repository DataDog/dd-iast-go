// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package stream weaves taint propagation hooks into the standard library
// packages fmt, io, bufio and encoding/json (plan heapbits-sqli-cmdi, section
// 6). The hooks copy the heap taint bits of internal/taint/heapbits where
// these packages move bytes with copy, append(x, y...) or make + copy (the
// runtime hooks of iast/runtime cannot see these operations). Import it
// through the repository's Orchestrion tool package.
//
// The hooks are in the bodies of the standard library functions. Thus they
// do not change the application source code. They do nothing until the
// first taint is set in the process (the sticky gate heapbits.Live).
//
// What the hooks do:
//
//   - fmt: the writes of a value (pad, padString, and the Write methods
//     that a Formatter calls) copy the bits of the written bytes (exact).
//     The padding growth keeps the bits of the old output. Generated text (%q,
//     %x, %v of a []byte, %T, %p, and the output of String, Error, GoString
//     and Format methods) of a tainted argument is tainted as a whole
//     (coarse), with a derived entry of the source of the argument. A
//     tainted format string makes the whole output coarse. The printer
//     buffer is cleared before it goes back to its pool.
//   - io.ReadAll: the bits of each chunk go to the final slice.
//   - bufio.Reader: the bits follow the bytes from the buffer to the caller
//     (Read, ReadBytes) and in the slide of fill. A delegated Read into reused
//     memory uses the read rule (see below).
//   - encoding/json: the slide and the growth of the Decoder buffer keep the
//     bits, the delegated Read uses the read rule, a string with escapes is
//     tainted as a whole (coarse), and the values of ",string" fields keep the
//     taint also when the string-to-slice propagation of the runtime is off.
//     With GOEXPERIMENT=jsonv2, the hooks do not apply.
//
// The read rule: before a delegated Read into memory that has taint bits
// (64 KiB or less), the hook keeps a copy of the bits, clears them, calls
// Read, then puts the old bits back on the bytes that Read did not write.
// The new bytes have only the bits that the Read sets (for example the bits
// of the request body).
//
// Known limits: copy and append(x, y...) in application code lose the taint;
// bufio.Writer, bufio.Scanner and fmt.Append* are not hooked.
package stream

// instrumentedPropagationPoints is the number of hooked standard library
// functions in orchestrion.yml (the aspects that are not declarations; the 2
// variants of (*fmt.pp).fmtString count as one). The application does not
// link this package, thus the aspect fmt-telemetry-decls gives the number to
// telemetry (see internal/taint/request/telemetry.go). TestAspectCount checks
// both values.
const instrumentedPropagationPoints = 18
