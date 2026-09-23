# sink-json-sources: encoding/json instrumentation
Verdict: Critical compatibility break: the woven `encoding/json.Decoder.Decode` hook makes valid Go 1.27.0 customer builds fail.
Scope covered: `iast/encoding/json/orchestrion.yml`, `iast/encoding/json/json.go`, `internal/taint/jsonbridge/bridge.go`, `internal/taint/propagation/json.go`, relevant unit/integration tests, and Go 1.26.6/1.27.0 `encoding/json` sources.

## Findings
### sink-json-sources-F1: Go 1.27 JSONv2 breaks every woven Decoder build
- Severity: Critical
- Category: compile-break
- Location: iast/encoding/json/orchestrion.yml:36-47
- Claim: The `Decoder.Decode` advice injects references to the legacy private fields `dec.r` and `dec.d`. Go 1.27.0 selects JSONv2 by default; its `encoding/json.Decoder` instead holds `dec`, `opts`, `err`, `hadPeeked`, and `hadEOF`. Building a valid program that uses `json.NewDecoder(...).Decode(...)` through the pinned Orchestrion fails while compiling the woven standard-library package, before customer code can run. The other four hooks target removed legacy `decodeState` methods, so simply omitting the invalid `Decode` injection would leave the advertised JSON propagation unsupported on that toolchain.
- Evidence: .omo/review/evidence/sink-json-sources/go127-jsonv2-repro/ (program and configuration) and .omo/review/evidence/sink-json-sources/go127-jsonv2-repro/build-output.txt; exact command: `go -C /tmp/ddiast-review/wt/sink-json-sources/review-json-go127 tool orchestrion go build .`; key output: `dec.r undefined` and `dec.d undefined`. The identical program builds cleanly with `GOTOOLCHAIN=go1.26.6`.
- Fix: Gate all legacy `encoding/json` advice off when JSONv2 is selected, and implement/test a separate JSONv2 propagation path before enabling it. At minimum, CI must compile a woven Decoder program against every supported Go toolchain and experimental-default combination.

## Checked and found correct
- On the pinned Go 1.26.6 toolchain, `GOTOOLCHAIN=go1.26.6 go -C /tmp/ddiast-review/wt/sink-json-sources test -count=1 -run '^TestSourceShape$' ./iast/encoding/json` passed: all five private join points and the three accessed legacy fields exist.
- The isolated reproducer program builds through Orchestrion on Go 1.26.6, showing that the failure is a toolchain compatibility regression rather than an invalid repro.
- `GOTOOLCHAIN=go1.26.6 go -C /tmp/ddiast-review/wt/sink-json-sources/iast/integration/testapp tool orchestrion go test -count=1 -timeout=15m -run '^(TestJSONDestinationClassesPreserveTheirContracts|TestJSONUnmarshalStringTagsInNestedAndMapValues|TestJSONDecoderReinitializedWithCleanReader)$' ./...` passed. It exercises arrays, slices, named string map values, nested `,string` fields, and decoder reuse with a clean reader.
- Added private review coverage for direct `json.Unmarshal` into an embedded struct and ran it with the pinned woven toolchain; both the embedded-struct case and the basic direct-unmarshal control passed, preserving decoded values and taint.
- `json.go` rejects decode errors, non-string/unsettable reflect values, and values with `UnmarshalJSON` or `UnmarshalText` methods before replacing a destination; the `,string` path records the outer quoted token so repeated equal raw tokens remain distinguishable.

## Not covered / open questions
- A JSONv2-compatible provenance design was not evaluated because the current instrumentation cannot compile under Go 1.27.0.
- Same-decoder reentrancy is a documented limitation; decoder-slot saturation and high-contention behavior were not stress-tested in this node.
