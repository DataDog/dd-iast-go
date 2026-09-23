# fx-sink-json-sources-F1: Go 1.27 JSONv2 Decoder build

Scope: HEAD `2e23b46`; `iast/encoding/json/orchestrion.yml`,
`iast/encoding/json/json_test.go`, `orchestrion.tool.go`, `go.mod`, README,
phase-1 design intent, and the Go 1.26.6/1.27.0 `encoding/json` sources.

## Verdict per finding

**sink-json-sources-F1: CONFIRMED.** My own minimal customer program compiles
and runs with ordinary Go 1.27.0, but its Orchestrion-woven build fails while
compiling `encoding/json`. This is a compile failure, not merely missing taint
propagation. There is only one finding under test, so no duplicate to merge.

## Reproduction (commands + key output lines)

The independently written program is
`.omo/review/evidence/fx-sink-json-sources-F1/main.go`. I placed the same
source at `/tmp/ddiast-review/wt/fx-sink-json-sources-F1/review-json-f1/main.go`
inside a private repository copy. Its `main` calls
`json.NewDecoder(strings.NewReader(...)).Decode(...)` and prints the value.
Build commands ran with `GOFLAGS=-p=4`; the full captures are alongside the
source in `.omo/review/evidence/fx-sink-json-sources-F1/`.

```console
$ env GOFLAGS=-p=4 GOTOOLCHAIN=go1.27.0 go -C /tmp/ddiast-review/wt/fx-sink-json-sources-F1/review-json-f1 run .
independent-f1
$ env GOFLAGS=-p=4 GOTOOLCHAIN=go1.27.0 /usr/bin/time -l go -C /tmp/ddiast-review/wt/fx-sink-json-sources-F1/review-json-f1 tool orchestrion go build .
# encoding/json
$WORK/b002/orchestrion/src/encoding/json/<generated>:2: dec.r undefined (type *Decoder has no field or method r)
$WORK/b002/orchestrion/src/encoding/json/<generated>:2: dec.d undefined (type *Decoder has no field or method d)
WOVEN_127_EXIT=1
$ env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 /usr/bin/time -l go -C /tmp/ddiast-review/wt/fx-sink-json-sources-F1/review-json-f1 tool orchestrion go build .
WOVEN_126_EXIT=0
$ env GOFLAGS=-p=4 GOTOOLCHAIN=go1.27.0 GOEXPERIMENT=nojsonv2 /usr/bin/time -l go -C /tmp/ddiast-review/wt/fx-sink-json-sources-F1/review-json-f1 tool orchestrion go build .
WOVEN_127_LEGACY_EXIT=0
```

The failing output is `woven-go127-output.txt`; the successful controls are
`plain-go127-output.txt`, `woven-go126-output.txt`, and
`woven-go127-legacy-output.txt`. `selected-sources-output.txt` records
`go list -f '{{.GoFiles}}' encoding/json`: default Go 1.27 selects
`v2_stream.go`, while Go 1.26 and Go 1.27 with `nojsonv2` select `stream.go`.
The highest recorded peak RSS was 434,749,440 bytes, below the brief's 4 GB
reporting threshold.

## Reachability

**Reachable by default on Go 1.27.0:** no IAST runtime switch, active request,
or unusual customer code is required. The root `orchestrion.tool.go` imports
the JSON integration, and the join point matches `Decoder.Decode` in the
standard library. `go.mod` specifies Go 1.26.6; it does not pin compilation
to that compiler. The same woven program builds on default Go 1.26.6.

README.md:36 documents **Go 1.26 JSON propagation coverage**, and the phase-1
design-intent document lists unsupported JSON destinations. Neither documents
or accepts failure to compile valid programs on Go 1.27. This is **not** a
documented compile-break limitation; even if Go 1.27 provenance is initially
unsupported, a broken host build violates the repository's first product rule.

## Adjusted severity

**Critical (unchanged):** an ordinary woven Go 1.27 application fails to build
with valid `encoding/json` usage, exactly matching the brief's Critical
compile-failure criterion.

## Root cause (file:line)

`iast/encoding/json/orchestrion.yml:36-47` injects `dec.r` and `&dec.d`
unconditionally into `(*encoding/json.Decoder).Decode`. Go 1.27's selected
`$GOROOT/src/encoding/json/v2_stream.go:20-31,74-91` defines `dec`, `opts`,
`err`, `hadPeeked`, and `hadEOF` instead. Disabling JSONv2 restores the
legacy fields and makes the build pass. The other four advice blocks
(`orchestrion.yml:49-123`) target legacy `decodeState` methods absent from
the selected JSONv2 source, so they cannot supply JSONv2 provenance.

## Minimal fix

Restrict legacy `Decoder`/`decodeState` advice to the legacy
`encoding/json` implementation. On JSONv2, either add separately tested
join points that preserve provenance or safely omit this propagation without
injecting invalid field references. Add a minimal woven Decoder build control
for both default Go 1.26.6 and default Go 1.27.0.
