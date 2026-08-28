# Phase 8 plan: bounded `encoding/json` propagation

## Decision

Instrument Go 1.26.6 decoder materialization boundaries. A post-decode
reflection traversal was rejected during review because it taints retained or
custom-produced values that cannot be attributed to an input token.

Typed string destinations pass through `(*decodeState).literalStore`, which has
the exact raw literal and destination `reflect.Value`. Decoder documents are published before unmarshal by binding
`Decoder.r` to `Decoder.d` and cloning each exact `d.data` document into a
managed HTTP body source from `decodeState.init`. Literal offsets in the mutable
decoder buffer are translated to that immutable clone. Direct `Unmarshal`
input already carries byte provenance.

## Architecture

- `internal/taint/jsonbridge` is the dependency-minimal atomic and panic-shielded
  bridge imported into `encoding/json`.
- `propagation.JSONString` looks up the complete document, proves the literal is
  an interior byte window, intersects source ranges with that window, and emits
  one coarse whole-result range on an equal-value managed clone.
- `iast/encoding/json` registers reader binding, document adoption, typed
  literal callbacks. Heavy registration is injected into
  root production `main` packages and excluded from generated `.test` mains.
- Aspects pin `Decoder.Decode`, `decodeState.init`, `literalStore`, and
  `literalInterface`. All callbacks are synchronous and request-bounded.

## Semantics and limits

- Only strings whose exact raw literal intersects tainted document ranges are
  propagated. Escaped and unescaped output is coarse because JSON unquoting is
  not affine in the general case.
- Nested structs, arrays, slices, and typed map values use decoder-native token
  attribution. Existing destination values, failed
  input, numbers, booleans, nil, decoded byte slices, and custom unmarshaler
  output are not tainted.
- Interface values, typed map keys, and `map[string]any` keys remain unsupported: Go 1.26 creates
  them inside object loops after `unquoteBytes`, with no Orchestrion 1.12.2
  statement-level join point that can preserve exact token association.
- Values shorter than two bytes and documents or decoder buffers beyond the
  existing 64-KiB managed-root limit safely drop.
- Decoder reuse republishes each document before its literals are decoded.
- Bridge panic recovery and safe misses preserve every host result and panic.

## Validation

Use isolated woven HTTP tests for tainted `Unmarshal` bytes, owner-bound and
reused `Decoder` readers, nested structs/maps/arrays, escapes, invalid input,
and downstream sink use. Pin Go source shape and jsonv1. Add inactive and
active-clean allocation benchmarks, telemetry counts, executable bootstrap
checks, race, vet, checklocks, checkptr, and aggregate woven tests. Register in
the aggregate tool, CI, and README only after all gates pass.
