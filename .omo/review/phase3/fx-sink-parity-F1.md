# fx-sink-parity-F1: SQL evidence truncation boundary

HEAD checked: `2e23b4614320defd0d32177a69888dcab73f4d11`.

## Verdict per finding

**sink-parity-F1 — CONFIRMED.** With the default 250-character evidence budget, an unredacted tainted SQL part beginning at offset 250 is serialized as `{"source":0,"truncated":"right"}`. The shared IAST schema requires both `source` and `value` on an unredacted tainted part. The missing field occurs in both JSON and the normal MessagePack encoding, not only in the finder's JSON fixture. Only one finding was submitted; there are no duplicate IDs to combine.

## Reproduction (commands + key output lines)

Own reproducer: `.omo/review/evidence/fx-sink-parity-F1/independent_boundary_test.go`; captured output: `.omo/review/evidence/fx-sink-parity-F1/independent_boundary.out.txt`. To recreate the private copy after cleanup, run from the main checkout:

```sh
mkdir -p /tmp/ddiast-review/wt
rsync -a --exclude .git --exclude .omo ./ /tmp/ddiast-review/wt/fx-sink-parity-F1/
cp .omo/review/evidence/fx-sink-parity-F1/independent_boundary_test.go /tmp/ddiast-review/wt/fx-sink-parity-F1/internal/taint/redaction/
cd /tmp/ddiast-review/wt/fx-sink-parity-F1
GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test -timeout 5m -run '^TestIndependentSQLBoundaryEvidence$' -count=1 -v ./internal/taint/redaction
```

The expected exit is **1**, because the test asserts the schema requirement against the defective code. Key output:

```text
encoding=json prefix=249 tainted_part={"source":0,"truncated":"right","value":"x"}
encoding=msgpack prefix=249 tainted_part={"source":0,"truncated":"right","value":"x"}
encoding=json prefix=250 tainted_part={"source":0,"truncated":"right"}
encoding=msgpack prefix=250 tainted_part={"source":0,"truncated":"right"}
GO_TEST_EXIT=1
```

The test starts a real request taint owner, taints a parameter, propagates it into SQL text, collects taint evidence, runs SQL analysis and redaction, and serializes the resulting event with both encoders. It only raises sampling to 100% to make admission deterministic; it checks that enabled, redaction, and the 250-character budget retain their defaults. This is an internal-API reproduction, not a woven application or live-backend test.

## Reachability

**Yes, under default configuration on Go 1.26.6.** A sampled customer HTTP request (30% by default) can put a tainted identifier after a 250-character SQL prefix using supported direct concatenation; the documented `database/sql` sink calls the same collection, analyzer and `BuildWithSensitive` conversion. The 252-byte example is well within the 32-KiB analyzer cap. The README documents the 250-character truncation budget, **not** an exception to the evidence schema or omission of a required tainted value. The malformed wire evidence breaks the reporting/provenance contract; the retained `source:0` still points to the correct source, however, and downstream rejection was not measured.

## Adjusted severity

**Medium (original High).** This is a proven schema-invalid edge case on a supported path, but no backend rejection or false-positive/false-negative vulnerability has been demonstrated to meet the brief's High criterion.

## Root cause (file:line)

`internal/taint/redaction/source.go:120-177` appends an output part even when `truncateEvidence` has no characters left (`:230-243`). `buildPart` keeps its source index and `truncated:right` but receives an empty value (`:187-208`). `internal/model/evidence.go:54-60` omits empty `value` in JSON; the generated MessagePack encoder makes the same omission at `internal/model/evidence_gen.go:171-174`. The required fields are defined by `system-tests/tests/appsec/iast/vulnerability_schema.json` (`UnredactedTaintedValue`).

## Minimal fix

Do not emit zero-length unredacted tainted parts. When an unsafe part would start after the budget, reserve at least one character for a source-linked tainted part by truncating preceding literal evidence and marking that truncation; verify the resulting JSON and MessagePack shapes at 249 and 250 characters. Simply dropping the source-linked part would hide the taint attribution while still reporting a vulnerability.
