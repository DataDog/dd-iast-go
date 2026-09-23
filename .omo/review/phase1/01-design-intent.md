# Design intent and documented limitations

## Reading rule for downstream reviewers

This is a map of the branch's stated contract, not independent confirmation that
each implementation or benchmark claim is true. Treat the completed-phase,
validation, and performance statements below as plan claims to verify against
HEAD. Do not file a defect merely because an item in the documented
limitations list is unsupported; challenge it only if the implementation
violates the stated safety boundary.

## Intended semantics

The branch implements request-scoped Go IAST taint tracking woven at compile
time by Orchestrion. HTTP-derived data is tainted with immutable source
identity `(origin, name, full unredacted value)`. Taint ranges are byte-offset
ranges with vulnerability-specific secure marks. Exact transformations preserve
range/source identity where practical; coarse transformations taint the whole
result with the first contributing source in deterministic order and intersect
marks so they cannot invent sanitization.

All taint state belongs to an active request owner. A process-visible lookup can
find owner-separated entries for the same value, including foreign active
owners, but owner completion synchronously releases anchors and invalidates the
request's values. A sink can therefore report taint from another *active* owner
on the sink span, while taint retained after the origin request finishes is
intentionally outside the first-release lifetime model.

The explicit host-safety priorities are: preserve application values, errors,
panics, evaluation order, aliases, and capacity; avoid unbounded waits;
gate expensive work behind cheap eligibility checks; and drop IAST provenance
rather than block or change host behavior. Numeric addresses are lookup
comparison keys only. Managed strong roots, not `uintptr` reconstruction or
weak handles over arbitrary data, own the backing allocation.

### Sources and propagation advertised by README

- HTTP sources include request URI/path/query, headers, cookies, form and path
  values, multipart values, supported reader provenance, and owned body results.
- Direct root-application calls support the README propagation matrix:
  named `strings`/`bytes` operations, formatting, URL/quote operations,
  builder/buffer operations, 2--16 operand string concatenation, supported
  string/byte slicing, byte-to-string conversions, and decoder-native JSON
  string materialization.
- SQL injection reports tainted query text at `database/sql` prepare/execute/
  query boundaries. Bound query parameters are deliberately not query evidence.
- Command injection reports only a process-start attempt in `exec.Cmd.Start`;
  command construction alone is deliberately clean.
- Evidence is segmented in sink-value order, references deduplicated sources,
  and is redacted before leaving the process.

The branch history reflects that sequence: range/store/request foundations,
HTTP sources, named propagation, report/sinks, JSON, operator support, and
finally expanded propagation validation. The last commits are coverage-plan and
coverage-test work (`b3aac975`, `fd7875e2`, `2e23b461`).

## Bounded-memory and bounded-work design

The plans require fixed-capacity tables and bounded probes rather than growing
maps or overflow chains. Under capacity pressure, a new root/value/range/source
or report is dropped; live entries are not evicted merely to admit it.

| Area | Documented limit / rule |
| --- | --- |
| Request admission | 30% default sampling; configured concurrent analyses default to 2, range 0--64; a hard process ceiling is 64 active owners. `0` disables owner acquisition. |
| Store topology | 256 shards, 128 slots per shard, maximum 64 probes; 16,384 process value entries and 4,096 per owner. |
| Managed roots | 512 roots per owner; 256 values per root generation; one root at most 64 KiB; 2 MiB charged roots per request and 8 MiB process-wide. Roots charge complete retained backing/capacity, not merely visible length. |
| Full feature envelope | Approved whole-feature fixed-plus-managed ceiling is 24 MiB. The Phase 9 claim is 22,620,768 bytes for final fixed store/manager/managed-root capacity, below that ceiling. |
| Source/object state | 256 sources and 256 object bindings per request. Empty values are untainted; new managed roots require at least two bytes. One-byte *derived windows* are a documented exception and may retain provenance from an existing safe root. |
| Ranges | Default 10 ranges; guaranteed capacity for ten ranges per admitted value; configured hard maximum 64. Excess ranges retain the earliest output-order prefix and drop the tail with telemetry. |
| Owner fanout / propagation work | At most four owners per snapshot/publication, 16 inspected inputs, 32 exact replacement segments, 32 published windows, and 256 value windows per root generation. Concatenation admits 2--16 operands; longer chains are a complete safe miss. |
| Stateful writers | At most eight writer receivers per owner, four owners per receiver, and 64 KiB charged visible capacity. Strong request-bounded receiver anchors are intentional; their full allocation retention is not charged exactly, but the number of anchors is bounded and release occurs with owner finish. |
| Reader and JSON state | At most eight reader bindings per owner; inspect only the first eight `io.MultiReader` inputs; bind `bufio.Reader` only at buffer size <=4 KiB. JSON documents/buffers over 64 KiB drop provenance. Decoder association has 64 process slots and at most four probes. |
| Report collection | At most four owners, 256 collected/canonical ranges, 256 sources, a 256-KiB snapshot workspace, 513 output parts, and 1 MiB of source-comparison work. |
| Sink and payload defenses | SQL/command analyzers cap input at 32 KiB. A serialized event caps at 25,000 bytes; 25,001+ uses the documented `MAX_SIZE_EXCEEDED` fallback. Event vulnerabilities have a hard maximum of 64. |
| De-duplication | Fixed process set of 1,000 hashes; one-hour epoch; clear all when full. Lock contention skips de-duplication rather than reporting. |
| Runtime configuration | Per-request vulnerability default 2, hard maximum 64; range default 10, hard maximum 64; source/evidence truncation default 250 Unicode characters. README values match `internal/config/config.go`. |

The high-level retention trade-off is explicit: a managed anchor can retain an
allocation larger than the visible substring or buffer view. The design accepts
that only because root/object/writer reference counts are bounded and every
anchor is released at owner completion. Review memory claims with retained-heap
tests, not just charged-byte counters.

## Deliberate limitations and accepted trade-offs

These are expected safe misses, not standalone bugs:

- Only direct calls in eligible root application packages propagate; calls
  through function or method values do not. Compiler-optimized conversion
  contexts (including calls, comparisons, map keys, ranges, and concatenation)
  are intentionally unwrapped.
- `+=`, string-to-byte conversion, `append`, `copy`, and direct byte
  index/slice assignments do not create tracked mutable roots. The Phase 6 plan
  calls this a mandatory safe stop because unregistered mutable aliases cannot
  be invalidated soundly with the bounded design.
- `strings.Replacer` tracks input-string provenance only, not tainted
  replacement terms. Builder value copies are unsupported.
- `bytes.Buffer` value-copy provenance exists only when backing pointer, unread
  pointer, length, and capacity match a tracked view. Divergent/historical views
  and a receiver after transfer can lose provenance. `Bytes`,
  `AvailableBuffer`, and `Peek` results are untainted; mutable exposure
  invalidates overlapping tracked views, even conservatively when bytes do not
  ultimately change.
- Request bodies are never consumed eagerly and arbitrary caller-owned
  `Body.Read(p)` buffers remain untainted. Supported wrapper/owned-result paths
  include `io.ReadAll`; unknown reader wrappers require an explicit
  integration.
- HTTP framework-specific sources, XML/general-reflection/third-party binders,
  database row sources, sanitizers, persistent cross-request taint, and
  non-SQL/non-command sink families are out of the initial scope.
- JSON supports string values in nested structs, arrays, slices, and typed map
  values, including named strings and `,string`. Custom unmarshaler output,
  decoded byte slices, interface values, typed map keys, and `map[string]any`
  keys are explicit misses. Reentrant use of the same decoder can lose outer
  provenance.
- Sink registration is injected for root-module executable `main` packages.
  Plugin, library, and non-root executable builds do not activate these
  request-scoped SQL/command sinks. No span produces an orphan event; the
  per-request quota limits each orphan event but not all orphan findings for a
  request.
- A strong writer anchor can make a stack receiver escape. The user accepted
  this writer-specific allocation trade-off; it is not a general exemption
  from the local performance gates.

## Status, pending external items, and historical caveats

The parent plan claims all repository-controlled phases are complete for the
authorized safe matrix. Phase 6 is complete only for concatenation, slicing,
and byte-to-string conversions; Orchestrion PR #881 is pinned at
`23afa71d6dcb` through pseudo-version
`v1.12.2-0.20260828141217-23afa71d6dcb` and remains pending a published
Orchestrion release.

Phase 7a/9 claims remain conditional on two accepted compatibility assumptions:
the RFC-derived redaction corpus must be replaced or validated against the
normative shared corpus, and a live backend fixture must confirm the
25,000-byte / `MAX_SIZE_EXCEEDED` wire behavior before general availability.
The plans also record that mutation-tool availability was not established
(`go-mutesting` and `mutilate` absent), although fuzzing and other repository
checks are claimed to have run.

The Phase 5/6 sampled-out HTTP measurements did not meet the original strict
upper-bound target: the recorded median was accepted by the user despite a
larger bootstrap upper bound. Treat that acceptance as a documented product
decision, but remeasure it before relying on it for a new performance claim.

## Plan-document contradictions recorded for review

1. `_docs/plans/taint-tracking-net-http-sqli-cmdi-phase-7a.md:5` still labels
   the phase as “draft, pending critic and user review,” while lines 445 and
   492 record implemented boundaries and approved activation. The parent plan
   also describes Phase 7a as complete. This stale header is a misleading status
   signal.
2. `_docs/plans/taint-tracking-net-http-sqli-cmdi.md:209` says the first version
   does not track one-byte values, but
   `taint-tracking-net-http-sqli-cmdi-phase-5.md:49` explicitly allows one-byte
   derived windows from an existing managed root. The intended distinction is
   “no one-byte new managed roots,” not “no one-byte provenance at all.”

No additional README/configuration contradiction was found in the cheap
comparison: README runtime settings agree with `internal/config/config.go`, and
the aggregate tool imports the documented propagation, JSON, I/O, HTTP, SQL,
and command integrations.

## Downstream verification checklist

1. Prove the store has fixed slot/probe/counter bounds and that every admission
   failure drops provenance without changing the host result.
2. Confirm owner finish releases roots, writer anchors, reader bindings, and
   object bindings synchronously enough to prevent post-finish retention.
3. Verify root charging uses complete retained backing/capacity and the final
   retained heap stays within the documented 24 MiB envelope under saturation.
4. Verify source cloning prevents interned/static backing from tainting equal
   unrelated application values; test the one-byte-root versus derived-window
   distinction.
5. Verify all enabled propagation aspects match only the advertised direct
   shapes, preserve single evaluation/panic/type/alias behavior, and omit every
   documented mutable safe miss.
6. Verify writer buffer-copy transfer/invalidation behavior, exposed mutable
   view invalidation, limits, and the accepted stack-receiver escape cost.
7. Verify reader wrapper limits, no eager reads, `io.ReadAll` data/error
   parity, and cleanup of reader associations.
8. Verify JSON token association, decoder reuse/reentrancy behavior, 64-slot
   four-probe saturation, and all documented unsupported destinations.
9. Verify SQL and command hooks preserve return/error/panic behavior, report
   only at stated sink boundaries, and use correct active/foreign-owner span
   selection.
10. Verify immutable evidence snapshots, source-index transactions, redaction
    fail-closed behavior, analyzer/event caps, and payload fallback boundaries.
11. Verify process/request de-duplication is bounded and contention does not
    suppress reporting permanently.
12. Re-run, rather than merely trust, the plan-claimed race, checkptr, woven,
    nested-module, fuzz, coverage, and benchmark evidence on Go 1.26.6.
