# map-arch: taint-tracking architecture map

Verdict: Architecture traced across the complete assigned production-source scope; no definite defect established during mapping (static review only).
Scope covered: All 125 non-test Go files and `orchestrion.yml` files under `taint/`, `internal/`, and `iast/` at HEAD `2e23b46`, including nested test applications. Detailed component, flow, concurrency, bounds and risk map: [00-architecture.md](00-architecture.md).

## Findings

No independently established findings. The ten follow-up review priorities in
`00-architecture.md` are hypotheses or high-impact seams, not rated defects.

## Checked and found correct

- Static trace connects `net/http` advice to scope creation, owner acquisition,
  eager and lazy source registration, request-owned store publication, direct
  propagation advice, SQL/command sink callbacks, redaction, report admission,
  span finish and owner teardown. Anchors are in `00-architecture.md`.
- Value identity uses address, length and representation kind, and store root
  records retain strong typed anchors; the numeric `uintptr` keys are not
  reinterpreted as Go pointers (`internal/taint/store/store.go:39-86`;
  `internal/taint/store/root.go:21-268`).
- Source metadata is committed after a successful store publication; generation
  checks appear on owner handles and lookup snapshots
  (`internal/taint/request/owner.go:136-230`;
  `internal/taint/store/lookup.go:30-43,142-195`).
- Bounded value/root/source/writer allocations and nonblocking hot-path locks
  have explicit enforcement sites (`internal/taint/store/limits.go:8-30`;
  `internal/taint/store/root.go:281-320`;
  `internal/taint/request/table.go:130-157`).
- The declared 256 event-source limit accepts the 256th distinct source and
  rejects the 257th: the `>=` check occurs *before* appending the next source
  (`internal/spans/tainted.go:80-104`).

## Not covered / open questions

- No builds, instrumented tests, race checks, runtime reproductions, or
  assertions of behavior on either Go toolchain were run: this assignment was
  a read-only architecture map, and no unverified Critical/High finding was
  raised. Downstream reviewers should exercise the ten seams in the map.
- Third-party runtime implementations (dd-trace-go, Orchestrion and sqllexer)
  were not independently audited; the map describes their call sites in this
  repository.
- Documented coverage exclusions and the explicit limits on memory retained
  through reader/writer graphs were recorded as invariants/trade-offs, not
  recast as unproven defects.
