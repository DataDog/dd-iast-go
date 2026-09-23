# fx-sink-evidence-F1: verification of phase-2 finding sink-evidence-F1

Verdict: CONFIRMED — the mechanism is real and reproduced independently; severity adjusted High → Medium because it is unreachable under the default configuration (needs `DD_IAST_MAX_CONCURRENT_REQUESTS>=5`) and the report is still emitted with complete source provenance; only trace attachment degrades to the designed orphan path.

Scope covered: `internal/taint/evidence/evidence.go` (collection, canonicalize, addOwner), `internal/taint/store/lookup.go` (four-window lookup bound), `internal/vulnerability/tainted.go` (selectTaintedAnnotation), `internal/spans/owner.go` (owner-span bindings), `iast/os/exec/exec.go` + `internal/taint/commandbridge/bridge.go` (real sink entry), `internal/config/config.go` (admission defaults); private-copy reproductions at HEAD 2e23b46.

## Verdict per finding

### sink-evidence-F1: Joined evidence omits a contributing owner's bound span
- Verdict: **CONFIRMED** (single finding; no duplicates in the input set).
- Original severity: High. Adjusted severity: **Medium**.
- Claim verified at HEAD 2e23b46:
  - `evidence.CollectJoinedStrings` (evidence.go:120-177) visits up to `MaxJoinedValues = 256` arguments; each argument is looked up separately, and `store.Lookup` caps windows per *key* at 4 (store/lookup.go:10,117), so distinct arguments from distinct owners all contribute. Ranges from 5+ distinct owners reach `collector.ranges`.
  - `Snapshot.canonicalize` (evidence.go:339) calls `addOwner` per collected range, but `addOwner` (evidence.go:405-413) appends only while `len(s.owners) < maxOwners` where `maxOwners = store.MaxSnapshotOwners = 4` (evidence.go:32). A fifth distinct contributing owner's identity is **silently dropped** while its ranges/sources stay in the snapshot. The `OwnerCount` doc comment ("The store lookup has the same four-owner hard bound") is wrong for the joined path: the per-key lookup bound does not bound the number of owners in a joined snapshot.
  - `selectTaintedAnnotation` (internal/vulnerability/tainted.go:110-125) iterates only `snapshot.OwnerCount()` identities before falling back to `spans.NewOrphanTaintedSpan()`. If the only bound contributing span belongs to the dropped fifth owner, the report is committed to an orphan span — the wrong trace — despite a live, bound request span existing.
- Reproduction: two independent reproducers, both captured (see below). Control test proves the identical flow works when the bound owner is inside the four-identity cap, isolating the defect to the identity truncation.

## Reproduction

Private copy: `/tmp/ddiast-review/wt/fx-sink-evidence-F1` (removed after verification).

1. Independent reproducer (mine) — `evidence/fx-sink-evidence-F1/zz_fx_verify_owner_fanout_test.go`, exercised through the real command-sink entry `iast/os/exec.Report` (what the woven `os/exec` advice invokes via `commandbridge`):

```
cd /tmp/ddiast-review/wt/fx-sink-evidence-F1 && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 \
  go test -run 'TestFxDirectCollectionDropsFifthOwnerIdentity|TestFxJoinedReportOrphansFifthBoundOwner|TestFxControlFourthBoundOwnerFound' \
  -count=1 -timeout=10m -v ./internal/vulnerability
```

Key output (PASS = defect demonstrated; all three passed on first run):

```
--- PASS: TestFxDirectCollectionDropsFifthOwnerIdentity (0.00s)   # 5 owners contribute, snapshot.OwnerCount()==4, fifth identity absent
--- PASS: TestFxJoinedReportOrphansFifthBoundOwner  (0.02s)       # exec.Report(bg ctx): fifth owner annotation = 0 reports, exactly 1 finished orphan span
--- PASS: TestFxControlFourthBoundOwnerFound        (0.01s)       # control: 4 owners, 4th bound → its annotation gets the report, 0 orphans
```

Setup: 5 active request owners (`config.MaxConcurrentRequests = 8`), one distinct tainted argument per owner, only the fifth owner's span bound; `exec.Report(context.Background(), argv)` — the spanless-context shape the command sink can receive.

2. Finder's reproducer cross-checked (unmodified, same private copy):

```
cd /tmp/ddiast-review/wt/fx-sink-evidence-F1 && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 \
  go test -run '^TestJoinedEvidenceFindsFifthBoundOwner$' -count=1 -timeout=10m -v ./internal/vulnerability
--- FAIL: ... fifth owner reports = 0, snapshot owners = 4, orphan spans = 1; want 1 report on fifth owner
```

Captured outputs: `evidence/fx-sink-evidence-F1/fx_owner_fanout.out.txt`, `finder_owner_fanout.crosscheck.out.txt`.

3. Corroborating captured output from this node's earlier interrupted run (same workspace, kept as evidence): `fx_sink_evidence_f1.out.txt` records `default_max_concurrent=2 admitted=2 third=capacity_dropped; configured_max_concurrent=5 admitted=5; sources=5 snapshot_owners=4 fifth_owner_retained=false report_committed=true fifth_owner_vulnerabilities=0 orphan` — independently confirming both the defect and that the default admission limit of 2 cannot host five contributing owners.

## Reachability

- Not reachable under default configuration: `DD_IAST_MAX_CONCURRENT_REQUESTS` defaults to 2 (internal/config/config.go:67), so at most 2 owners can be live concurrently — five distinct contributing owners are impossible. Requires the documented, supported setting `DD_IAST_MAX_CONCURRENT_REQUESTS>=5` (clamped 0..64), plus ≥5 simultaneous requests each contributing a distinct argv element, plus the command sink firing from a context with no IAST-annotated span (e.g. a background goroutine reusing request data), plus the only bound span belonging to a truncated owner.
- Not a documented limitation: the four-owner report bound is documented (01-design-intent.md "Report collection: at most four owners"; evidence.go `OwnerCount` comment), but the documented model is a four-owner *collection* bound. The implementation collects ranges from more owners than it records identities for and then mis-attributes the report — an internal inconsistency, not the stated safe miss. It still breaks product rule 4 (accurate provenance) on a supported (non-default) configuration: the vulnerability event is emitted with complete source provenance, but attached to an orphan trace instead of the contributing request's span, defeating trace-correlation of the finding.
- A woven end-to-end run was not performed; the reproducer drives the exact sink entry (`exec.Report`) and reporting entry point the woven advice calls, without weaving.

## Adjusted severity

- **Medium** — a real mis-attribution defect on a supported path, but unreachable at default configuration, requiring a narrow concurrency shape, with the report still delivered (orphan) and no host impact, data loss, or false taint. Arguably High if `MaxConcurrentRequests>=5` were positioned as a mainstream production setting; on the brief's scale ("incorrect edge case with limited impact") Medium fits.
- Duplicates: none; the input set contains a single finding, so the duplicate question does not arise.

## Root cause

- `internal/taint/evidence/evidence.go:405-413` (`addOwner` silently discards identities beyond `maxOwners`, evidence.go:32 `maxOwners = store.MaxSnapshotOwners`), reached from evidence.go:339; the bound is inconsistent with joined collection (evidence.go:120-177), whose 256 per-key lookups can admit more than four distinct owners; consumed by `internal/vulnerability/tainted.go:110-125` which can then only select an orphan.

## Minimal fix

In `canonicalize`/`addOwner`, make the owner bound consistent with joined collection. Either (a) raise the snapshot owner bound to `MaxJoinedValues` (17 bytes per identity, ≤256) so every contributing owner is recorded, or (b) fail closed: when a contributing range's owner identity cannot be recorded, mark the snapshot dropped (`StatusDropped`) — or drop that range — instead of silently keeping its evidence while discarding its identity. Option (a) preserves the current report rate and matches the existing collection bounds; also correct the `OwnerCount` doc comment.
