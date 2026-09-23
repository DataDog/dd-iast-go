# fx-store-memory-bounds-F3: Short evidence parts pin full snapshots

## Verdict per finding

### store-memory-bounds-F3 — CONFIRMED

The backing-retention mechanism and the supported-maximum memory overrun are
real. I independently reproduced it with 64 active request scopes, each bound
to its own span, rather than the phase-2 harness's one-scope/many-span setup.

## Reproduction

Target was HEAD `2e23b4614320defd0d32177a69888dcab73f4d11` on Go 1.26.6,
darwin/arm64. The independent internal-API test taints a SQL-injection
expression, joins it into a 32,768-byte query, runs the real SQL analyzer and
default redaction/truncation, then commits findings to bound span annotations.
It uses distinct synthetic vulnerability hashes to fill the configured
per-event limit; it does not exercise Orchestrion hooks or global report
deduplication.

Reproducer source:
`.omo/review/evidence/fx-store-memory-bounds-F3/repro/zz_review_f3_independent_test.go`

```sh
cd /tmp/ddiast-review/wt/fx-store-memory-bounds-F3 && env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 DD_IAST_MAX_RANGE_COUNT=64 DD_IAST_VULNERABILITIES_PER_REQUEST=64 DD_IAST_REDACTION_ENABLED=true DD_IAST_TRUNCATION_MAX_VALUE=250 timeout 900 go test -count=1 -timeout 12m -v -run '^TestIndependentF3SQLSnapshotRetention$' ./internal/taint/store
```

Captured output is in
`.omo/review/evidence/fx-store-memory-bounds-F3/01-independent-sql-retention.txt`:

```text
events=64 activeRequests=64 vulnerabilities=4096 queryBytes=32768 defaultTruncationCharacters=250 identityBytes=640 heapBefore=19062784 heapAfter=156958720 delta=137895936 wholeFeatureCeiling=25165824 ratio=5.48 pinnedPerEvent=2097152 pinnedPrefix=true
eventSources=1 eventVulnerabilities=64 wireBytes=24863 fallback=false
finishedHeap=17096704 released=139862016
PASS
```

The prefix's `unsafe.StringData` matched the full snapshot's pointer before
commit. The event retained it after the snapshot variable was cleared. The
test passed; exit code was 0.

## Reachability

Ordinary customer code can trigger the alias under defaults: sampled HTTP
request data can flow through supported string propagation into a
`database/sql` query, where the SQL sink collects, analyzes, redacts, and
commits evidence. Defaults in `internal/config/config.go:73-80` enable IAST,
sample 30%, allow two active requests and two findings per request, enable
redaction, and truncate values at 250 characters. Thus the mechanism is
reachable at default settings, although these default quotas do not reproduce
the 24 MiB overrun; a 32 KiB query with a short retained prefix can still pin
one full snapshot per finding.

The larger factor is reachable at supported maxima (64 requests and 64
findings per event), as the independent test shows. The README documents
larger backing retention for reader/writer anchors, but not report evidence
parts pinning sink snapshots. The design-intent document explicitly promises a
24 MiB whole-feature ceiling, so this report-time retention is not covered by
that accepted anchor trade-off and breaks product rule 3.

## Adjusted severity

**High** — retained `HeapInuse` grew by 137,895,936 bytes (5.48 times the
24 MiB ceiling) at supported limits; the bounded data is released at span
finish, so this is not an unbounded-growth Critical.

## Root cause (file:line)

- `internal/taint/redaction/source.go:172,187-214` slices the full cloned
  snapshot into value parts and leaves short, untruncated parts backed by it.
- `internal/model/truncation/truncation.go:14-15` returns values within the
  character limit unchanged.
- `internal/spans/tainted.go:115,274-294` copies part headers into the event
  without cloning their strings. Its admission charge at
  `internal/spans/tainted.go:81-102,141-162` covers only newly added source
  identity names and values, not evidence parts or their backing storage.

## Minimal fix

At event commit, clone each retained evidence `Value`/`Pattern` after redaction
and truncation, and reserve the complete retained evidence cost (part/mark
arrays, strings, and model records) against a process-wide event-memory budget.
Reject a commit when that budget is exhausted; the 25,000-byte encoded-payload
limit alone is not a retained-heap limit.
