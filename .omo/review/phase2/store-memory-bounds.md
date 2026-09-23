# store-memory-bounds: taint storage has no hard retained-memory ceiling

Verdict: FAIL - fixed request/store quotas work, but two independently unbounded retention paths and a 5.49x whole-feature memory overrun invalidate the hard-footprint guarantee.

Scope covered: `internal/taint/store/{limits,store,owner,root,value,overflow,mutation,lookup,binding,writer}.go`; request manager, source table, scope, reader and HTTP/lazy source ownership; range layout/canonicalization and the complete ranges test suite; `internal/spans/{annotation,owner,tainted,payload,orchestrion}.go`; `internal/vulnerability/dedup/dedup.go`. Traced supporting evidence, redaction, model/truncation, configuration, writer wrappers, and JSON/writer bridges. Target: HEAD `2e23b46`, Go 1.26.6, darwin/arm64. Evidence root: `.omo/review/evidence/store-memory-bounds/`.

## Findings

### store-memory-bounds-F1: Strong reader and writer anchors retain arbitrarily large uncharged allocations

- Severity: Critical
- Category: memory-bound
- Location: `internal/taint/store/binding.go:29-35,166-203`; `internal/taint/store/writer.go:23-42,224-229`
- Claim: Fixed reference counts do not bound reachable bytes. `request.BindReader` retains a complete reader graph; a tracked `bytes.Buffer` can hold a 64-byte capacity-limited view into an arbitrarily large backing allocation. One live owner suffices. Increasing the backing allocation does not increase the reader charge and leaves the buffer charge at 64 bytes. Thus there is no constant worst-case retained-heap bound, even without exceeding any table limit. This challenges the explicitly accepted trade-off in `README.md:70-77` under product rule 3 and this assignment's severity rule; it is not an undocumented behavior or a claim that memory remains leaked after finish.
- Evidence: `repro/internal/taint/store/zz_review_anchor_test.go`, with its GC helper in `zz_memory_bounds_review_test.go`; captured output `01-store-and-anchors.txt`, all under the evidence root. Real `bytes.Reader` binding and the actual `BufferWriteString` wrapper each retained exactly **33,554,432** and **100,663,296** extra bytes after GC for 32/96 MiB inputs. Incremental charges were **0** for readers and **64** for buffers. Untracked controls returned to baseline; finish released exactly the retained payload in every case. Exact executed command is recorded in log 01; isolated replay after the evidence README setup: `timeout 900 go test -count=1 -timeout 12m -v -run '^TestBoundsRetainedAnchors$' ./internal/taint/store`.
- Fix: Do not strongly retain arbitrary receiver/reader graphs or unverified backing views. Preserve identity with a bounded scheme that does not keep the object graph alive; retain only owned, completely sized copies when safe, and drop propagation where allocation ownership cannot be established. Merely reducing the reference-count cap cannot establish a byte bound.

### store-memory-bounds-F2: Non-atomic annotation admission permits unbounded map growth

- Severity: Critical
- Category: memory-bound
- Location: `internal/spans/annotation.go:131-143,198-205,227-236`
- Claim: `hasSpace := trimStore()` runs separately from `LoadOrCompute`. Arbitrarily many concurrent new-span calls can all observe available capacity, then each insert its own 3,200-byte annotation. The map has no fixed slot ceiling, and its entries remain while the spans are live. Request owner permits do not protect the legacy `AnnotationFor` path. The 2 MiB source charge cannot help because empty annotations consume zero charged source bytes. The same check/insert separation exists in `BindScope`; the reproducer exercises `AnnotationFor`.
- Evidence: `repro/internal/spans/zz_review_annotation_admission_test.go`, `annotation-schedule.patch`, and `03-annotation-admission.txt` under the evidence root. A private-only channel barrier pauses immediately after the capacity read and changes no decision or map logic. At configured capacity **64**, the actual API retained **128**, **512**, and **2,048** annotations, respectively **2x**, **8x**, and **32x** capacity; the last run added **7,651,328 HeapInuse bytes**, with source charge zero. All entries were removed by finish. There is no limit on the number of callers that can reach this barrier before any insertion; this is a missing constant bound, not merely a fixed overshoot. The same schedule passed under `-race` without a data-race warning (`04-ranges-and-race.txt`). Exact command: `env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 DD_IAST_MAX_RANGE_COUNT=64 timeout 900 go test -count=1 -timeout 12m -v -run '^TestBoundsAnnotationAdmission$' ./internal/spans`, from the private copy after applying the preserved patch.
- Fix: Atomically reserve an annotation permit before construction/insertion, release it on duplicate/failed insertion and every removal, and include negative sampling decisions. A fixed-capacity table is another option. Checking map size again without a reservation still races.

### store-memory-bounds-F3: Short evidence parts pin full snapshots outside the event byte budget

- Severity: High
- Category: memory-bound
- Location: `internal/taint/redaction/source.go:187-207`; `internal/spans/tainted.go:114-162,274-294`; `internal/taint/evidence/evidence.go:293-300`
- Claim: A short, untruncated first evidence part remains a substring of the complete cloned sink snapshot. `TryCommitTainted` copies part headers, not their backing strings, while reserving only newly introduced source identity bytes. Repeated findings with the same source therefore retain fresh full snapshots with essentially no additional charge. The event payload cap is checked on encoding, not retained storage; even an event below 25,000 encoded bytes can retain MiBs. With 64 annotations and 64 vulnerabilities each, a 32 KiB SQL snapshot per finding retains **134,217,728 backing bytes alone**, before metadata, despite 250-character truncation.
- Evidence: `repro/internal/taint/store/zz_review_event_retention_test.go` and `06-sql-evidence.txt` under the evidence root. The harness uses the real source API, join wrapper, collector, SQL analyzer, redactor, annotation map, and commit API. `AnalyzeSQL` returns `AnalysisOK`; redaction stays enabled; each evidence contains only `"xx"` plus 248 characters. **64 events / 4,096 vulnerabilities** added **138,264,576 HeapInuse bytes (5.49x 24 MiB)**, while exact source identities totaled **192 bytes** and root charge was **32,784**. One event encoded to **21,772 bytes**, `fallback=false`, while retaining **2,097,152 snapshot bytes**. Finish/GC released **138,403,840 bytes**. Exact command: `env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 DD_IAST_MAX_RANGE_COUNT=64 DD_IAST_VULNERABILITIES_PER_REQUEST=64 timeout 900 go test -count=1 -timeout 12m -v -run '^TestBoundsEventEvidenceRetention$' ./internal/taint/store`, from the private copy.
- Fix: Clone the final retained evidence substrings into compact owned storage and reserve their actual retained bytes, part/mark arrays, and event models against a process budget before commit. Truncation or a serialization cap alone is not a retained-heap bound. Reconcile the combined budget with the promised 24 MiB ceiling.

## Checked and found correct

### Derived fixed storage and charged limits

All sizes below are bytes, from `unsafe.Sizeof` on the required toolchain;
they are object-layout totals, not assertions about allocator span occupancy.
Let `C = DD_IAST_MAX_CONCURRENT_REQUESTS`, clamped to 0..64, and
`R = DD_IAST_MAX_RANGE_COUNT`, clamped to 1..64.

| Storage | Derivation / maximum |
| --- | ---: |
| Value index | `256 shards * 128 slots * 32` = **1,048,576**; locks/probe metadata bring shards to **1,062,912** |
| Root records | `64 * 512 * 320` = **10,485,760** |
| Inline ranges, included in roots | `64 * 512 * 10 * 24` = **7,864,320** |
| Overflow ranges | `256 * (64-10) * 24` = **331,776**, plus **512** free-index bytes |
| Object-binding tables | `64 * (256 * 32 + 512 * 2 + 32)` = **591,872** |
| Writer records | `64 * 8 * 1,616` = **827,392**; their fixed 64-range sets are included |
| Remaining owner metadata | **91,136** |
| Remaining store metadata | **88** |
| Complete `Store` | **13,391,448** |
| Request `Source` / `Table` / analysis slot | **48 / 13,336 / 13,384** |
| Complete `Manager` | `64 * 13,384 + 64 * 8 + 16` = **857,104** |
| Fixed store + manager | **14,248,552** |
| Shared managed-root/writer charge | `min(8 MiB, C * 2 MiB)` |
| Nominal fixed + maximal charge | **22,637,160** = approximately **21.589 MiB** |

The fixed arrays are allocated for all 64 owners even at the default `C=2`;
changing `R` does not shrink them. Initialization is lazy. With `C=0`, normal
request admission does not initialize a new manager. Once initialized, fixed
storage remains allocated after owners finish.

The HEAD result is **16,392 bytes above** the historical 22,620,768-byte plan
figure, but remains below 24 MiB **only for this restricted accounting sum**.
It excludes report storage, object graphs, bridge state, caller workspaces,
and allocator fragmentation.

Other enforced limits, including allocations already charged above:

- Process live values: **16,384**; owner values: **4,096**; root windows:
  **256**. Physical index capacity is **32,768 slots**, including stale numeric
  entries. Probes stop at **64**; compaction after **32 tombstones** uses one
  `128 * 32 = 4,096`-byte scratch table, not a growing overflow chain.
- Each owner has **512 roots**, **256 sources**, **256 bindings**, at most
  **8 reader bindings**, and **8 writer records**. At `C=64` those are 32,768
  roots, 16,384 sources/bindings, and 512 readers/writers. Binding/source
  indexes contain **512 uint16 slots** each. Root/source maxima cannot all
  consume their largest payloads simultaneously because byte/value quotas
  intersect.
- Root visible length/capacity and source name are each capped at
  **65,536**. `TaintSourceBytes` charges backing capacity, immutable source
  value, and name: at most **196,608** per reservation, shared with the
  2 MiB/8 MiB quotas. Known sizes round through `sizeClasses` up to 32,768,
  then to **8 KiB pages**. Writer visible capacity uses the same shared charge.
- `Range` is **24**, `Set` **1,544**, lookup `Entry` **1,576**, and the
  four-owner `Snapshot` **6,312**. Canonicalization accepts **192** inputs;
  its three **383-range** scratch arrays total **27,576** bytes. These are
  bounded per call, not one globally capped allocation.

### Reporting and ancillary storage

The following are category bounds, not an additive worst-case heap total:
some data is shared; allocator rounding is separate; F1/F2 prevent a finite
whole-process bound in the first place.

| Storage / constraint | Byte consequence |
| --- | --- |
| Annotation | **3,200** each; intended 64 gives **204,800**, but F2 invalidates that global count |
| Owner-span directory | **512** fixed pointer bytes and at most `64 * 32 = 2,048` live binding-record bytes |
| Source identity/model descriptors | `256 * (40 + 64)` = **26,624/event**; nominal 64-event maximum **1,703,936** |
| Exact source strings | **262,144/event**, **2,097,152/process**, enforced on string lengths, not total event heap |
| Vulnerability/evidence/location structures | `64 * (24 + 64 + 80)` = **10,752/event**, excluding strings/parts |
| Value-part arrays | At most **513** parts/finding, `513 * 72 = 36,936` logical descriptor bytes; at 64 events x 64 findings this alone permits **151,289,856** logical bytes before rounding |
| Secure marks | At most **36** vulnerability-type identifiers per mark list, one byte each; copied separately by commit, not part of source-string accounting |
| Sink/source snapshots | Sink clone at most **65,536** plus cloned source strings at most **262,144**; up to 256 sources/ranges, 513 parts, four owners; bounded per collection call, no global collector semaphore |
| SQL/command analyzer | **32,768** input bytes, 256 intervals/command arguments, 16,384 SQL tokens per dialect; source comparison budget **1 MiB** |
| Event admission/encoding | `V=min(configured vulnerabilities,64)`; **25,000 encoded bytes** checked at finish, not a retained-storage reservation |
| Truncation config | Default **250 Unicode characters**, with no upper config clamp; upstream input caps still apply, but slicing can retain full backing (F3) |
| Process dedup | One fixed **4,040**-byte set, including **1,000 int32 hashes** and one-hour epoch/lock; full or expired set clears |
| JSON decoder bridge | **64 slots x 40 = 2,560** fixed bytes, four-probe admission; per-slot reader/document/quoted records are 16/40/24 bytes; at most **4 MiB** of 64 KiB document clones, often shared with store roots; reader graphs fall under F1 |
| Writer expectation bridge | **128 uintptr slots = 1,024** bytes plus scalar/callback state; four probes |
| HTTP eager/lazy scratch | 32 names/64 values and 48 names/96 values; 64-byte entry records plus string headers give **3,072 / 4,608** bytes of fixed arrays per call, excluding returned application maps |
| Other propagation work | Four owner snapshots, 16 inspected inputs, 32 windows or exact replacement matches; bufio tracked buffer <= **4,096** bytes |

Scope/owner handles are bounded-size objects (`Scope=64`, `Analysis=32`,
`store.Owner=40`), but application-held contexts and concurrent call stacks
are not globally bounded by the active-owner count. They are not silently
included in a purported fixed process-heap number.

### Empirical saturation

Measurements use `runtime.MemStats.HeapInuse` after GC; logs contain both
absolute readings and deltas. No test uses sleeps or timing-based success.

| Experiment | Observed result |
| --- | --- |
| Fixed store allocation | GC'd HeapInuse 1,302,528 -> 14,639,104; delta **13,336,576**, near the 13,391,448-byte layout, with baseline-runtime noise |
| All fixed owner tables | **64 owners, 32,768 root records, 16,384 bindings, 512 readers, 512 writers**, overflow free=0; extra allocations added **180,224** bytes |
| Root-record saturation method | Re-adopting the same complete allocation replaces its index key but fills separate root records; only 64 live values, charge **4,259,840**. This measures table occupancy, not distinct payload maxima |
| Range overflow | **256 roots with 64 ranges**; the 257th keeps exactly **10** and increments range-drop telemetry; finish restores all 256 blocks |
| Simultaneous process root/value caps | **8,388,608 charged bytes and 16,384 values** across 64 owners/2,048 roots; HeapInuse 14,630,912 -> 28,770,304, delta **14,139,392**; finish returned to baseline |
| Request/source saturation | **64 analyses x 256 sources**; 257th source rejected; charge **393,216**, HeapInuse delta **786,432**; finish reconciled all charges/values |
| Mutable-source maximum | 65,536 backing + 65,536 name + 65,536 immutable copy = **196,608 charged bytes** |
| Event source cardinality | **64 x 256 = 16,384 identities**, charge **262,144**, HeapInuse delta **2,695,168** |
| Event source byte budget | **8 x 256 KiB = 2 MiB**, ninth full event rejected; HeapInuse delta **3,129,344**; release returned charge to zero |
| Dedup saturation | 1,000 retained hashes; insertion 1,001 clears to one; exact one-hour advance expires it; no growing allocation |

The store-only saturated process reached approximately **27.44 MiB**
HeapInuse even before adding event storage. Charged sizes are not equivalent
to in-use allocator spans; the observed 1.69x root-charge/delta difference
must not be hidden by quoting `unsafe.Sizeof + ProcessRootBytes`.
This is below the assignment's >2x High threshold for that charge alone;
F3 independently exceeds the full 24 MiB budget by 5.49x.

Existing tests also passed for 2 MiB request and 8 MiB process rejection,
512 roots, 4,096 request/16,384 process values, the 257th root window,
64-probe collision overflow, oversized root/name/capacity rejection, failed
publication rollback, generation quota transfer, and overflow recovery.
Manager admission returned exactly 0/1/2/64/64 slots for requested
limits 0/1/2/64/65. The complete ranges suite passed. These apply the
phase-1 R9/S30 memory/saturation checks and verify synchronous anchor release;
there is no claim here of comprehensive provenance or mutation correctness.

## Not covered / open questions

- No finite numeric maximum exists under the current implementation. The
  counterfactual fixed-plus-charged sum must not be presented as the maximum
  of **all** taint storage. F1 needs a product decision revisiting the documented
  trade-off if the hard rule remains binding; F2/F3 are independent defects.
- No woven build, Go 1.27 run, live tracer export, whole-repository race suite,
  or build-time RSS measurement was performed. Direct wrappers/internal APIs
  were sufficient for these storage proofs; the admission reproducer alone
  was additionally run under `-race`. Mock tracer spans exercise actual
  annotation storage, not the production tracer's export queue.
- Snapshot/bridge scratch bounds were traced statically where outside the
  primary scope. Per-call workspaces, application-owned results retained after
  owner finish, runtime stacks/caches, and tracer export queues are not a
  promised constant process budget.
- The initial 64 KiB collector-only event experiment in log 02 bypassed SQL
  analysis and is not the F3 proof. Log 06 uses the actual 32 KiB analyzer cap,
  enabled redaction, and the final preserved source.
- All reproducer commands completed. No production fix was applied. Evidence,
  replay instructions, and the private-only scheduling patch were preserved;
  the private copy is removed as part of final verification.
