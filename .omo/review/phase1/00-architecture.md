# dd-iast-go taint tracking: implementation map

Scope: HEAD `2e23b46`; all non-test Go files and `orchestrion.yml` under
`taint/`, `internal/`, and `iast/`, including nested test applications. Paths
and line numbers below are relative to the repository root. This is a map of
implementation, not a claim that every propagation path is defect-free.

## Components by package

| Package | Responsibility and entry points |
| --- | --- |
| `taint` | Public generic `TaintString`, `TaintBytes`, `IsTainted*`, `Visit*`; public `Origin`, `Marks`, `Range` (`taint/taint.go:19-113,122-201`). `taint/orchestrion.yml:8` declares the package configuration. |
| `iast/net/http`, `iast/net/url` | Stdlib server entry, trace start, application handler and lazy request-source advice (`iast/net/http/orchestrion.yml:16-122,141-355`); URL query advice (`iast/net/url/orchestrion.yml:13-29`); trace binding helper (`iast/net/http/http.go:21`). |
| `iast/bufio`, `iast/io` | Reader identity propagation through `bufio.NewReaderSize`, `io.LimitReader`, `TeeReader`, `MultiReader`, and `ReadAll` (`iast/bufio/orchestrion.yml:16-33`; `iast/io/orchestrion.yml:13-85`). |
| `iast/encoding/json` | Decoder/unmarshal and string-literal hooks (`iast/encoding/json/orchestrion.yml:12-123`); callback registration and reflection filter (`iast/encoding/json/json.go:20-45`). |
| `iast/propagation` | Application-root direct-call replacements for `strings`, `bytes`, `fmt`, `strconv`, `net/url`, writer calls, plus operator, slicing, and conversion advice (`iast/propagation/orchestrion.yml:12-1082`); wrappers preserve host operations (`iast/propagation/strings.go:19-219`, `bytes.go:15-195`, `coarse.go:19-105`, `writer.go:19-244`, `operators.go:18-305`). |
| `iast/database/sql`, `iast/os/exec` | SQL prepare/exec/query advice and root-executable sink bootstrap (`iast/database/sql/orchestrion.yml:16-117`; `sql.go:34-56`); command callback after the `os.StartProcess` attempt (`iast/os/exec/orchestrion.yml:15-78`; `exec.go:42-98`). `iast/crypto/{cipher,hash}` separately report weak algorithms through their YAML and `ReportWeak*` wrappers (`iast/crypto/cipher/cipher.go:20`; `iast/crypto/hash/hash.go:18`). |
| `iast/internal/propagationtest`, `iast/*/testapp` | Instrumented call-site fixtures and nested-module executable bootstraps, not runtime state (`iast/internal/propagationtest/strings.go:17-91`, `bytes.go:10-39`, `writer.go:16-324`; `iast/integration/testapp/chains.go:14-33`). |
| `internal/config/{parser,loader}` and `internal/config` | Parse, clamp, load environment configuration on initialization (`internal/config/parser/parser.go:59-123`; `loader/loader.go:42-110`; `config.go:16-85`; `init.go:25-58`). |
| `internal/taint/request` | Scope sampling/admission and source-owner directory (`scope.go:28-145`; `owner.go:18-103`); bounded source deduplication (`table.go:15-84,130-190`); eager/lazy HTTP sources (`http.go:51-155`; `lazy.go:16-229`); reader associations (`reader.go:16-128`); validated provenance visitor (`lookup.go:13-162`). |
| `internal/taint/store` | Fixed process store, owner generations and address identity (`store.go:39-180`; `owner.go:18-64,155-215`); strong root anchors, derivation, accounting (`root.go:21-268,281-398`); sharded value index, stale reclaim (`value.go:31-228,231-314`); snapshot (`lookup.go:10-198`), root-generation invalidation (`mutation.go:18-98`), object bindings (`binding.go:14-245`), stateful writers (`writer.go:15-550`). |
| `internal/taint/ranges` | Bounded owner-local source-ID intervals and safety-mark bitset (`ranges.go:15-99`; `marks.go:12-95`); canonical precedence/fragmentation (`canonical.go:14-135`); copy, slice, concatenate, join, repeat, compose, overwrite and coarse operators (`operations.go:25-438`). |
| `internal/taint/propagation` | Hot-path `ActiveStore`/`MayContain` gate followed by owner-separated snapshot and ranges operations (`propagation.go:110-196,220-260,326-426,428-701`); exact string/byte join/replace/UTF-8 (`string_exact.go:17-322`; `bytes_exact.go:25-489`); coarse transforms (`string_coarse.go:20-220`), conversion (`conversion.go:15-51`), JSON (`json.go:19-69`), concatenation (`operator_concat.go:9-79`) and writer synchronization (`writer.go:17-238`). |
| `internal/taint/{http,io,url,json,operator,writer,scope,sql,command}bridge` | Cycle-breaking callback and cheap activity gates: HTTP (`httpbridge/bridge.go:15-156`), readers (`iobridge/bridge.go:11-43`), query (`urlbridge/bridge.go:11-31`), JSON (`jsonbridge/bridge.go:15-241`), operators (`operatorbridge/bridge.go:11-17`), writers (`writerbridge/bridge.go:12-106`), scope finish (`scopebridge/bridge.go:11-30`), sinks (`sqlbridge/bridge.go:15-62`; `commandbridge/bridge.go:14-53`). |
| `internal/taint/evidence` and `internal/taint/redaction` | Bounded cross-owner exact-source snapshot, deterministic part ordering (`evidence/evidence.go:20-31,99-177,195-427`); SQL/command analyzers (`redaction/sql.go:23-185`; `redaction/command.go:12-44`), source/sink redaction and truncation (`redaction/source.go:35-320`). |
| `internal/vulnerability` | Build tainted reports, location/stack capture, dedup, commit (`tainted.go:31-126`; `report.go:30-109,121-171`); fixed-window process dedup (`dedup/dedup.go:14-126`); frame normalization (`stacktrace/stacktrace.go:12-89`). |
| `internal/spans` | Weak-key root-span annotation and owner-to-span weak binding (`annotation.go:26-55,114-249`; `owner.go:18-101`); source remap and bounded event commit (`tainted.go:18-31,61-167`); finish hook and span tags (`orchestrion.yml:14-30`; `orchestrion.go:27-60`); encoded-payload fallback (`payload.go:15-122`). |
| `internal/model` | `Event`, `Vulnerability`, `Evidence`, `ValuePart`, `Source`, `Location`, origin/type enums and MessagePack-generated codecs (`event.go:17-63`; `vulnerability.go:17-51`; `evidence.go:14-99`; `source.go:14-42`; `constants/origin.go:16-45`; `constants/vulnerabilitytype.go:17-65`; `*_gen.go`). `internal/instrumentation` adapts tracer telemetry and stack capture (`instrumentation.go:12-53`; `telemetry/telemetry.go:23-165`). |

## One request, from input to span

1. Orchestrion weaves `net/http` server/handler advice that calls
   `httpbridge.Begin`, `Eager`, and `Finish` around request execution
   (`iast/net/http/orchestrion.yml:16-45,82-122`).
   `request.scope.init` registers these callbacks, lazy HTTP callbacks,
   reader and URL callbacks (`internal/taint/request/scope.go:138-145`).
   `Begin` reuses an existing context scope or makes one immutable sampling
   decision, then obtains a manager permit up to configured concurrent requests
   (`scope.go:73-103,148-158`; `owner.go:55-103`). Disabled, sampled-out,
   capacity-dropped, and active decisions are distinct (`scope.go:28-35`).
2. `EagerHTTP` clones and taints URI/path/query, header names/values, binds URL
   and body-reader objects (`request/http.go:59-78,97-155`). `ParseForm`,
   `PathValue`, `Cookie`, `URL.Query` and related hooks lazily manage cloned
   map values or scalar results (`request/lazy.go:28-128,144-220`).
   `io`/`bufio` hooks propagate reader binding; `io.ReadAll` adopts its complete
   byte result and JSON decoder may clone body bytes (`request/reader.go:27-128`).
   A source tuple `(origin,name,full value)` is hashed/deduplicated in the
   256-source per-analysis `Table`; only a successfully published root commits
   its source ID (`request/table.go:66-84,130-157`;
   `request/owner.go:136-230`).
3. Identity is **backing-address plus length plus kind**, not content:
   `StringKey` uses `unsafe.StringData`, `BytesKey` uses
   `unsafe.SliceData`, casts the address to `uintptr`, and rejects empty or
   over-`uint32` values (`store/store.go:39-61`). `uint32`-offset windows point
   into cloned/adopted strong string/byte roots, with owner/root generations
   and per-root range sets (`store/root.go:21-268`; `store/value.go:110-228`).
   The pointer-free 256-shard index can retain stale numeric addresses until
   lazy reclaim; **it never turns a `uintptr` back into a pointer**
   (`store/store.go:63-180`; `store/value.go:231-314`). Store lookup copies
   up to four validated owner snapshots, then request lookup resolves all
   source IDs under `sourceMu` (`store/lookup.go:104-198`;
   `request/lookup.go:59-162`). Object bindings keep strong typed pointers
   separate from the numeric comparison key (`store/binding.go:29-43,75-126`).
   Weak pointers belong to *span* associations, not to taint-value roots
   (`spans/annotation.go:26-35`; `spans/owner.go:18-25`).
4. Application-root operator and direct stdlib call-site advice runs original
   behavior before propagating taint (`iast/propagation/orchestrion.yml:12-1082`;
   `iast/propagation/operators.go:18-305`). Propagation first checks active
   analysis/value counters, input length and `MayContain`, then copies a live
   owner-separated snapshot; exact operations transform intervals while
   coarse operations widen only the intersecting source's range
   (`request/lookup.go:70-78`; `propagation/propagation.go:110-195,326-426`;
   `propagation/string_exact.go:21-111,113-189`;
   `ranges/operations.go:25-285`). Windows derive new keys within the same
   root. Copies clone or adopt a *complete* allocation. Byte mutation claims
   a new root generation before publication so a failed update cannot leave
   old provenance live (`store/mutation.go:18-98`). `strings.Builder` and
   `bytes.Buffer` retain separately charged writer state; alias/overlap
   invalidation and a dirty bit handle missed updates (`store/writer.go:73-112,363-432`;
   `propagation/writer.go:17-238`).
5. SQL `PrepareContext`/`ExecContext`/`QueryContext` and command
   `Cmd.Start`/`os.StartProcess` call bound sink callbacks only on an
   active-analysis fast gate (`iast/database/sql/orchestrion.yml:54-117`;
   `iast/os/exec/orchestrion.yml:48-78`;
   `sqlbridge/bridge.go:44-62`; `commandbridge/bridge.go:35-53`).
   SQL checks query text, not parameters; command assembles bounded argv
   after process attempt (`iast/database/sql/sql.go:34-56`;
   `iast/os/exec/exec.go:42-98`). `evidence.CollectString`/
   `CollectJoinedStrings` revalidate source ownership and collect copies;
   SQL/command analyzers find sensitive intervals, `redaction.BuildWithSensitive`
   emits redacted/truncated source identities and evidence parts
   (`evidence/evidence.go:99-177`; `redaction/sql.go:23-53`;
   `redaction/command.go:12-44`; `redaction/source.go:35-245`).
   `vulnerability.ReportTainted` chooses a bound root span or an orphan,
   captures a location, applies process dedup, and commits remapped source IDs
   under annotation lock (`vulnerability/tainted.go:31-126`;
   `spans/tainted.go:61-167`; `spans/owner.go:67-87`).
   Span `Finish` closes the annotation and attaches a 25,000-byte-limited
   MessagePack meta-struct (or JSON tag fallback), requests trace retention,
   and releases source-identity charges (`spans/orchestrion.go:27-60`;
   `spans/payload.go:46-105`). Scope `Finish` clears source/root anchors,
   counters, permit and owner-span binding (`request/scope.go:209-222`;
   `request/owner.go:257-273`; `store/owner.go:155-215`).

## Bridge wiring and initialization

The woven stdlib imports a small `*bridge` package, **not** the request,
propagation or reporting implementation, avoiding cycles with stdlib and
dd-trace-go. Bridges hold callbacks in `atomic.Pointer` and return an unchanged
result/no-op until registered; SQL, command and JSON also use active-owner
counters; operator/writer bridges use active-value/state counters
(`httpbridge/bridge.go:15-82`; `sqlbridge/bridge.go:23-62`;
`operatorbridge/bridge.go:11-17`; `writerbridge/bridge.go:23-83`).
`request.scope.init` installs HTTP, reader, URL hooks
(`request/scope.go:138-145`); `propagation.writer.init` installs writer
invalidation (`propagation/writer.go:17-33`); JSON, SQL and command package
`init` functions install their callbacks (`iast/encoding/json/json.go:20-26`;
`iast/database/sql/sql.go:51-56`; `iast/os/exec/exec.go:94-98`);
`spans.owner.init` registers scope-finish cleanup (`spans/owner.go:100-101`).
The first sampled request initializes `defaultManager` exactly once, binds
live counters and publishes the process manager only **after** wiring them
(`request/scope.go:47-59`). Root-executable bootstrap advice imports/activates
sink registration; library/plugin builds need not activate sinks
(`iast/database/sql/orchestrion.yml:12-31`;
`iast/os/exec/orchestrion.yml:12-30`). The trace span `Finish` hook is in
`internal/spans/orchestrion.yml:14-30`.

## Concurrency inventory

| Primitive | Protected state / failure policy |
| --- | --- |
| `sync.OnceValue`, `atomic.Pointer[Manager]`, manager `atomic.Uint64` bitset, slot atomics and `sourceMu` | One process manager; at most 64 analysis permits acquired by CAS; generation/directory/source-table publication and reset; `TryLock` failures drop source operations (`request/scope.go:47-59`; `request/owner.go:18-35,57-103,138-142,259-273`). |
| `Scope.mu` (`+checklocks:mu`) | Analysis and sampling decision read/finished without racing shared handler contexts (`request/scope.go:62-70,170-222`). |
| Store `ownerMu`, owner `lifecycleMu`, `rootsMu`, `bindings.mu`, `writersMu`, 256 `shard.mu`, `overflowMu` | Nonblocking slot acquisition, finish/write exclusion, root/range anchors, bound typed objects, writer state, address-index insertion/lookup, overflow free list (`store/store.go:74-180`; `store/owner.go:20-64,131-165`; `store/lookup.go:81-198`; `store/overflow.go:8-37`). Read/write hot-path locks mostly use `TryLock`/`TryRLock`, with `// +checklocksforce` on those unlocks (`store/owner.go:28,139-152`; `store/value.go:115-139`). Finish/reset take blocking locks after state transition. |
| Store owner/root generation, state, quotas, charged/value/root/writer counters, drop counters, writer dirty/version/index atomics | Revalidate owners and windows after lookup; CAS quotas and claims; keep process/request budgets; conservatively discard writer provenance when a mutation cannot lock, with seqlock-style pointer-index snapshots (`store/store.go:74-180`; `store/value.go:51-108`; `store/mutation.go:79-98`; `store/writer.go:76-112,412-432`). |
| Bridge atomic callback pointers, activity pointers/counters, JSON decoder-slot atomics, writer expectation table | Publish callbacks and gate woven hot paths; 64 decoder slots track pointer/depth/reader/document/quoted state; 128 expectation slots coordinate native buffer invalidation (`jsonbridge/bridge.go:15-44,59-102,206-240`; `writerbridge/bridge.go:12-29,51-106`). |
| `xsync.Map` with `weak.Pointer[tracer.Span]`, `Annotation.RWMutex` (`+checklocks:RWMutex`), `closed`/`RequestTainted` atomics, owner-span atomic pointers | Bound root-span annotations, serialize source remap/report commit/close, avoid holding spans alive through owner association (`spans/annotation.go:26-79,223-249`; `spans/owner.go:18-101`; `spans/tainted.go:61-167`). |
| Process-event-source-byte `atomic.Int64`, dedup `sync.Mutex` (`+checklocks:mu`), telemetry `atomic.Uint64` | CAS global source charge, nonblocking fixed hash set, lock-free counters (`spans/tainted.go:31,297-320`; `vulnerability/dedup/dedup.go:45-126`; `instrumentation/telemetry/telemetry.go:23-68`). Explicit `+checklocksignore` applies to dedup entry points (`dedup.go:57-59,76-79,106-109`). |

## Bounds and enforcement

| Limit | Enforced at |
| --- | --- |
| Config: sample `0..100%`, active requests `0..64` (default 2), vulnerabilities/request `1..64` (default 2), ranges/value `1..64` (default 10), truncation characters | Environment clamp (`internal/config/config.go:16-85`); scope admission (`request/scope.go:86-103`); event admission (`model/event.go:26-53`); range normalization (`ranges/ranges.go:15-49`); truncation (`model/truncation/truncation.go:13-26`). |
| 64 store owners; 16,384 process / 4,096 request values; 8 MiB process / 2 MiB request charged roots; root 64 KiB, source root charge 192 KiB, 512 roots/owner, 256 values/root | Constants (`store/limits.go:8-18`); owner acquire (`store/owner.go:20-64`), CAS reservations (`store/root.go:281-320`; `store/value.go:51-108,196-228`), clone/adopt checks (`store/root.go:21-268`), writer charge (`store/writer.go:474-495`). |
| 10 inline ranges/root, 64 total, 256 fixed overflow blocks; 256 shards x 128 slots, 64 probes, compact after 32 tombstones; size classes then 8 KiB pages | `store/limits.go:18-56`; overflow allocation (`store/overflow.go:8-37`), range publish (`store/root.go:347-367`), index insertion/compaction (`store/value.go:133-193,225-314`). Ranges canonicalization accepts at most `3*64=192` inputs and fixed `2*192-1` fragments (`ranges/ranges.go:15-26`; `ranges/canonical.go:14-84`). |
| 256 request sources, 512 source hash slots/probes; 256 typed object bindings with at most 8 reader bindings; 8 writers/owner; at most 4 owner snapshots | `request/table.go:15-31,130-157`; `store/binding.go:14-18,166-203`; `store/writer.go:210-222`; `store/lookup.go:10,117-139`. |
| 32 HTTP header names / 64 values; 48 lazy map names / 96 values; bufio tracked buffer <= 4,096 bytes; JSON 64 decoder slots with four-probe admission, document <= 64 KiB; 128 writer expectation slots | `request/http.go:51-54,97-106`; `request/lazy.go:16-18,163-173`; `iobridge/bridge.go:11-12`; `jsonbridge/bridge.go:33-44,103-124,206-240`; `writerbridge/bridge.go:12,51-106`. |
| Up to 32 derived windows/call, 16 join/coarse inputs (`maxInputs`), 32 exact replacement matches; redaction source-comparison work <= 1 MiB | `propagation/propagation.go:33-40,220-260`; `propagation/string_exact.go:17,191-241`; `redaction/source.go:23,279-293`. |
| Evidence <= 64 KiB sink value, 256 KiB copied source strings, 4x64 collected ranges, 513 parts, 256 distinct sources / argv entries; analyzers <= 32 KiB, 256 sensitive intervals / command arguments | `evidence/evidence.go:20-31,99-140,240-255,416-427`; `redaction/analyzer.go:10-17`; `redaction/command.go:12-25`; `redaction/sql.go:23-53`. |
| Event <= 256 exact sources, 256 KiB source strings/event, 2 MiB source strings/process, <= 64 vulnerabilities and 25,000 encoded bytes; dedup 1,000 hashes per one-hour window; stack capture max depth 64 / location recapture 8 | `spans/tainted.go:18-31,61-89,297-320`; `spans/payload.go:15-20,51-85`; `vulnerability/dedup/dedup.go:14-18,57-103`; `vulnerability/report.go:121-142,205-208`. Weak span-map admission checks `config.MaxConcurrentRequests` and trims dead keys (`spans/annotation.go:223-249`). |

The byte budgets count *known visible/owned allocations*, not arbitrary data
reachable from a bound reader, writer or an interior slice; this is a documented
trade-off (`store/binding.go:29-32`; `store/writer.go:23-27`; README,
Propagation coverage). Static fixed arrays also consume memory independently
of these charged counters.

## Invariants reviewers should test

* Each live address key is backed by a strong, complete managed allocation
  until its request owner finishes; `uintptr` is only an equality/range key,
  never a GC root. Adopted strings start at allocation base and adopted bytes
  describe full capacity (`store/store.go:6-10,39-61`;
  `store/root.go:184-247`). This assumes a live Go allocation retains a stable
  address throughout lookup and no distinct live allocation shares that
  address; `runtime.KeepAlive`/strong anchors matter at boundaries.
* A slice/substring window must be within the *same owner's* root span,
  with offset/length valid in `uint32`; source IDs are owner-local, not
  interchangeable across owners (`store/value.go:31-49,110-131`;
  `store/lookup.go:142-195`). A stale owner handle or root generation cannot
  publish into a reused slot (`store/owner.go:127-165`;
  `store/mutation.go:79-98`).
* Source metadata and its taint root commit as a pair; duplicate sources
  reuse an ID only for equal origin/name/full value. Callbacks must not retain
  borrowed visitor source strings after the synchronous visit
  (`request/owner.go:136-230`; `request/lookup.go:13-25,103-162`).
* Wrapped application operations must evaluate each original argument once,
  preserve panic/error/side effects, and only alter backing identity where
  replacement is semantically safe (`iast/os/exec/orchestrion.yml:48-78`;
  `iast/propagation/operators.go:18-305`). Byte aliases modified outside
  supported hooks and builder value copies are documented limitations
  (README, Propagation coverage), not automatically findings.
* The analysis permit, store owner, source table, span annotation and event
  source charge have separate lifetimes and bounds. Finish must reconcile
  every one exactly once, even after an unsuccessful publication
  (`request/scope.go:209-222`; `request/owner.go:257-273`;
  `store/owner.go:155-215`; `spans/orchestrion.go:27-60`).
* The map's `weak.Pointer` does not retain a span; owners' *typed object*
  bindings are strong. Late callbacks must revalidate both ID and generation
  before crossing from request provenance into a span
  (`spans/owner.go:18-101`; `store/binding.go:29-43`).

## Ten riskiest review areas (priorities, not findings)

1. GC address identity, allocation-base adoption and stale numeric slots:
   `store/store.go:39-61`, `store/root.go:184-247`,
   `store/value.go:231-314`.
2. Cross-request owner/source remapping during concurrent `Finish` and slot
   reuse: `request/owner.go:94-103,257-273`,
   `request/lookup.go:103-162`.
3. Root-generation claims versus concurrent value reservations and stale
   accounting: `store/mutation.go:25-98`, `store/value.go:75-108,196-228`.
4. `bytes.Buffer` copies and unseen mutation/alias invalidation, including
   expected-write collisions: `store/writer.go:73-112,363-432`,
   `writerbridge/bridge.go:51-106`.
5. JSON decoder-slot collisions/reentrancy, reflection targets and document
   identity: `jsonbridge/bridge.go:33-44,59-180,206-240`,
   `propagation/json.go:19-69`.
6. Boundary advice preserving customer evaluation order, panic and exact
   stdlib result under Go toolchain changes:
   `iast/propagation/orchestrion.yml:12-1082`,
   `iast/os/exec/orchestrion.yml:48-78`.
7. Exact-to-coarse range transitions under truncation and multibyte transforms:
   `ranges/canonical.go:14-84`, `propagation/string_exact.go:113-241`,
   `propagation/bytes_exact.go:110-355`.
8. HTTP eager/lazy source insertion after capacity or contention drops, plus
   `URL.Query` ownership ambiguity: `request/http.go:97-155`,
   `request/lazy.go:28-45,163-220`.
9. Redaction completeness for SQL syntax, command argv, cross-owner source
   identity and payload fallback: `redaction/sql.go:23-185`,
   `redaction/source.go:35-245`, `spans/payload.go:46-105`.
10. Span lifecycle, weak-key cleanup, dedup/annotation lock ordering and orphan
    reporting: `spans/annotation.go:114-249`, `spans/orchestrion.go:27-60`,
    `vulnerability/tainted.go:90-126`.
