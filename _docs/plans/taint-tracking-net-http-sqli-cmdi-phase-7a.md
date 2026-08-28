# Phase 7a plan: tainted reports and sink hooks

## Status

- **State:** draft, pending critic and user review
- **Parent:** [taint-tracking-net-http-sqli-cmdi.md](./taint-tracking-net-http-sqli-cmdi.md)
- **Dependencies:** Phases 1–5; independent of deferred Phase 6
- **Toolchain:** Go 1.26.6 and Orchestrion 1.12.2

This phase builds wire-compatible tainted evidence and adds SQL-injection and
command-injection sink hooks. Phase 7b remains the end-to-end HTTP-to-sink
integration gate.

Internal evidence reviewed for this plan includes the accepted July 2023 IAST
Evidence Redaction RFC, the IAST tainted-range/evidence schema RFC, and the 2026
IAST redaction-regex incident report. The accepted RFC fixes the source and
evidence pattern semantics, SQL-literal redaction, strict command redaction,
and shared corpus requirement. The incident requires linear or explicitly
bounded analyzers and a hard evidence-length cap before redaction.

## 1. Decisions and checkpoints

### 1.1 Decisions fixed by accepted specifications

- Tainted evidence uses consecutive `valueParts`; tainted parts reference an
  event-local source index.
- A sensitive source contains `redacted:true` and an alphanumeric `pattern`, not
  its raw `value`. Evidence occurrences reuse the corresponding pattern slice
  when it can be mapped; otherwise they use `*` characters.
- SQL redaction marks every dialect literal as sensitive.
- Command redaction preserves only the initial executable, optionally preceded
  by `sudo` or `doas`; the rest is redacted.
- Source name/value patterns use the existing canonical
  `DD_IAST_REDACTION_NAME_PATTERN` and `DD_IAST_REDACTION_VALUE_PATTERN`
  settings. `DD_IAST_REDACTION_ENABLED=false` keeps unredacted evidence.
- The shared cross-tracer redaction corpus is normative. A tokenizer is not
  accepted until it passes that corpus.

### 1.2 User checkpoint before sink enablement

Before sink integrations are added to `orchestrion.tool.go`, present:

1. golden prepare, execute, and command payloads in msgpack and JSON;
2. cross-owner source-index and overlap behavior;
3. the shared redaction corpus results for every supported SQL dialect and
   command case;
4. the final evidence and event-size boundary behavior;
5. untainted and sampled-out benchmark results.

The parent plan carries a 25,000-byte encoded-event limit and Java-compatible
`MAX_SIZE_EXCEEDED` sentinel. The 2026 incident separately establishes a
32-KiB pre-analyzer evidence cap. Implement both as independent constants, but
keep the event-limit sentinel behind this checkpoint until backend compatibility
is confirmed. If compatibility cannot be confirmed, sink aspects remain out of
the tool package.

## 2. Dependency-minimal sink bridges

Standard-library advice must not import reporting, tracing, formatting, SQL, or
command packages. Add:

- `internal/taint/sqlbridge`: callback takes `context.Context`, query string,
  and a small sink-kind enum;
- `internal/taint/execbridge`: callback takes `context.Context` and `[]string`
  argv.

Each bridge contains only atomic callback registration and a noinline slow path.
The zero value is a no-op before `init`. The slow callback boundary catches any
unexpected panic so reporting can never break the host operation. No host error
or panic is translated.

Registration lives in one dependency package that imports neither
`database/sql` nor `os/exec`. A bootstrap aspect adds a blank import of that
package to every application-root package, so it initializes before any root
package initializer can call a sink. The bootstrap aspect excludes all
`dd-iast-go/**`, `dd-trace-go/**`, bridge, and registration packages to prevent
self-weaving and cycles. Standard-library bodies import only their minimal
bridge. Adding integrations to `orchestrion.tool.go` only discovers the aspects
and is not treated as runtime registration.

Binary-level fixtures prove the complete initialization graph for ordinary,
test, synthetic-main, plugin, and root-package initializer variants. They call a
real sink from an application package initializer and verify the registered
callback, not only the bridge no-op. Dependency tests reject `database/sql` in
the bootstrap/SQL bridge closure and `os/exec` in the bootstrap/exec bridge
closure. Any cycle, missing init, early-init panic, or synthetic fingerprint
failure is a stop condition.

## 3. SQL injection boundaries

Instrument the Go 1.26.6 public operation bodies that own one application SQL
operation:

- `DB.PrepareContext`, `DB.ExecContext`, `DB.QueryContext`;
- `Conn.PrepareContext`, `Conn.ExecContext`, `Conn.QueryContext`;
- `Tx.PrepareContext`, `Tx.ExecContext`, `Tx.QueryContext`;
- `Stmt.ExecContext`, `Stmt.QueryContext`.

Non-context methods and `QueryRow*` delegate to these boundaries and receive no
second aspect. Internal driver retries remain inside one boundary, so a retry
cannot duplicate a report. `Stmt` hooks read the package-private prepared query
exactly once. Exact receiver/name matching and pinned source-shape compile tests
fail closed when Go changes delegation.

Each body installs a result-preserving deferred callback and performs expensive
reporting only after the original operation has selected its result. This cannot
consume a context deadline before the driver checks it or change the returned
error. Deferred callbacks are panic-shielded and cannot replace an original
panic. `Stmt` hooks check a nil receiver before reading its private query and
pass an explicit validity bit to one unconditional minimal-bridge defer. This
retains the original nil-receiver panic site without adding a prepared-statement
allocation.
Near-deadline, canceled-context, nil-receiver, panic-stack, and returned-error
fixtures lock this behavior.

Prepare and execution are distinct attempted sink operations and can report at
different application locations. Existing per-event and process location hashes
deduplicate repeated calls at one location. Query arguments are never passed to
the bridge: parameterized values therefore cannot become evidence, while a
tainted query string still reports.

SQL location skipping removes only contiguous leading frames in dd-iast-go,
dd-trace-go, and `database/sql`, then selects the first application frame.

## 4. Command injection boundary

Instrument the single `os.StartProcess` call inside `(*exec.Cmd).Start`. Command
construction does not report. `Run`, `Output`, and `CombinedOutput` converge on
`Start`.

A source-expression IIFE evaluates `c.ctx` and every original
`os.StartProcess` argument once. It calls the host `os.StartProcess` directly,
invokes a dependency-minimal reporting bridge with the captured argv only after
return, and returns the original process and error unchanged. Keeping the host
call in the woven body preserves its compiler escape contract; the bridge does
not use an unsound `noescape` assertion. Reporting after the call records an
attempted OS start even when it returns an error, while validation failures
before that call do not report. If the host call panics, the callback does not
execute and the original panic is unchanged. Location selection permits a cumulative two-frame gap budget across
the skipped prefix for the compiler-elided IIFE and `Cmd.Start` frames observed
in the pinned toolchain. It rejects larger total gaps; pinned source and woven
location tests constrain the accepted attribution shape.

Evidence is argv joined by one untainted ASCII space, with checked offsets for
argument ranges. The strict command redactor preserves argv[0], or preserves
`sudo`/`doas` plus argv[1] when present, and redacts all remaining command text.
A sensitive-source match can still redact a preserved command occurrence.

Command location skipping removes contiguous leading frames in dd-iast-go,
dd-trace-go, `os/exec`, and `os`, then selects the first application frame.

## 5. Fast gate and span selection

Sink callbacks use this order:

1. global enabled and active-analysis check;
2. `executed.sink` at the accepted verbosity;
3. string eligibility, key creation, `MayContain`, and exact lookup;
4. secure-mark filtering that confirms at least one unsafe range;
5. `executed.tainted`;
6. location, source, redaction, de-duplication, and payload work.

SQL first uses the supplied context span. Command first uses `Cmd.ctx`. Both then
use the current tracer span, a generation-validated contributing-owner binding,
and finally the existing orphan-vulnerability span. A tainted reporter uses an
external/current span only when an annotation is already present and open; it
never creates the first annotation on an arbitrary span that could already be
finishing. An absent or closed annotation falls through to an owner binding or
a fresh orphan span. Active request roots have their annotation established by
Phase 3 binding before user sinks execute.

Add a bounded owner-to-root-span directory in `internal/spans`, keyed by owner
index/ID/generation and containing only the existing weak root-span identity plus
annotation. `BindScope` publishes it; scope finish invalidates it through a
minimal callback so no span is strongly retained. Immutable report snapshots
carry the owner identity required for lookup. Multiple contributors select the
first span by the stable ordering from section 7.

One request sampling decision remains immutable. If the sink context explicitly
contains a sampled-out or capacity-dropped scope, the finding is suppressed even
when provenance belongs to another owner. With no sink scope, a confirmed
foreign contribution is reported on the selected/current/orphan span and is not
subject to a second random request decision. Finished or stale owner bindings
fall through safely. Fixtures cover every priority, stale/finished spans, several
owners, and a sampled-out sink scope.

## 6. Immutable taint snapshots and marks

Extend the synchronous request visit API only if needed to return a bounded
immutable report snapshot. The snapshot copies owner identity, byte range,
secure marks, and complete `Source{Origin,Name,Value}` metadata while owner
generation and state are revalidated. No request-local `SourceID` leaves the
visit. Borrowed source strings are copied into report-owned memory before each
synchronous callback returns, so an event never retains a managed request root
after owner finish. Collection uses a 256-KiB hard byte budget and a fixed
unique-source index. Exact `(Origin, Name, complete Value)` identity is deduped
while collecting; model truncation happens only after exact dedup. If the aggregate byte
budget, unique-source count, or workspace cannot hold the complete candidate
snapshot, drop the complete report with bounded visibility. Admission never
depends on store delivery order. A future deterministic selection policy
requires separate review.

At most four owners and 64 ranges per owner can contribute. Collection uses a
fixed or explicitly capped 256-range workspace. If a foreign owner finishes
between callbacks or cannot be revalidated, drop only that contribution and
count the bounded loss. Never emit a tainted part without a materialized source.
Maximum repeated-source, maximum distinct-source, finish-between-callback, and
retained-memory tests enforce the budget.

A range marked safe for the current vulnerability type is excluded. If no
unsafe range survives, count suppression and do not report. Other secure marks
are converted to `ValuePart.SecureMarks` without inventing marks.

## 7. Evidence segmentation and transactional event merge

Report assembly first creates local report-owned sources and value parts without
holding the span annotation lock.

Across owners, sort surviving ranges by byte start, then source origin/name/full
value, range length, marks, and validated owner identity as the final tie-break.
Store slot or delivery order is never used. First provenance wins; later
overlaps are clipped or dropped. Walk the original byte string once and emit
consecutive non-empty untainted and tainted parts. Byte offsets remain byte
offsets for UTF-8 and invalid UTF-8. Checked arithmetic and validated bounds
prevent panics.

Segmentation has explicit limits of 256 canonical taint intervals, 256 sensitive
redaction intervals, and 513 output parts after all splitting. Exceeding any
limit conservatively fully redacts the evidence while retaining bounded taint
parts/source references, or drops the report if that representation cannot fit.
No `2*ranges+1` or redaction split can grow without a checked cap.

Source identity is exact unredacted `(Origin, Name, Value)` before redaction and
model truncation. The annotation owns a fixed 256-entry identity sidecar with a
256-KiB cumulative byte budget. It retains complete cloned identities until
`Finished`, aligned one-to-one with `Event.Sources`; redaction and model
truncation never destroy dedup identity. If a new identity cannot fit, drop the
complete report rather than compare approximately. Local parts initially
reference local indexes. Under the annotation lock, one new
`Event.AddTaintedVulnerability` operation:

1. checks vulnerability capacity and per-event hash duplication;
2. maps local sources to existing or new event sources;
3. checks the 256-source hard limit;
4. remaps every local part index;
5. commits sources and vulnerability atomically.

A failed vulnerability commit cannot leave orphan sources or sidecar entries.
Concurrent findings cannot publish mismatched indexes. Existing
`model.NewVulnerability` hashing (type + path + line) remains unchanged.

Model truncation is applied after byte segmentation with one running evidence
character budget. It cannot be bypassed by many separately truncated parts.
The output part count is hard-bounded by the explicit interval/part limits and
payload budget.

## 8. Redaction

### 8.1 Source patterns

Compile configuration regexes once through Go RE2. The canonical environment
variables take precedence over compatibility aliases
`DD_IAST_REDACTION_KEYS_REGEXP` and `DD_IAST_REDACTION_VALUES_REGEXP`. Alias-only,
canonical-only, both-set, invalid-alias, and default cases are tested; telemetry
registers the effective canonical setting.

On a name or value match,
generate a deterministic alphanumeric placeholder with the same byte length as
the source. Store only `Pattern` and `Redacted:true`; the annotation sidecar,
not the wire model, retains exact raw identity until finish.

Any source that contributes to a vulnerability-specific sensitive interval is
also globally redacted for that event. Redaction wins when merging with an
existing source. The same bounded transaction upgrades the source model and all
previous value parts that reference its index; earlier occurrences are
conservatively fully redacted when an exact pattern slice is unavailable.
Analyzer failure, interval-cap fallback, and oversized-evidence fallback apply
the same source-upgrade rule. The scan is bounded by the 64-vulnerability and
513-part hard limits.

A redacted source occurrence is split into sensitive and non-sensitive pieces.
Because ranges do not carry source-relative offsets, mapping uses a bounded
unique-occurrence search of the evidence part bytes in the complete source
value. A unique exact match reuses the corresponding source-pattern slice. No
match, multiple matches, transformed/coarse provenance, or exhausted comparison
budget uses same-length `*` bytes. The complete report has a fixed one-megabyte
source-comparison work budget.

### 8.2 SQL literals

Promote the already licensed `github.com/DataDog/go-sqllexer` dependency from
indirect only if its scanner passes the normative corpus. Add dialect adapters
for every dialect represented by that corpus. The scanner input is capped at 32
KiB before analyzer execution. Oversized input keeps bounded taint segmentation,
source indexes, and secure marks, but marks every evidence interval and every
contributing source as redacted; it does not collapse provenance into one
source-less part. Scanner work and token count are bounded and must always make
forward progress. Malformed Oracle q-quotes,
comments, numeric literals, quoted identifiers, escape forms, and dialect
quotes are explicit fuzz seeds.

If go-sqllexer cannot pass, implement a bounded linear scanner only after a
separate corpus comparison. A broad fallback regex is not accepted.

### 8.3 Commands

Use a linear argv-aware redactor, not a shell regex or parser. Preserve only the
command prefix from section 4 and redact the remaining byte intervals. Before
any full scan or join, enforce 256 arguments and 32 KiB of cumulative bytes with
checked arithmetic. Exceeding either bound capacity-drops the report and emits no
raw evidence; it is not classified as clean and cannot become a false positive.
Repeated blank lines, huge clean prefixes, empty/one-byte argument floods, and
malformed text from the 2026 incident are regression tests.

## 9. Process de-duplication

Add a fixed process set of 1,000 vulnerability hashes plus a one-hour epoch.
Guard it with `TryLock`. Full capacity or expiry clears the complete set. Lock
contention skips de-duplication, not reporting, and records a bounded debug
signal. A process hash is inserted only after the event transaction commits, so
a capacity/source/annotation failure cannot suppress valid reports for one
hour. Concurrent identical commits can both report before either insertion;
this bounded best-effort duplicate is accepted. `DD_IAST_DEDUPLICATION_ENABLED=false`
bypasses the process set. Existing per-event dedup remains the final
transactional check.

## 10. Bounded location discovery

Keep `SkipFrame` for existing weak hash/cipher reporting. Add a bounded
`SkipWhile` namespace-prefix policy for tainted sinks. Always capture enough
frames to scan to a hard depth, even when stack reporting is disabled; that
setting controls recording, not location discovery. Extra frames are discarded
when disabled. If no application frame exists within the bound, emit a location
with span ID and no path/line rather than scanning farther.

Preserve per-vulnerability UUID stack IDs and current hashes. Add an annotation
lifecycle state protected by its lock. `Finished` atomically removes the
annotation from the weak store, takes the exclusive lock, marks it closed,
invalidates every owner binding, then snapshots/attaches the final event; no
later commit is accepted. A reporter that loaded the pointer before removal
serializes on the same lock: it either commits before closure or observes closed
and falls back. A reporter that looks up afterward finds no annotation and uses
an owner binding or fresh orphan; it cannot resurrect an annotation. A finish
with no annotation needs no tombstone because tainted reporting is lookup-only.
Deterministic tests cover first lookup racing finish and store trimming.

The complete trace, location, and UUID are prepared before publication.
Reporting obtains the open annotation with `TryLock`, verifies event/source
capacity and dedup, records the stack while the span is still protected from
`Finished`, installs `StackID` in the still-local location, and commits sources
and vulnerability before unlocking. The tracer stack-record call is the only
external call under this lock; its lock graph and no-callback behavior must be
audited with forced reentrancy/deadlock tests. A reporter holding the lock before
closure completes before `Finished` attaches the event. The published location
is never mutated. If the stack audit fails, add an explicit annotation
reservation protocol before proceeding.

## 11. Payload-size defense

Before span attachment, encode the actual candidate event on the selected path;
`Msgsize` is not accepted as a length. At 25,001 bytes or more, build a separate
truncated event while the annotation remains immutable: preserve type, hash,
and location; replace detailed evidence with the selected sentinel; omit
sources. Test msgpack and JSON at 24,999, 25,000, and 25,001 actual bytes. Set a
truncation indicator only if the Go tracer exposes the backend-approved tag.

The 32-KiB evidence cap protects analyzer CPU and secrets. The 25,000-byte event
cap protects wire payload size. They are independent. Add a non-configurable
hard maximum of 64 vulnerabilities per event and clamp the runtime setting to
it. Bound location path/class/method strings at the existing model truncation
limit. Re-encode the fallback; if it still exceeds 25,000 bytes, omit optional
location strings while preserving span ID, type, hash, and every vulnerability.
A compile-time/maximum-shape test proves the final degradation fits.

## 12. Telemetry

Build-time aspects increment `instrumented.sink` exactly for SQL injection and
command injection shapes. `executed.sink` increments for an enabled active sink
execution after the cheap gate, including a clean lookup miss. `executed.tainted`
increments only after unsafe taint is confirmed, before dedup/capacity handling.
Safe-marked, deduplicated, capacity-dropped, and accepted cases have explicit
counter tests. Suppressed findings, foreign-owner drops, source/event
capacity, process-dedup contention, analyzer cap/failure, and payload truncation
use only shared-spec metric names. Until a name is accepted, emit a rate-limited
debug log instead of inventing a metric.

## 13. Safety and fixed bounds

- No reporting path can panic through a host call.
- Ordinary locks use `TryLock`/`TryRLock`; cleanup can block.
- Standard-library bridges are safe before registration and cannot recurse.
- No numeric pointer is converted back to a Go pointer.
- Work is bounded by four owners, 256 collected ranges, 256 event sources, the
  configured vulnerability count, 1,000 process hashes, bounded stack depth,
  32-KiB analyzer input, and the 25,000-byte event limit.
- Under contention or capacity pressure, drop reporting data instead of
  blocking or changing the host result.

## 14. Validation

Unit/property/fuzz tests cover range ordering, gaps, overlap clipping,
multi-owner delivery, source dedup/index remap, marks, source-pattern slicing,
invalid UTF-8, running truncation budgets, redaction corpora, malformed SQL,
command incident regressions, de-dup expiry/clear/contention, `SkipWhile`, and
both payload encoders.

Woven fixtures cover every SQL receiver, context/non-context delegation,
`QueryRow*`, prepare and execute, repeated prepared statements, `driver.ErrBadConn`
retries, parameterized clean queries, tainted query strings, and exact source
locations. Command fixtures cover construction-only, validation failure,
failed/successful start, `Start`, `Run`, `Output`, `CombinedOutput`, side-effect
order, panic behavior, and argv evidence.

Golden tests cover redaction enabled/disabled, stack enabled/disabled, no span,
bound span, orphan span, foreign-owner finish races, process and event dedup,
msgpack, and JSON.

Run ordinary/woven suites, race, vet, checklocks, `GODEBUG=checkptr=2`, import
closure/cycle tests, retained-memory checks, and coverage/mutation feasibility.

Benchmarks use at least twenty one-second samples for disabled, no-active,
active-clean, and tainted SQL/command hooks, process dedup, segmentation,
redaction, and payload guards. Disabled and active-clean hooks add no allocation.
Use the approved four-nanosecond/5% local gates and rerun sampled-out HTTP before
the sink-enablement checkpoint.

## 15. Commit boundaries

1. `SkipWhile` and location refactor with no existing behavior change.
2. Fixed process dedup set.
3. Immutable report snapshots and pure evidence segmentation.
4. Transactional event source/vulnerability merge.
5. Source redaction plus accepted corpus fixtures.
6. Bounded SQL and command analyzers.
7. Pure, inactive payload-limit construction and boundary tests; do not wire it
   into existing span attachment before backend/user approval.
8. SQL bridge, aspects, and isolated woven fixtures.
9. Command bridge, aspect, and isolated woven fixtures.
10. Telemetry, README, goldens, and complete benchmarks.
11. User sink-enablement checkpoint, then `orchestrion.tool.go` registration,
    payload-guard activation, README enabled coverage, and Phase 7a exit record.

## 16. Implementation checkpoint evidence (2026-08-27)

Commit boundaries 1 through 10 are implemented with SQL and command aspects
kept out of the root `orchestrion.tool.go`. The shared cross-tracer corpus was
not available in public sources, Google Drive, or Jira. The user approved the
RFC-derived regression corpus provisionally; final enablement remains explicitly
conditioned on replacing or validating it against the normative corpus.

The isolated woven suites cover all eleven Go 1.26 SQL context methods, prepared
statements, delegation, retries, canceled results, driver panics, the one command
process-attempt boundary, process errors, construction and validation failures,
nil-context owner fallback, analyzer limits, and source locations. Semantic
wire goldens encode and decode accepted SQL and command events through both JSON
and msgpack, require equivalent models, and reject raw tainted evidence in both
encodings. Actual payload-limit boundaries remain covered at 24,999, 25,000,
and 25,001 bytes for both encodings.

Twenty one-second sample medians on Apple M1 Max:

Benchmark | Control | Woven/active | Delta | Allocations
---|---:|---:|---:|---:
Prepared `Stmt.ExecContext`, inactive | 214.40 ns | 216.15 ns | +0.82% | 3 / 3
Failed process start, inactive | 1.186 ms | 1.151 ms | -2.99% | 28 / 28
SQL bridge, inactive | — | 2.37 ns | — | 0
Command bridge, inactive | — | 2.19 ns | — | 0
SQL report, active clean | — | 17.33 ns | — | 0
Command report, active clean | — | 28.63 ns | — | 0

The active meta-structure path performs one bounded msgpack encoding to enforce
the exact limit and the tracer later encodes the immutable event again at flush.
No tracer API accepts pre-encoded meta-structure bytes, so this bounded
finding-only completion cost is currently unavoidable.

Standard-library archives link only dependency-minimal bridge packages. Heavy
sink callback registration is injected into the root executable's `main`
function; linking it from `database/sql` or `os/exec` caused Orchestrion
synthetic test-variant cycles. Isolated executable builds verify that each sink
`init` task is retained without an explicit source import.

The source IIFE initially exposed a false `noescape` optimization opportunity.
That assertion was removed after review; the host `os.StartProcess` call remains
directly visible to the compiler and allocation parity is restored. The
command location policy uses a cumulative two-frame compiler-gap budget and
re-indexes the retained application frame to zero.

The Phase 5 sampled-out HTTP result remains +1.81% median with a +3.93%
bootstrap upper bound, which the user explicitly accepted. Sink aspects do not
run on the benchmark request path and remain unregistered in the aggregate tool.

At the enablement checkpoint, the user approved activation with assumptions.
The root tool now registers both sink packages and span attachment enforces the
actual-encoding payload guard. This approval explicitly carries the provisional
RFC-derived corpus and assumes backend acceptance of `MAX_SIZE_EXCEEDED` and
the 25,000-byte limit. The normative corpus and backend system fixture remain
mandatory Phase 9 general-availability gates rather than Phase 7a blockers.

## 17. Stop conditions

Stop for user review if the shared redaction corpus is unavailable or fails; a
bridge dependency reaches its instrumented standard package; a host value,
error, panic, or evaluation count changes; a source index cannot be committed
transactionally; foreign-owner evidence cannot be fully copied; SQL/command
location hashes are unstable; any analyzer is not linear/bounded; backend event
limit or sentinel compatibility remains unresolved at enablement; or local and
sampled-out performance is unacceptable.
