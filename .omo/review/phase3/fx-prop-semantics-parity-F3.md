# Independent verification: strings.Map deletion provenance

## Verdict per finding

**`prop-semantics-parity-F3`: CONFIRMED.**

Independently checked HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.
The newly written reproducer obtains taint from a woven HTTP handler's header,
joins it between clean SQL fragments, deletes every tainted rune with a direct
`strings.Map` call, and executes the resulting constant SQL through woven
`database/sql.ExecContext`. The sink commits one `SQL_INJECTION` vulnerability
whose source is the entirely deleted header. This proves more than collection
status alone.

Only one finding was submitted; there is no duplicate pair to consolidate.
No production code was changed.

## Reproduction

Independent source: `.omo/review/evidence/fx-prop-semantics-parity-F3/main.go`.
The finder's reproducer was not used.

Recreate the private copy and install the retained reproducer:

```sh
R=/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go
W=/tmp/ddiast-review/wt/fx-prop-semantics-parity-F3
mkdir -p /tmp/ddiast-review/wt
rsync -a --exclude .git --exclude .omo "$R/" "$W/"
mkdir -p "$W/cmd/f3verify"
cp "$R/.omo/review/evidence/fx-prop-semantics-parity-F3/main.go" \
  "$W/cmd/f3verify/main.go"
cd "$W"
/usr/bin/time -l env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 \
  DD_IAST_REQUEST_SAMPLING=100 \
  go tool orchestrion go run ./cmd/f3verify
```

Commands were bounded by 600-second monitor deadlines and run serially.
The Go 1.26.6 woven command exits **1**, intentionally failing the assertion
that deleted-source provenance must be absent. Captured output:
`.omo/review/evidence/fx-prop-semantics-parity-F3/woven-go1.26.6.out.txt`.

```text
runtime=go1.26.6 woven=true enabled=true sampling=100 redaction=true dedup=true
input_range=[7,11) source="X-Discard" value="~~~~"
mapped="SELECT 42" calls=13 native_calls=13 empty="" empty_tainted=false
control=literal tainted=false sql_collection=0
control=native_map tainted=false sql_collection=0
control=exact_replace tainted=false sql_collection=0
mapped_range=[0,9) source="X-Discard" value="~~~~"
mapped_tainted=true sql_collection=1 control_reports=0 map_reports=1
REGRESSION: strings.Map retained deleted-source provenance on constant SQL
```

The log also contains the actual event: type `SQL_INJECTION`, source origin
`http.request.header`, name `X-Discard`, and a redacted nine-byte evidence part
referencing that source. All four SQL calls reach the in-memory driver with
exactly `SELECT 42`. The driver supplies only the database interface; it does
not call IAST or synthesize reports. Tracer agent-connection warnings do not
prevent the local event commit; backend ingestion was not tested.

The input interval check excludes a source/join setup error. Literal SQL, a
native function-value `Map` call, and exact `ReplaceAll` are clean controls.
The empty-result control is clean, and native/woven callback counts are equal.

The same program without weaving passes, exit **0**:

```sh
env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 DD_IAST_REQUEST_SAMPLING=100 \
  go run ./cmd/f3verify
```

Its retained log, `plain-go1.26.6.out.txt` in the same evidence directory, ends:

```text
mapped_tainted=false sql_collection=0 control_reports=0 map_reports=0
PASS: constant SQL has no deleted-source provenance
```

The Go 1.27.0 attempt uses the woven command above with
`GOTOOLCHAIN=go1.27.0`. It fails before running the program because the existing
JSON advice targets absent `Decoder` fields:

```text
dec.r undefined (type *Decoder has no field or method r)
dec.d undefined (type *Decoder has no field or method d)
```

See `woven-go1.27.0.out.txt`. This is the separately recorded
`base-test-127-F1` compatibility blocker, not evidence against F3. Runtime
verification here is limited to Go 1.26.6. The pinned woven run's
`/usr/bin/time -l` maximum RSS was 376,619,008 bytes, below the brief's 4-GB
reporting threshold.

## Reachability

**Reachable under default configuration on sampled requests.** The handler,
direct `strings.Join`/`strings.Map`, and `DB.ExecContext` are ordinary supported
application calls. Source creation, propagation, SQL registration, and sink
callbacks are woven; the program does not manually taint values or invoke
propagation/reporting wrappers.

The reproducer dispatches an `http.HandlerFunc` through the supported
application-handler fallback (`iast/net/http/orchestrion.yml:82-122`).
It uses only inspection APIs to observe ranges and the committed span event.
Sink registration comes from executable-main advice
(`iast/database/sql/orchestrion.yml:16-31`).

IAST defaults to enabled, 30% sampling, two concurrent requests, and enabled
redaction/deduplication (`internal/config/config.go:74-85`). Only sampling is
set to 100% to remove randomness from the reproducer. Default 30% sampling
admits the same active path (`internal/taint/request/scope.go:86-103,148-158`);
no capacity, range, mark, or redaction override is needed.

**Documented limitation: yes.** README's propagation matrix advertises `Map`.
The approved Phase 5 plan, `_docs/plans/taint-tracking-net-http-sqli-cmdi-phase-5.md:59-68`,
explicitly categorizes it as coarse; phase 1's design-intent report likewise
describes whole-result ranges and the first contributing source.

This report challenges that trade-off only where it violates product rule 4:
the only tainted interval contributes **zero output bytes**, yet its source
is assigned to clean SQL and produces a vulnerability. Widening an actual
contribution and retaining a completely deleted source are materially different
accuracy outcomes. This is not merely missing sanitizer support.

## Adjusted severity

**High, unchanged:** independently reproduced false provenance and a committed
false-positive vulnerability on a supported direct-call path, matching the
brief's High definition despite the documented coarsening trade-off.

No host-result change, actual SQL exploit, or sensitive-data disclosure is
claimed.

## Root cause (file:line)

- `iast/propagation/orchestrion.yml:688-695` replaces direct application
  `strings.Map` calls with `StringsMap`.
- `iast/propagation/coarse.go:34-35` passes the native result and the **entire
  original input** to `CoarseString`; callback emission information is lost.
  These are the corrected HEAD lines for the finder's `36-38` citation.
- `internal/taint/propagation/propagation.go:326-337,363-394` takes the
  nonalias path and accumulates input ranges without testing whether their
  runes survived. At `402-418`, it clones the clean result and publishes a
  range covering its entire length with that input source.
- `iast/database/sql/sql.go:34-48` accepts the resulting unsafe snapshot and
  reports it. The sink cannot recover the discarded transformation history.

The behavior is therefore in Map's use of coarse propagation, not in HTTP
source attribution, joining, SQL execution, or evidence redaction.

## Minimal fix

Give `StringsMap` a Map-specific propagation path that records input-byte to
output-byte contributions during the **single native callback traversal**.
Ignore negative mapping results when accumulating source contributions;
publish nothing when no tainted rune survives. Prefer bounded exact output
ranges; any retained coarse fallback must select only surviving sources and
intersect only their marks.

Keep the active/possible-hit gate, fixed range/owner limits, native result,
callback order/count, panic behavior, and UTF-8 byte-width handling. Do not
re-run the application callback to reconstruct ranges. Retain this regression,
the exact-replacement/native controls, and a surviving-taint positive control
when implementing the fix.
