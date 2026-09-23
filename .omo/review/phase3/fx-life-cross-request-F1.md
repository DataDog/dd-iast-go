# fx-life-cross-request-F1: verification of life-cross-request-F1

## Verdict per finding
- **life-cross-request-F1: CONFIRMED.** Suppose request A adopts an `io.ReadAll` body without copying it and then recycles that slice while A is still active. A concurrent request B that refills the slice to the same length with (unhooked) `append` and converts it with `string()` receives A's `http.request.body` provenance. B's span then reports SQL_INJECTION for a query that the server built entirely from constants and an integer. The mechanism is exactly as claimed, and it is deterministic: no GC or timing luck is involved, because A's root anchor keeps the address pinned.

## Reproduction
My own reproducer (independent of the finder's harness) is `.omo/review/evidence/fx-life-cross-request-F1/zz_fx_f1_{app,test}.go`. All application logic sits in the woven root package, the way a customer handler would. The pool is a deterministic capacity-1 channel free list, not `sync.Pool`, and needs no GOMAXPROCS tricks. B builds its query with `append(buf, "SELECT name FROM users WHERE id="...)` plus `strconv.AppendInt(buf, 4242, 10)`, then `query := string(buf)` and `db.ExecContext`. A's body is the 36-byte `{"name":"x' UNION SELECT pass--"}   `.

```
cd iast/integration/testapp && GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 \
  /usr/bin/time -l go tool orchestrion go test -count=3 -timeout 15m -run TestFxF1 -v .
```
Key output (`run-go1.26.6-count3.log`, identical on all 3 iterations, peak RSS 369 MB):
```
A: body ptr=0x1629bbb96c00 tainted=true
B: buf ptr=0x1629bbb96c00 sameBacking=true query="SELECT name FROM users WHERE id=4242" tainted=true
span fx.B: enabled=1 json={"sources":[{"origin":"http.request.body","pattern":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ","redacted":true}],
  "vulnerabilities":[{"type":"SQL_INJECTION",...,"location":{...zz_fx_f1_app.go","line":58,"method":"...FxLookup"...}}]}
CONFIRMED CROSS-REQUEST BLEED: clean server-built query "SELECT name FROM users WHERE id=4242" in request B reported with A's body as source
concurrent-different-length: query="SELECT name FROM users WHERE id=42" tainted=false   (control: clean)
sequential-A-finished:       query="...id=4242" tainted=false                          (control: clean)
```
B's source is A's 36-byte body. Its value is redacted here only because the SQL analyzer marks the numeric literal sensitive. In the finder's harness the raw attacker value appears unredacted in B's span.

Cross-check: I re-ran the finder's `TestReviewPooledReadAllSliceAcrossRequests` (`finder-R1-rerun-go1.26.6.log`). `concurrent-same-length` FAILS with `B: query="SELECT id FROM customers" tainted=true ranges=[[0,+24) origin=http.request.body ... value="x' OR '1'='1' --comment!"]`, and both controls pass.

Go 1.27.0: the woven integration testapp does not build (`encoding/json/<generated>: dec.r undefined`, `run-go1.27.0-buildfail.log`). This is the known, unrelated JSON-weaving break. The code path involved (store key identity, `Lookup`, `BytesToString`) contains nothing toolchain-specific.

## Reachability
- **Default configuration, supported surface:** `io.ReadAll` on a request body (a supported owned-result source path), a declaration-context `string(buf)` conversion (supported: "allocation-preserving `[]byte`-to-`string` assignments, declarations"), and a `database/sql` sink. `append`/`strconv.AppendInt` are ordinary code. Nothing needs to be enabled beyond IAST itself.
- **Preconditions (narrowing):**
  1. The application recycles the exact `io.ReadAll` result slice (or an alias at its base) into a pool or free list.
  2. B reuses it while A's analysis is still active.
  3. B's refilled length equals the length of a window A registered at that base address. In practice this means the full body length. Prefix windows that A sliced from the body would widen this, but that follows from static reasoning only and I did not reproduce it.
  4. B converts the slice with a wrapped conversion.

  Recycling `io.ReadAll` results is less common than pooling `bytes.Buffer`, but it is legitimate, and fixed-width payloads make equal lengths plausible under concurrency. Both requests must be sampled (100% in the harness). With default sampling the probability drops, but a sampled A plus a sampled B is enough.
- **Documented?** Partly. README:43-46 says `append`/`copy` writes "through mutable aliases retained before tracking, or across later tracking, are not observed and can leave stale ranges". 01-design-intent:22-27 says a sink "can report taint from another *active* owner". Neither document says that stale byte provenance can be attributed to a *different request/user*. The combination violates product rule 4 ("no cross-request taint bleed"), so the documentation does not excuse it.

## Adjusted severity
**High (unchanged).** This is a false-positive SQL_INJECTION on B's span whose source is another request's body, on supported source, conversion and sink paths. It is deterministic once the preconditions hold. It sits at the low end of High because it needs an application pool that recycles an `io.ReadAll` result, plus an exact length match while A is live.

## Root cause (file:line)
- `internal/taint/request/reader.go:67-88,119`: `ReadAllBytes` → `adoptBodyBytes` → `owner.AdoptSourceBytes(data, ...)` publishes the *application-owned, mutable* slice itself as a root.
- `internal/taint/store/root.go:209-221`: the root is keyed by `BytesKey(value)` = (data pointer, len, KindBytes), anchored (`publishRoot(..., value, ...)`), with no record of the content.
- `internal/taint/store/lookup.go:125,152,162`: a hit needs only pointer/len/kind equality plus an *active* owner generation and a matching root generation. Nothing checks that the bytes are unchanged, and nothing checks that the looking-up request is the owner. `append`/`copy` never bump the root generation (`PublishBytesMutation`/`claimMutation` in `store/mutation.go:25-98` run only on hooked mutations).
- `internal/taint/propagation/conversion.go:23-45`: `BytesToString` adopts the new string into *every* owner returned by the snapshot, here A's. The sink then reports it on B's span as a foreign-owner contribution.

## Minimal fix
When a `KindBytes` root is published (`AdoptSourceBytes`, `AdoptBytes`, `PublishBytesMutation`), record a 64-bit content fingerprint of the published bytes (at most 64 KiB, already anchored). Record it per window as well, or recompute it over the root's `[rootOff, rootOff+len)` range. In `Store.Lookup`, for `key.Kind == KindBytes` only, recompute the fingerprint under `rootsMu` and skip the entry on a mismatch. Ideally also claim a new root generation so that later lookups are invalidated cheaply. Strings are immutable and keep the current fast path. The cost is O(len) only after a `MayContain` hit on a byte key. A weaker stop-gap is to reject foreign-owner contributions from mutable byte roots in `BytesToString`/at sinks, and to document the interaction in the README. That removes cross-user attribution but keeps same-request stale ranges.
