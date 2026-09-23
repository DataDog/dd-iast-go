# fx-store-stress-F2: stale full shard cannot recover

Verdict: **CONFIRMED.** `putWindow` can convert every stale slot in a full
shard to tombstones without finding a zero slot; because compaction is called
only by successful insertion, that shard can never insert or compact again.

Scope covered: `internal/taint/store/{value,owner,root,store,limits}.go`,
`internal/taint/{request,propagation}/`, README, design intent, and the
finder's stress reproducer.

## Verdict per finding

### store-stress-F2: CONFIRMED

The mechanism is real at HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.
`putWindow` (`internal/taint/store/value.go:147-193`) marks encountered stale
entries as `tombstone`; if the 64-slot probe sees no zero, it deliberately
refuses the remembered tombstone and returns `false` to avoid a duplicate.
`compact` is only reached after `insertWindow` succeeds
(`internal/taint/store/value.go:225`). A shard containing no zero can therefore
neither insert nor invoke compaction. Once every old owner is finished, all
128 physical slots can be tombstones forever.

There are no duplicate findings in this assignment.

## Reproduction

I copied and ran the finder reproducer in the private copy:

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 \
  go test -timeout 10m -run '^TestReviewShardWedgeAfterOwnerFinish$' \
  -count=1 -v ./internal/taint/store
```

It failed as intended: three later owners had `shard-0 derives ok=0`,
`shard-0 TaintString ok=0/50`, `live=0 tomb=128 empty=0`, and
`compactions=0->0`. Captured output:
`.omo/review/evidence/fx-store-stress-F2/finder-go1.26.6.out.txt`.

My independent reproducer uses only `TaintBytes` and `Derive`; it does not
write shard slots directly. It fills all initial slots from one managed root,
finishes that owner, then attempts windows from a new root at initial slots 0,
64, and 32:

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 \
  go test -timeout 10m -run '^TestIndependentShardWedge$' \
  -count=1 -v ./internal/taint/store
```

Key output was `accepted=[false false false]; shard0 live=0 tombstones=128
empty=0 compactions=0`; the expected failing test proves the persistent safe
miss. It also reproduced unchanged under the default Go 1.27.0 toolchain.
The test and captured outputs are
`.omo/review/evidence/fx-store-stress-F2/wedge_independent_test.go`,
`independent-go1.26.6.out.txt`, and `independent-go1.27.0.out.txt`.

## Reachability

The triggering operations are supported store behavior behind woven direct
string/byte windows (`internal/taint/propagation/propagation.go:61-105`), and
one active request has enough documented value capacity to create the 128
entries. No non-default configuration or unsupported Go version is required:
the README defaults still admit two concurrent sampled analyses.

The saturation condition is collision-heavy, not an ordinary low-volume
request. My 1,500-step rolling stress run at the default two-owner concurrency
reached 116/128 but did not fill a shard; a four-owner run reached 126/128.
Thus this is reachable through supported customer workloads, but unlikely
without unusually dense/selected derived windows. It is not a documented
limitation: README/design docs allow bounded temporary drops under pressure,
not permanent loss after owners finish. It still violates accurate provenance
once triggered.

## Adjusted severity

**High** (unchanged): a supported-path false negative permanently disables
tracking for all later identities assigned to the wedged shard, until process
restart, even though creating the full shard is collision-heavy.

## Root cause

`internal/taint/store/value.go:164-172` converts reclaimable stale entries to
tombstones. `value.go:188-193` rejects the exhausted probe window without
reusing one. `value.go:224-227` calls `compact` only after successful insertion,
which cannot happen once there is no zero slot.

## Minimal fix

When the probe window is exhausted and `shard.tombstones > 0`, call
`compact(shard)` while holding `shard.mu`, then retry the probe once. The retry
must be bounded; after compaction still cannot create a duplicate because it
re-executes the existing full probe against the compacted table. This restores
zero slots when the full shard was stale without evicting live entries.
