# fx-perf-contention-F1: request admission contention

## Verdict per finding

**perf-contention-F1: REFUTED as a High correctness defect; the underlying
contention loss is reproduced. Adjusted severity: Info.**

HEAD checked: `2e23b4614320defd0d32177a69888dcab73f4d11`.
`Store.Acquire` really rejects a request after permit acquisition when another
caller holds `ownerMu`, even with unused owners. However, the approved design
explicitly allows store-contention losses, separately from exhausted capacity.
This is not evidence of a violation of the supported, admitted-request
provenance contract. The review brief excludes documented deliberate
limitations unless a separate product-rule violation is established.

The finder also calls the max-two benchmark "default config" despite explicitly
setting sampling to **100%**, rather than the default **30%**
(`.omo/review/evidence/perf-contention/request_zz_perf_contention_test.go:47-50`). Its
15-41% and 39-70% figures are workload observations, not default customer loss
guarantees. No wall-clock benchmark was used for this verification.

Only one finding was supplied; there are no duplicates to merge.

## Reproduction

All execution used the private copy
`/tmp/ddiast-review/wt/fx-perf-contention-F1`; production code was unchanged.
Evidence is under `.omo/review/evidence/fx-perf-contention-F1/`.

Independent artifacts:

- `zz_review_admission_test.go`: deterministic store-level refusal with **one
  live owner and 63 unused owners**, followed by successful admission after
  unlocking. The lock is explicitly held by the test to model an acquisition
  in progress; this test alone does not establish natural collision rates.
- `main.go`: finite observation harness using the real `request.Begin`/`Finish`
  API, plus a woven `http.Handler` fallback mode that never calls admission or
  source APIs itself. A serial control precedes two workers, with default
  enabled/sampling/max values asserted. No lock manipulation, sleeps,
  retry-until-success loops, or production-code changes. Exactly two workers
  means that the entering worker can have at most one other request occupying
  a permit; every `DecisionCapacityDropped` is checked against the store
  acquisition counter.

Restore these files in a fresh private copy as
`internal/taint/store/zz_review_admission_test.go` and
`reviewadmission/main.go`, respectively, then:

```sh
cd /tmp/ddiast-review/wt/fx-perf-contention-F1
export GOFLAGS=-p=4 GOMAXPROCS=2 GOTOOLCHAIN=go1.26.6
timeout 300 go test -timeout 2m -count=1 \
  -run TestReviewAdmissionBusyStoreWithSpareOwners -v ./internal/taint/store
timeout 300 go run ./reviewadmission -surface=api
/usr/bin/time -l timeout 600 go tool orchestrion go run \
  ./reviewadmission -surface=http
```

Captured output, all three commands exit 0:

```text
active_before=1 free_before=63 rejected_while_busy=true drops=1 admitted_after_unlock=true
go=go1.26.6 procs=2 woven=false surface=api enabled=true sampling=30 max=2
workers=1 requests=50000 sampled_out=34960 active=15040 capacity_dropped=0 store_acquire_drops=0
workers=2 requests=100000 sampled_out=70143 active=25981 capacity_dropped=3876 store_acquire_drops=3876 lost_of_sampled=0.1298
```

The last two lines are excerpts; complete output is in `api-go126.txt`.
Every batch reported `remaining_active=false`, so the observed failure
released its permit rather than permanently disabling IAST.
`mechanism-go126.txt` contains the passing deterministic check.

The woven command produced (`woven-go126.txt`, excerpt):

```text
go=go1.26.6 procs=2 woven=true surface=http enabled=true sampling=30 max=2
workers=1 requests=50000 sampled_out=34895 active=15105 capacity_dropped=0 store_acquire_drops=0
workers=2 requests=100000 sampled_out=70195 active=27421 capacity_dropped=2384 store_acquire_drops=2384 lost_of_sampled=0.0800 active_query_tainted=27416 dropped_query_tainted=0 remaining_active=false
```

This is real woven application-handler/source advice, driven directly with
HTTP request objects, not a network load test. All 2,384 dropped scopes lacked
query taint. The five additional active-handler misses are not attributed to
admission and are excluded from that count. The reported maximum RSS was
355,024,896 bytes. Tracer warnings report no local Datadog Agent; backend
report delivery was not asserted.

Repeating the two run commands with `GOTOOLCHAIN=go1.27.0` gave:

- Plain API: exit 0, serial zero drops; two workers
  `active=26057 capacity_dropped=3852 store_acquire_drops=3852`,
  `lost_of_sampled=0.1288`, no remaining active analysis (`api-go127.txt`).
- Woven: exit 1 before execution, with `dec.r undefined` and `dec.d undefined`
  in generated `encoding/json` advice (`woven-go127.txt`). This independently
  encounters the pre-existing `base-test-127-F1` compatibility blocker, not an
  admission failure. Reported maximum RSS: 272,285,696 bytes.

Rates above are finite-run observations, not customer-rate estimates. Both
reproducer sources passed LSP diagnostics and `gofmt -d`.

## Reachability

**Reachable with defaults: yes. Documented limitation: yes.**
Defaults are enabled, 30% sampling, two concurrent analyses
(`internal/config/config.go:75-77`, `README.md:114-116`).
The real HTTP path reaches the same admission code through
`iast/net/http/orchestrion.yml:16-45,82-122`,
`request.BeginServerContext`/`BeginContext`, and `request.begin`.
An unadmitted scope does not taint HTTP fields
(`internal/taint/request/http.go:64-67`).

The controlling policy is explicit:

- `_docs/plans/taint-tracking-net-http-sqli-cmdi.md:21`: pressure **or
  contention** drops IAST data rather than blocking.
- The same plan's acceptance criterion at `:1107`: store contention and
  capacity pressure drop data without unbounded waiting.
- `.omo/review/phase1/01-design-intent.md:29-32`: host-safety priorities permit
  dropping provenance rather than blocking.
- `internal/taint/store/owner.go:8-9,18-19`: the API documents disabled handles
  for acquisition contention and nonblocking acquisition.

README does not explain this specific mutex, but the design documents do
cover this behavior. Free storage does not establish an unconditional promise
to admit every sampled request. No host failure, incorrect source identity,
leaked permit, or memory-bound violation was demonstrated. The admission
behavior therefore does not override the documented trade-off. Go 1.26.6
customer reachability is exercised; Go 1.27.0 API reachability is exercised,
but its woven path cannot be evaluated past the separate compile blocker.

## Adjusted severity

**Info, down from High:** observable loss at a documented nonblocking admission
boundary, without an independently demonstrated violation of a product rule.

`AcquireDrops()` has no production caller at this HEAD, so missing external
visibility is real. It is a useful observability improvement, not proof that
the documented admission-loss policy is a High false-negative defect.

## Root cause (file:line)

- `internal/taint/store/owner.go:24-28`: `ownerMu.TryLock` failure increments
  `acquireDrops` and returns a disabled handle before inspecting owner capacity.
- `:29-60`: owner selection and writer-state clearing occur under that lock.
  The mutex is per store; the production singleton makes it process-wide.
- `internal/taint/request/owner.go:65-86`: the permit is acquired first, then
  released if store acquisition fails.
- `internal/taint/request/scope.go:94-98`: this failure becomes
  `DecisionCapacityDropped`, not an active analysis.

The finder is incorrect that the permit CAS "already serializes admission":
it assigns distinct permit bits; it does not serialize owner initialization.

## Minimal fix

No correctness fix is required by the accepted contention-loss contract.
If reducing admission loss is desired, claim each free owner with a CAS into
an **initializing** state, initialize it exclusively, then publish `stateActive`.
Do not simply CAS directly to active before resetting generation/state: that
would let a stale handle observe a partially reinitialized owner. Alternatively,
a manager-specific owner reservation can exploit its unique permit, but must
preserve the existing direct-store/shared-manager contract.
Export the bounded acquisition-loss counter to permitted telemetry or a
rate-limited debug log, and clarify that sampling is eligibility rather than
guaranteed analysis. These are proposals, not changes made during verification.
