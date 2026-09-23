# fx-life-weak-gc-F2: post-finish child binding

Scope covered: `internal/spans/{annotation,orchestrion,owner,tainted}.go`,
`internal/vulnerability/{tainted,report}.go`, request-scope lifetime,
`iast/net/http` and weak-crypto weaving, the pinned dd-trace-go span lifecycle,
README, and `phase1/01-design-intent.md`.

## Verdict per finding

### life-weak-gc-F2: CONFIRMED

The core mechanism is real. `Finished` removes the association using the exact
receiver pointer, while annotations are stored under `span.Root()`. Once a root
has finished, a child started from a retained request context still resolves to
that root. `BindScope` therefore inserts a fresh root-keyed annotation. Finishing
the child looks up the child pointer, not the root key, so it does not close or
remove that new annotation.

The finding needs two qualifications:

* The ordinary post-handler path creates an unsampled annotation because the
  scope is already inactive. It still occupies a slot and can deny a later
  active request, but cannot itself accept `ReportTainted`.
* The weak-crypto aspects are **not** an F2 trigger: they pass `nil` context,
  so `vulnerability.Report` creates an orphan span rather than reusing a
  retained request context. A committed-but-unflushable finding requires the
  narrower window where root finish precedes scope finish.

## Reproduction

Independent test: `.omo/review/evidence/fx-life-weak-gc-F2/review_fx_late_bind_test.go`.
It starts a root under an active scope, finishes that root, then starts children
from the retained request context.

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -count=1 -timeout 12m \
  -run 'TestReviewFXLate' -v ./internal/spans/
GOFLAGS=-p=4 go test -count=1 -timeout 12m \
  -run 'TestReviewFXLate' -v ./internal/spans/
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l \
  go tool orchestrion go test -count=1 -timeout 12m \
  -run '^TestReviewFXLateBindCannotCommitToFinishedRoot$' -v ./internal/spans/
```

Both plain runs failed on Go 1.26.6 and Go 1.27.0 with:

```text
BUG: late child spans recreated 2 annotation slot(s) for finished roots
BUG: stale late-child annotations denied a later active request
BUG: finishing late children left 2 finished-root annotation slot(s)
BUG: a late child committed a vulnerability into an open annotation whose root had already finished
```

The focused woven Go 1.26.6 run reproduces the final line through the actual
`Span.Finish` hook. Captured logs are `plain-go1266.log`, `plain-go1270.log`,
and `woven-go1266.log` in the same evidence directory; woven peak RSS was
350,371,840 bytes.

## Reachability

Reachable under default configuration. The `tracer.StartSpanFromContext` call
site advice invokes `iast/net/http.BindStartSpan` whenever the resulting context
has a request scope (`iast/net/http/orchestrion.yml:50-75`,
`iast/net/http/http.go:21-26`). Ordinary application code can retain a request
context in a goroutine after the handler returns and start a traced child there.
The default annotation capacity is two (`internal/config/config.go:74`).

This is not a documented limitation in README or
`.omo/review/phase1/01-design-intent.md`. It violates the provenance rule on a
supported traced-child path and can make later admitted analyses silently lose
findings. The stale entry is eventually reclaimable after the root becomes
unreachable and trimming runs, so this is not an unbounded-memory leak.

## Adjusted severity

**High (unchanged).** Two reachable retained contexts can fill the shipped
two-slot annotation budget and produce false-negative reporting for otherwise
admitted requests; the active-scope ordering window additionally accepts a
finding with no remaining flush target.

## Root cause

`internal/spans/orchestrion.go:28` deletes only `weak.Make(span)`.
`internal/spans/annotation.go:123-128` and `:186-212` normalize associations to
`span.Root()` and recreate them after absence. `internal/spans/orchestrion.go`
then receives a child at finish and cannot delete the root-keyed late entry.
`trimStore` (`annotation.go:227-236`) counts that live-key entry against
`MaxConcurrentRequests`. The owner binding permits the active-scope commit
until `scope.Finish`.

## Minimal fix

Do not create annotations for inactive scopes. For the still-active ordering
window, retain a closed root association (or equivalent bounded lifecycle
marker) until matching scope cleanup, and make `BindScope` reject it rather
than replacing it. Scope cleanup must remove that marker, and closed markers
must not consume the bounded live-annotation admission budget. This prevents
both resurrection after root finish and unbounded marker retention.
