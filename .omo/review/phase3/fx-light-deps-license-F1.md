# fx-light-deps-license-F1: temporary Orchestrion revision

Reviewed at HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`
on September 23, 2026. Evidence is under
`.omo/review/evidence/fx-light-deps-license-F1/`.

## Verdict per finding

**light-deps-license-F1: CONFIRMED, with a narrower interpretation.**
`go.mod:14` pins Orchestrion
`v1.12.2-0.20260828141217-23afa71d6dcb`. The pinned commit is on
`origin/romain.marcadier/iast-operator-join-points`, not `origin/main`,
and no checked local tag contains it. Live remote refs corroborated those
branch tips on the review date. The phase-6 plan explicitly requires moving
to the first published Orchestrion release containing these join points
*before general availability*. Thus there is a real, already-tracked GA
prerequisite, not a newly discovered dependency-resolution failure.

## Reproduction

The independent reproducer resolves the revision from the **private**
module rather than copying the finder's hash:

```sh
cd /tmp/ddiast-review/wt/fx-light-deps-license-F1
pin=$(GOWORK=off GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go list -m -f '{{.Version}}' github.com/DataDog/orchestrion)
rev=${pin##*-}
git -C /Users/eliott.bouhana/go/src/github.com/DataDog/orchestrion rev-parse "$rev"
git -C /Users/eliott.bouhana/go/src/github.com/DataDog/orchestrion merge-base --is-ancestor "$rev" origin/main
```

Captured: `private_version=v1.12.2-0.20260828141217-23afa71d6dcb`;
`resolved_revision=23afa71d6dcb13cc221c6461745229779e7674b4`;
`on_origin_main=no exit=1`. The only containing remote-tracking branch
was `origin/romain.marcadier/iast-operator-join-points`. Full commands,
live ref outputs and captured results: `provenance.txt`.

The independent customer-shaped reproducer `reviewpin.go` concatenates
two runtime arguments and prints Orchestrion's woven-build flag. Copied to
the private module as `reviewpin/main.go`, it was exercised with:

```sh
cd /tmp/ddiast-review/wt/fx-light-deps-license-F1
GOWORK=off GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l go tool orchestrion go build -o ./reviewpin/reviewpin ./reviewpin
./reviewpin/reviewpin left right
go version -m ./reviewpin/reviewpin
```

The command exited **0**; output included `woven=true concat=leftright`,
and the binary listed the pinned Orchestrion pseudo-version. Peak build
RSS was **434,208,768 bytes**, below 4 GB. See `woven-build.txt`.

## Reachability

Ordinary woven builds of this module use the pin, but the claimed
release prerequisite is not a customer-triggered failure under the
documented supported Go 1.26.6 toolchain and default configuration.
The parent plan at `_docs/plans/taint-tracking-net-http-sqli-cmdi.md:845-862`
and phase-6 plan at
`_docs/plans/taint-tracking-net-http-sqli-cmdi-phase-6.md:82-90,369-372`
document the temporary pin and pre-GA replacement. This does not
violate a host safety or taint-provenance product rule.

I also tried Go 1.27.0. The woven build exited **1** with
`dec.r undefined` and `dec.d undefined` from
`iast/encoding/json/orchestrion.yml:38-43`. That is a separate
Go-version-specific JSON advice failure, not evidence that the topic-branch
pin cannot resolve or that its ancestry breaks the supported Go 1.26.6
build. The plan targets exactly Go 1.26.6; the Go 1.27.0 failure is
recorded in `woven-build.txt` for separate compatibility review.

## Adjusted severity

**Info** (original: High): documented external GA release prerequisite,
with no observed failure on the supported toolchain. If the release were
attempted before the upstream APIs were published, the stated GA policy
would require delaying it; the finding does not meet the brief's High
runtime/provenance or customer-breakage criteria.

## Root cause (file:line)

`go.mod:14` deliberately selects the reviewed upstream join-point
revision while Orchestrion PR #881 remains outside `main`; the
pre-GA release policy is in the phase-6 plan at lines 82-90. The same
version is repeated in the overhead and three nested test-app modules.
There is one finding, so there are no duplicates to merge.

## Minimal fix

Once upstream merges and publishes a version containing the required
join points, replace this pseudo-version consistently in the root,
benchmark, and nested test-app modules, regenerate the Orchestrion tool
pin, and rerun the supported woven builds. Do not substitute an older
release that lacks those APIs merely to remove the branch pin.
