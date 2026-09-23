# fx-perf-hotpath-F1: inactive lazy-iterator allocation

## Verdict per finding

**perf-hotpath-F1: CONFIRMED. Adjusted severity: Medium (original: High).**

At HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`, all five sequence
wrappers construct an extra capturing closure before checking taint activity.
An independent woven application fixture reproduces **+32 bytes
and +1 allocation per escaping iterator**, including `strings.SplitSeq`,
with default configuration and no active request owner.

Only one finding was supplied. The five affected constructors share
`stringWindowSeq`; they are manifestations of one root cause, not five issues.

## Reproduction

All evidence is in `.omo/review/evidence/fx-perf-hotpath-F1/`.
The independent sources are `sequence.go` and `sequence_test.go`. They use
ordinary direct stdlib calls in an eligible root-application package, return
the iterators, and retain them in a typed `iter.Seq[string]` variable.
There is no `any` boxing, artificial `noinline`, mocked store, or forced GC.
Function-value calls provide uninstrumented controls in the same woven binary;
the separate plain build verifies that this control has matching allocation
counts before weaving.

Setup, starting without the private directory:

```sh
ROOT=/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go
WT=/tmp/ddiast-review/wt/fx-perf-hotpath-F1
E="$ROOT/.omo/review/evidence/fx-perf-hotpath-F1"
mkdir -p /tmp/ddiast-review/wt
rsync -a --exclude .git --exclude .omo "$ROOT/" "$WT/"
mkdir -p "$WT/iast/seqreview"
cp "$E/sequence.go" "$E/sequence_test.go" "$WT/iast/seqreview/"
cd "$WT"
unset DD_IAST_ENABLED DD_IAST_REQUEST_SAMPLING DD_IAST_MAX_CONCURRENT_REQUESTS
export GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6
```

Commands actually run, with stdout/stderr captured:

```sh
# plain-1.26.6.txt: exits 0
timeout 900 go test -v \
  -run 'TestNoOwnerAllocationParity|TestSequenceValues' \
  -bench 'BenchmarkEscapingSequence|BenchmarkImmediateSplit' \
  -benchtime=10000x -benchmem -count=1 -timeout=15m ./iast/seqreview

# woven-test-1.26.6.txt: deliberately fails allocation parity, exits 1
timeout 900 /usr/bin/time -l go tool orchestrion go test -v \
  -run 'TestNoOwnerAllocationParity|TestSequenceValues' \
  -count=1 -timeout=15m ./iast/seqreview

# woven-bench-1.26.6.txt: exits 0
timeout 900 /usr/bin/time -l go tool orchestrion go test -run '^$' \
  -bench 'BenchmarkEscapingSequence|BenchmarkImmediateSplit' \
  -benchtime=10000x -benchmem -count=1 -timeout=15m ./iast/seqreview
```

Decisive test output:

```text
toolchain=go1.26.6 woven=true enabled=true sampling=30 max_concurrent=2 no_owner=true
native=2 direct=3 extra=1 allocs/call
no-owner allocation regression: native 2, direct 3
--- FAIL: TestNoOwnerAllocationParity
--- PASS: TestSequenceValues
```

On Go 1.26.6, all five allocation-parity subtests fail only in the woven
build. All five deferred-consumption value comparisons pass.

Go 1.26.6 woven benchmark results:

| Constructor | Native B/op, allocs/op | Direct woven B/op, allocs/op |
| --- | ---: | ---: |
| SplitSeq | 64, 2 | 96, 3 |
| SplitAfterSeq | 64, 2 | 96, 3 |
| Lines | 32, 2 | 64, 3 |
| FieldsSeq | 24, 1 | 56, 2 |
| FieldsFuncSeq | 32, 1 | 64, 2 |

Immediate `range strings.SplitSeq(...)` remains **0 B/op, 0 allocs/op**
in both builds. The finding is specifically about escaping iterators, not
an unconditional heap allocation at every call site.

The original benchmark was also rerun independently:

```sh
cp "$E/finder_hotpath_review_test.go" iast/propagation/hotpath_review_test.go
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 timeout 900 go test -run '^$' \
  -bench '^BenchmarkHotPathReview/(no-owner|active-clean)/split-seq$' \
  -benchtime=100ms -count=1 -benchmem -timeout=15m ./iast/propagation
```

`finder-1.26.6.txt` confirms native **64 B/op, 2 allocs/op** versus
wrapper **96 B/op, 3 allocs/op**, both without an owner and with an active
owner containing no tainted values. It exits 0.

Go 1.27.0 was also tried:

```sh
# woven-test-1.27.0.txt: build fails, exits 1
GOTOOLCHAIN=go1.27.0 timeout 900 /usr/bin/time -l \
  go tool orchestrion go test -v \
  -run 'TestNoOwnerAllocationParity|TestSequenceValues' \
  -count=1 -timeout=15m ./iast/seqreview

# finder-1.27.0.txt: direct wrapper isolation, exits 0
GOTOOLCHAIN=go1.27.0 timeout 900 go test -run '^$' \
  -bench '^BenchmarkHotPathReview/(no-owner|active-clean)/split-seq$' \
  -benchtime=10000x -count=1 -benchmem -timeout=15m ./iast/propagation
```

The aggregate woven build is blocked by unrelated JSON advice:

```text
# encoding/json
$WORK/b104/orchestrion/src/encoding/json/<generated>:2: dec.r undefined (type *Decoder has no field or method r)
$WORK/b104/orchestrion/src/encoding/json/<generated>:2: dec.d undefined (type *Decoder has no field or method d)
FAIL github.com/DataDog/dd-iast-go/iast/seqreview [build failed]
```

The isolated Go 1.27.0 wrapper benchmark still reports native **64 B/op,
2 allocs/op** versus hook **96 B/op, 3 allocs/op**, in both owner states.
This does not establish end-to-end Go 1.27.0 reachability; that is blocked
before the fixture runs. No unrelated production code was changed.
The largest reported woven-command maximum RSS was 319,242,240 bytes,
below the brief's 4 GiB reporting threshold.

## Reachability

**Reachable by default: yes, in an Orchestrion-built application.**
`iast/propagation/orchestrion.yml:571-614` unconditionally replaces eligible
direct calls to the five stdlib constructors. The aggregate
`orchestrion.tool.go:24` enables propagation instrumentation. Returning an
iterator from an application function and storing it for later consumption is
ordinary supported code; it does not require HTTP traffic or an active owner.
The independent woven run explicitly records the default settings:
enabled, 30% sampling, and two concurrent analyses.

**Documented limitation: no.** README's propagation table advertises sequence
variants. Its unstable-performance notice is not a deliberate exemption for
inactive allocations. Neither that README nor
`.omo/review/phase1/01-design-intent.md` documents this cost; the accepted
writer-receiver escape trade-off concerns a different mechanism. Allocating a
propagation wrapper when no provenance can exist violates the requirement to
gate unnecessary work cheaply.

## Adjusted severity

**Medium:** a reproducible, avoidable hot-path heap allocation under default
configuration, but the evidence establishes a bounded +32 B/+1 allocation,
not the several-fold necessary-work slowdown required for High.

For the reported SplitSeq case, bytes and allocations rise 50%, not several
times. Other constructors rise by up to 2.33 times in bytes and twice in
allocation count. Shared-host timings are not used to infer a stable slowdown.
There is no demonstrated value difference, unbounded storage, or IAST
self-disable. The zero-allocation immediate-consumption result further limits
the allocation claim.

## Root cause (file:line)

- `iast/propagation/orchestrion.yml:571-614`: direct call-site replacement
  makes the wrapper reachable in normal application code.
- `iast/propagation/strings.go:75-86,104-110`: five constructors always call
  `stringWindowSeq`.
- `iast/propagation/strings.go:113-124`: `return func(...)` captures both the
  input string and the native sequence without an activity guard.
- `internal/taint/propagation/propagation.go:196-205`: `StringWindow` checks
  activity only when the sequence yields a value.
- `internal/taint/request/lookup.go:70-79`: the available allocation-free
  owner gate returns nil with no active analysis, but it is reached too late
  to prevent construction of the escaping wrapper.

## Minimal fix

Before returning the capturing closure in the shared `stringWindowSeq`,
return `sequence` unchanged when the existing
`operatorbridge.HasValues()` counter is zero. That also handles an active
but wholly clean store; an owner-only guard addresses the no-owner case.
Keep the current per-yield propagation and liveness checks when taint values
exist. Do not eagerly consume the sequence.

This is a proposed fix, not a production change made by this verification.
Retain allocation-parity coverage plus active-taint, early-stop,
owner-finish, and immediate-consumption tests when implementing it.
