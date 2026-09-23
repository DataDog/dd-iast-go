# fx-perf-algorithmic-F1: repeated full-source work per range

Target: HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.

## Verdict per finding

**perf-algorithmic-F1: CONFIRMED.** Each unsafe resolved range calls `sourceIndex`, which hashes the entire source name and value before probing for an already copied source. An existing entry then compares the full strings again. For R ranges from one S-byte source, evidence collection does O(R*S) source work instead of resolving that source once. There is only one finding under test, so there are no duplicates to merge.

## Reproduction

Independent reproducer: `.omo/review/evidence/fx-perf-algorithmic-F1/review_command_source_test.go`. Captured output: `.omo/review/evidence/fx-perf-algorithmic-F1/command-source-output.txt`. In the private copy, place the reproducer at `internal/taint/evidence/review_command_source_test.go`, then run:

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -mod=readonly -run '^$' -bench '^BenchmarkReviewCommandRepeatedSource$' -benchmem -benchtime=200ms -count=2 -cpu=1 -v -timeout 5m ./internal/taint/evidence
```

The test creates a real managed HTTP header source via `request.EagerHTTP`, derives distinct one-byte windows, and calls the **actual command-sink evidence collector** on 1 or 10 arguments. It overrides only sampling to 100% so admission is deterministic; the range limit remains its default 10. Key output:

```text
sourceBytes=65536 sinkBytes=19 collectedRanges=10 distinctSources=1 defaultRangeLimit=10
sourceBytes=65536/arguments=1       399989 / 418269 ns/op
sourceBytes=65536/arguments=10     7443828 / 4285379 ns/op
PASS
```

The paired 10-range cases took about 10–19 times as long as the one-range cases, despite copying exactly one source per report. Timings are noisy on this shared machine; the code path, range/source assertions, and profile are the stronger evidence. A Go 1.26.6 profile of the 10-range case sampled `sourceHash` for 430/900 ms (47.78% of captured CPU samples). Go 1.27.0 also collected 10 ranges and one source (4,982,410 ns/op versus 901,123 ns/op for one range). All commands, including the profile, passed; nearby evidence tests and `gofmt -l` passed.

## Reachability

**Yes, under defaults on sampled requests.** A 64-KiB HTTP header value is within the source-root limit; ten separate one-byte derived arguments fit the default `DD_IAST_MAX_RANGE_COUNT=10`. Command attempts run `iast/os/exec/exec.go:42-60`, which invokes `CollectJoinedStrings` before report deduplication; the same per-range collector also runs for SQL evidence. The default 30% request sampling limits how often it runs, not the per-sink cost once a request is admitted. The reproducer uses the internal HTTP and evidence APIs instead of a woven binary; it does not measure the full process attempt, redaction, or span commit.

**Not a documented deliberate limitation.** The README warns that performance is under development, and the design documents state finite source/range bounds; neither accepts rehashing an identical source for every range. The extra work violates the rule to minimize overhead on customer critical paths.

## Adjusted severity

**High (unchanged):** a reachable sink-path cost several times larger than needed under the default range limit, repeated before report deduplication. The source/range caps bound the total work, so this is not a Critical unbounded-cost finding.

## Root cause (file:line)

`internal/taint/evidence/evidence.go:209-221` resolves every unsafe range; `:240-266` calls `sourceHash` before the existing-entry check; `:277-291` iterates over all source bytes. `internal/taint/request/lookup.go:16-27,107-138` returns source strings per range but not their owner-local source ID to the collector.

## Minimal fix

Carry the validated owner-local source ID into `ResolvedRange` and use a small fixed, report-local cache keyed by owner identity/generation and source ID. Reuse its source index for subsequent ranges; retain exact full-identity hashing/comparison on a cache miss and across owners, and retain the existing source/byte limits.
