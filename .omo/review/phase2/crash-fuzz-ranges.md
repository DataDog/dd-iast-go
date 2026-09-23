# crash-fuzz-ranges: long ranges fuzz campaigns
Verdict: No crashers or invariant failures were found in either required 15-minute ranges fuzz campaign.
Scope covered: `internal/taint/ranges/fuzz_test.go` (`FuzzCanonicalize`, `FuzzSliceAndCopy`), `canonical.go` (`Canonicalize`), `operations.go` (`Slice`, `CopyOverwrite`/`Overwrite`), and `ranges.go` (`Set.ValidFor` and input bounds), run in the mandated private copy with Go 1.26.6 on darwin/arm64.

## Findings

No findings. Both fuzz targets exited successfully; neither produced a minimized failing input, panic, assertion failure, or generated crasher artifact.

## Checked and found correct

- `GOTOOLCHAIN=go1.26.6 go test -run='^$' -fuzz='^FuzzCanonicalize$' -fuzztime=15m -parallel=4 -timeout=18m ./internal/taint/ranges` passed in 900.635 seconds. It completed baseline coverage with 48 corpus entries, ran four workers, reached 30,020,191 executions at 15:00, and found zero new interesting inputs.
- `GOTOOLCHAIN=go1.26.6 go test -run='^$' -fuzz='^FuzzSliceAndCopy$' -fuzztime=15m -parallel=4 -timeout=18m ./internal/taint/ranges` passed in 900.722 seconds. It completed with nine corpus entries, ran four workers, reached 32,266,611 executions at 15:00, and found zero new interesting inputs.
- `FuzzCanonicalize` generated bounded valid raw ranges and checked the result against an independent canonicalization oracle, `Outcome.Valid`, `Set.ValidFor`, and truncation behavior.
- `FuzzSliceAndCopy` checked that `Slice` and overlapping `CopyOverwrite` results stayed valid for their output lengths.
- The only corpus files under `internal/taint/ranges/testdata/fuzz` were the repository's pre-existing `overlap` seeds, whose contents match the targets' explicit seed inputs; no failure-derived corpus entry was present.

## Not covered / open questions

- These campaigns exercise only the two package fuzz targets; they do not prove all range operations, concurrency behavior, request/store ownership, or mutable-byte limitations identified in the phase-1 research.
- The absence of new interesting inputs is a fuzzer observation, not a proof that no unrepresented input shape can fail.
