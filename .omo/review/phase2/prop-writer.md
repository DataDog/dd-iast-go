# prop-writer: Builder and Buffer propagation

Verdict: One High-severity writer-owner fanout bound breach; the reviewed read, write, reset, truncation, and copy paths otherwise follow the stated safe-miss policy.
Scope covered: `internal/taint/propagation/writer.go`, `internal/taint/writerbridge/bridge.go`, `internal/taint/store/writer.go`, `iast/propagation/writer.go`, writer aspects in `iast/propagation/orchestrion.yml`, Go `bytes.Buffer` methods, and existing writer tests.

## Findings

### prop-writer-F1: One Builder retains up to 60 owner records despite a four-owner limit
- Severity: High
- Category: memory-bound
- Location: internal/taint/propagation/writer.go:101-132
- Claim: `LookupWriterValue` returns at most four existing receiver owners, but the second loop calls `UpdateWriter` for each previously unseen owner contributing a tainted input without checking that receiver's total fanout. Each active owner can therefore retain a charged record for the same Builder. This violates the documented four-owner-per-receiver cap by up to 16x (64 active owners), while still respecting the separate process and per-owner quotas. For the reproduced 60-owner case, the 60 writer records alone charge 1,966,080 bytes instead of a four-record maximum of 131,072 bytes at 32 KiB each.
- Evidence: `.omo/review/evidence/prop-writer/zz_review_writer_test.go` and `.omo/review/evidence/prop-writer/owner-fanout.out.txt`; run `cd /tmp/ddiast-review/wt/prop-writer && GOTOOLCHAIN=go1.26.6 go test -timeout 10m -count=1 -run '^TestReviewWriterOwnerFanoutBound$' -v ./internal/taint/propagation` after copying the evidence test to `internal/taint/propagation/zz_review_writer_test.go`. Output: `writer records=60, process charged bytes=1966560`; assertion: `"60" is not less than or equal to "4"`. The extra 480 bytes are the 60 input roots. Exit status 1 is the expected reproducer failure.
- Fix: Enforce the per-receiver four-owner admission limit before creating a writer state for an input owner. Drop its writer provenance when full, without modifying the host Builder or already admitted owners; keep the existing `MaxWriters` per-owner quota independent.

## Checked and found correct

- `UpdateStringWriter` and `UpdateBytesWriter` snapshot the written input and use `ranges.Concat` with the previous unread length, so an appended input range begins after the existing content. `UpdateUntaintedWriter` advances the writer view without introducing a source range.
- `TruncateWriter` clips ranges to the retained prefix, and an empty result removes writer state. Direct `ResetWriter` releases tracked state. Existing writer tests exercise both.
- `BuilderString` clones a tracked result before publication, whereas `BufferString` adopts the fresh string from `bytes.Buffer.String`. Exact view checks reject unsupported Builder copies or divergent Buffer histories.
- `bytes.Buffer.Read`, `Next`, and other exposing/consuming methods use a native `Exposure` callback to invalidate receiver and overlapping Buffer state; they deliberately drop, rather than shift, remaining ranges. This prevents stale offsets but can miss provenance on the remaining unread bytes. Both `Read` and `Next` returned the host's `tack` after consuming `at`, without stale taint in the woven check at `.omo/review/evidence/prop-writer/zz_review_consumption_test.go` (`buffer-consumption.out.txt`: both subtests PASS). The coverage contract does not advertise preserving taint through reads. `ReadFrom` is not a supported tainted-input writer and its native backing-write callback invalidates existing state.
- Native invalidation distinguishes expected direct writes, header-only changes, and exposures. The direct wrappers cancel their expectation marker on return or panic, and `Truncate(0)` takes the `Reset` path that clears state.
- Selected existing woven tests for Builder/Buffer writes, reset, truncation, exposure, exact Buffer copies, and `ReadFrom` errors passed with `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 10m -count=1 -run '^(TestBuilderAndBufferPropagation|TestWriterResetTruncateAndIndirectMutation|TestBufferExposureMethodsInvalidateBeforeSubsequentReads|TestBufferCopyTruncate|TestBufferOriginalReadFromError|TestBufferCopyReadProvenance)$' -v ./iast/propagation`.

## Not covered / open questions

- Uninstrumented third-party calls, direct mutations through previously retained mutable aliases, and Builder value-copy tracking are documented unsupported paths.
- No exhaustive concurrent writer stress or retained-heap measurement was run. The fanout reproducer measures charged store bytes and retained writer-record count, not allocator heap usage.
