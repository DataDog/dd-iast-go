# prop-bytes-exact: Byte windows, fresh results, and invalidation

Verdict: Correctness disproved: supported reslicing within capacity loses taint; one reproduced High finding.

Scope covered: HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.
Read all of `internal/taint/propagation/bytes_exact.go` and `conversion.go`,
the byte-copy/window/repeat/coarse helpers in `propagation.go`,
`store/root.go`, `store/lookup.go`, `store/mutation.go`, and the relevant
window-publication and buffer-invalidation sections of `store/value.go` and
`store/writer.go`. Traced callers through `iast/propagation/bytes.go`,
`operators.go`, `writer.go`, and their Orchestrion advice, plus request byte
source publication. Read and ran the existing propagation/store tests and
private reproducers. Audited the allocating stdlib paths against the installed
Go 1.26.6 `bytes` source.

Applied research digest checks 9, 10, 12, 15, 16, and 23, and shadow scenarios
S1, S9, S11, S13, S21, S29, S31, S32, and S35 where they concern this component.
All builds and tests ran in `/tmp/ddiast-review/wt/prop-bytes-exact`.
Production code was not changed.

## Findings

### prop-bytes-exact-F1: Reslicing beyond the current length loses tracked byte provenance

- Severity: High
- Category: false-negative
- Location: `internal/taint/propagation/propagation.go:53-60`;
  rejection at `internal/taint/propagation/propagation.go:480-487`;
  supported callers at `iast/propagation/operators.go:276-303`.
- Claim: `ByteWindow` rejects valid two-index and three-index slices when the
  result extends beyond the input's current length, even though it remains
  inside both the input capacity and its existing managed root.
  `bytesAlias` compares the result end against `base + len(input)`, rather than
  the addressable capacity. No result key is derived, so later
  `BytesToString` also misses at `conversion.go:23-29`. This drops even the
  tainted bytes that overlap the input's visible prefix, not only newly exposed
  bytes. The reproduction contains no writes, unsupported operations, owner
  completion, contention, or budget exhaustion. README.md:33 explicitly
  advertises both slice forms.
- Evidence: Test source
  `.omo/review/evidence/prop-bytes-exact/zz_review_bytes_alias_test.go`;
  complete captured output
  `.omo/review/evidence/prop-bytes-exact/repro-go1.26.6.txt` and
  `repro-go1.27.0.txt`. Copy the test into
  `internal/taint/propagation/` in a fresh private copy, as described in the
  evidence directory's `README.md`, then run:

  ```sh
  cd /tmp/ddiast-review/wt/prop-bytes-exact
  GOMAXPROCS=2 GOTOOLCHAIN=go1.26.6 go test -p=2 -count=1 -timeout=3m -run '^TestReview' -v ./internal/taint/propagation
  ```

  The root is `"01234567"` with range
  `{Start:2, Length:4, SourceID:7, Marks:6}`. After `short := root[:3:7]`,
  both `short[1:6]` and `short[1:6:7]` return the correct `"12345"`,
  length 5, capacity 6, and backing pointer, but:

  ```text
  short len=3 cap=7, result="12345" len=5 cap=6, byte ranges=[], string ranges=[], want=[{1 4 7 6}]
  --- FAIL: TestReviewResliceWithinCapacityPreservesRanges/two-index
  --- FAIL: TestReviewResliceWithinCapacityPreservesRanges/three-index
  ```

  Both Go 1.26.6 and Go 1.27.0 exit 1 for these assertions. A shortened
  clean prefix also loses access to the tainted capacity tail.

  Compiler-woven confirmation uses public `taint.TaintBytes`, ordinary slice
  expressions, and an ordinary string conversion. Source:
  `.omo/review/evidence/prop-bytes-exact/zz_review_bytes_woven_test.go`;
  output: `.omo/review/evidence/prop-bytes-exact/woven-go1.26.6.txt`.
  After installing that test into `iast/propagation/`, run:

  ```sh
  cd /tmp/ddiast-review/wt/prop-bytes-exact
  GOMAXPROCS=2 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -p=2 -count=1 -timeout=4m -run '^TestReviewWoven' -v ./iast/propagation
  ```

  ```text
  woven=true input=true short=true result=false converted=false result="12345"
  --- FAIL: TestReviewWovenResliceWithinCapacity
  Messages: supported reslice lost source provenance
  ```

  The woven preflight, positive shortened-window control, and byte-identical
  clean control all pass before the failing assertion.
- Fix: For byte slicing, validate containment against the input's addressable
  capacity, then derive from its existing owner/root reference. Keep the
  store's root-span validation and root-relative range clipping; do not create
  a fresh root for an interior result. The store already checks the complete
  root span in `store/value.go:35-48` and clips ranges in
  `store/lookup.go:176-195`. Also address zero-length capacity-bearing
  intermediates: the same reproducer shows their subsequent expansion loses
  provenance, and merely changing `len` to `cap` is insufficient because
  `BytesKey` rejects empty values. Retain a bounded root association for such
  windows without reporting taint on the empty value itself.

## Checked and found correct

- **Existing baseline:** Before adding reproducers, Go 1.26.6
  `go test -p=2 -count=1 -timeout=3m ./internal/taint/propagation ./internal/taint/store`
  exited 0. Captured output is in `baseline-go1.26.6.txt`. This includes the
  existing fixed-seed 2,000-sequence independent range oracle. Its byte-window
  generator restricts bounds to current length
  (`sequence_operations_test.go:51-74`), explaining why it does not catch F1.
- **In-length windows and three-index capacity:** The added passing control
  retains the original backing pointer, preserves the requested capacity,
  clips offsets/source IDs/secure marks exactly, and permits a one-byte
  derived window. Equal bytes in a distinct untracked allocation remain
  untainted.
- **Fresh results versus aliases:** The added control confirms distinct
  backing arrays and exact range preservation for `Clone`, single-element
  `Join`, `Repeat(...,1)`, `Replace(...,0)`, no-match `ReplaceAll`,
  unchanged lowercase, and already-valid `ToValidUTF8`. These are real stdlib
  results, not simulated fresh allocations. The inspected Go 1.26.6 stdlib
  fast paths agree with the adoption assumptions in `bytes_exact.go`.
- **Exact transformation algebra:** Existing passing tests cover element and
  separator provenance, owner-local source IDs, copied versus replacement
  segments, partial ranges, empty patterns, valid and invalid UTF-8,
  ASCII exact positions, Unicode coarse behavior, secure marks, and the
  32-match exact/coarse boundary. No additional defect was found in the
  `JoinBytes`, `ReplaceBytes`, `ValidUTF8Bytes`, or `CaseBytes` implementations
  themselves under their audited-caller contracts.
- **Mutation invalidation and independent copies:** The added controls
  overwrite a root and explicitly invoke `PublishBytesMutation`. A successful
  empty-range update invalidates old windows; a rejected update after the
  generation claim also invalidates them. Independently copied byte results
  and the prior immutable string conversion keep their old, correct ranges.
  These results become untainted after owner finish. The controls pass on
  Go 1.26.6 and Go 1.27.0.
- **Conversion:** For tracked, nonempty windows of at least two bytes,
  `BytesToString` preserves exact source IDs, offsets, and marks on the fresh
  immutable result. The reviewed one-byte new-root exclusion remains a
  documented safe miss, not a new finding.
- **Bounds and race checks:** Existing tests reject oversized result lengths
  and capacities, retain the output-index/window limits, and exercise owner
  finish racing with byte propagation. The targeted exact-byte tests and new
  passing mutation/copy controls also pass with `-race` on Go 1.26.6:
  `race-go1.26.6.txt`, exit 0. The original package suites were not weakened;
  the separate correctness reproducers intentionally remain failing.

## Not covered / open questions

- **Documented mutable-alias limitation confirmed, not re-reported:** The
  woven characterization hands a tainted byte root to `bytes.NewBuffer`,
  resets the buffer, and overwrites it with clean bytes using `WriteString`.
  Reading the retained byte alias and converting it still reports taint:

  ```text
  documented later-alias limitation: woven=true overwritten="CLEAN!!!" byteTainted=true convertedTainted=true
  ```

  This is captured in `woven-go1.26.6.txt`. Native buffer invalidation tracks
  receiver/writer entries and overlapping writer views
  (`store/writer.go:363-399`), not every separately retained byte root.
  It falls under README.md:43-46's explicit later-alias limitation.
  The direct store-mutation controls above must not be mistaken for evidence
  that arbitrary `copy`, index writes, or root-to-buffer ownership transfers
  are automatically instrumented.
- Empty values are intentionally untainted. F1's nonempty intermediate is
  sufficient to establish the High finding regardless of how the product
  decides to describe empty-intermediate reslicing.
- No SQL/exec sink was invoked; loss is proven at the public taint lookup and
  converted-string boundary used by downstream reporting. No live backend,
  non-darwin platform, exhaustive interleaving proof, long fuzz campaign,
  retained-heap benchmark, or whole-repository checklocks run was attempted.
- The private test sources are preserved byte-for-byte in the evidence
  directory. Replay instructions recreate the disposable copy; no fix was
  applied to the reviewed implementation.
