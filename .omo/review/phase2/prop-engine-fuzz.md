# prop-engine-fuzz: long fuzz campaigns and an exact-op differential fuzzer for the propagation engine
Verdict: No correctness defect found in internal/taint/propagation exact/coarse string and byte transforms. Three 12-minute campaigns (24.7M execs total) produced no range/oracle mismatch, no out-of-bounds range, no value change, and no panic. Only Low/Info observations remain.
Scope covered: internal/taint/propagation/{propagation.go, string_exact.go, bytes_exact.go, string_coarse.go (CaseString, CoarseString), conversion.go, operator_concat.go} read in full; the existing fuzz harnesses (sequence_fuzz_test.go, sequence_fixture_test.go, sequence_operations_test.go, sequence_replace_test.go, sequence_oracle_test.go, owner_lifecycle_fuzz_test.go) read; call-site mapping in iast/propagation/{strings.go, bytes.go, coarse.go}; store lookup/derive/adopt paths (store/lookup.go:107-198, store/root.go:231-279, store/value.go:110-194) and ranges builder/Coarse/Repeat/Compose (ranges/operations.go:136-440). All runs used GOTOOLCHAIN=go1.26.6 and GOFLAGS=-p=4, with -parallel 2, in /tmp/ddiast-review/wt/prop-engine-fuzz (now deleted).

## Campaign results
| Fuzzer | Duration | Execs | Corpus | Result | Max RSS |
|---|---|---|---|---|---|
| FuzzEngineSequence (existing) | 12m0s | 5,557,124 | 327 | PASS | 267 MB |
| FuzzOwnerLifecycle (existing) | 12m0s | 12,641,782 | 37 | PASS | 262 MB |
| FuzzExactStringOps (new) | 12m1s | 6,479,217 | 1,400 | PASS | 371 MB |

Logs: `.omo/review/evidence/prop-engine-fuzz/fuzz_engine_sequence_12m.log`, `fuzz_owner_lifecycle_12m.log`, `fuzz_exact_string_ops_12m.log`. New-fuzzer corpus: `.omo/review/evidence/prop-engine-fuzz/FuzzExactStringOps_corpus.tgz`.

New fuzzer: `.omo/review/evidence/prop-engine-fuzz/zz_review_exact_ops_fuzz_test.go` (package propagation_test). Drop it into internal/taint/propagation and run `go test -run '^$' -fuzz '^FuzzExactStringOps$' -fuzztime 12m -parallel 2 .`. Each input runs 14 steps against 2 live owners, starting from random per-byte, per-owner taint (source IDs and marks). Each step applies one of 18 real stdlib operations and routes it through the engine's exact entry point: JoinString (1-20 elements, including the >16 coarse fallback, empty/tainted/clean separators, and runtime-`+` alias semantics), ReplaceString/ReplaceBytes (empty, 1-3 byte, and pool `old`; counts -1/0/1/2/3/5/40, including the >32-match coarse fallback), RepeatString/RepeatBytes (0-5), StringWindows/ByteWindows (Split, SplitAfter, SplitN, Fields, FieldsFunc), StringWindow/ByteWindow (Trim*, Cut, TrimFunc), CaseString/CaseBytes (Upper/Lower/Title over ASCII, non-ASCII, and invalid UTF-8), CopyString, AdoptStringCopy, CopyBytes, CoarseString (Replacer), CoarseBytes (Map), ValidUTF8Bytes, and BytesToString. After every operation it asserts:
(a) the returned value is byte-identical to the uninstrumented stdlib result;
(b) every store range satisfies Start+Length <= visible len (bytes included, whose roots span cap);
(c) the per-owner ranges equal a per-byte oracle that models exact copy/compose, the documented 10-range prefix truncation, one-byte fresh-root refusal, and whole-value Coarse (first source, AND of marks) where the engine documents coarse fallback;
(d) no contribution comes from an unexpected owner.
A missing contribution is tolerated only when a store drop counter moved during that step, and even then wrong ranges fail the run.

Non-vacuity: over the generated corpus, statement coverage is 72-100% for the targeted exact/coarse functions (the uncovered statements are mostly contended or stale-handle `continue` branches; coarseBytesAlias is at 44% because Map results never alias) (`.omo/review/evidence/prop-engine-fuzz/exact_ops_coverage.txt`). Three injected engine mutants were each killed by the corpus replay (`.omo/review/evidence/prop-engine-fuzz/mutation_kill_check.txt`):
- separator length dropped in joinStringHit fails with "missing owner 0 contribution";
- the ASCII check removed from caseBytesHit fails with "owner 0 ranges differ";
- `&=` changed to `|=` in coarseAccumulate fails with "ranges differ".

A harness-side memory blow-up appeared during bring-up: the worker died with 1.47 GB RSS while building a 16 MB replace oracle before its length guard (`.omo/review/evidence/prop-engine-fuzz/fuzz_exact_ops_harness_oom_probe.log`). The fix was to pre-size the output and append in linear time. It was not an engine issue: the crashing inputs pass once replayed.

## Findings
### prop-engine-fuzz-F1: JoinString clones a single-element join that already aliases a tracked value, doubling the root charge
- Severity: Low
- Category: perf
- Location: internal/taint/propagation/string_exact.go:24-47, 50-111
- Claim: `strings.Join([]string{x}, sep)` returns `x` itself (an alias). The alias fast path in JoinString only runs when `separator == ""` (string_exact.go:24). With a non-empty separator, joinStringHit clones the result (string_exact.go:66) and adopts a second managed root for bytes that are already tracked with identical ranges. That costs an allocation of up to 64 KiB plus a second root charge against the 2 MiB request / 8 MiB process budgets, so drops come earlier. Provenance stays correct.
- Evidence: `.omo/review/evidence/prop-engine-fuzz/zz_review_join_single_test.go`. Command: `go test -run '^TestReviewJoinSingleElementClones$' -v ./internal/taint/propagation`. Output (`.omo/review/evidence/prop-engine-fuzz/join_single.out.txt`): "native aliases element: true", "JoinString returned alias: false", "owner charge: 4096 -> 8192 bytes; owner values: 1 -> 2", "ranges on returned value: [{0 4096 1 0}]".
- Fix: before the store lookup, return the alias whenever `len(elements) == 1 && stringAlias(elements[0], result)`: call `StringWindow(elements[0], result)` and return `result`, regardless of the separator.

### prop-engine-fuzz-F2: Repository fuzzing covers only a narrow slice of the exact/coarse transition space
- Severity: Low
- Category: test-gap
- Location: internal/taint/propagation/sequence_operations_test.go:16-33; sequence_replace_test.go:24-31; sequence_fixture_test.go:18-25
- Claim: FuzzEngineSequence exercises 6 operation kinds: copy, window, repeat, 2-element join, replace with a 1-byte `old` (32 or fewer matches only, since sequence_replace_test.go:29-31 forces count=3 when there are more), and BytesToString. The exact-to-coarse transitions ranked as risk area 7 in 00-architecture.md have only example-based unit tests in the repository: join over 16 elements, replace over 32 matches, empty-`old` rune stepping, ValidUTF8Bytes invalid runs, Case*/Coarse* coarse widening, and multi-output Split/Fields windows. The new differential fuzzer covered these paths for 6.48M execs and found nothing wrong, but that coverage is not in the repository.
- Evidence: `.omo/review/evidence/prop-engine-fuzz/zz_review_exact_ops_fuzz_test.go`, `.omo/review/evidence/prop-engine-fuzz/exact_ops_coverage.txt`, `.omo/review/evidence/prop-engine-fuzz/mutation_kill_check.txt` (three mutants in these paths are killed by the new harness), and the operation switch in sequence_operations_test.go:18-33.
- Fix: upstream FuzzExactStringOps, or fold its operations and oracle into the existing sequence harness, and keep a small checked-in corpus.

### prop-engine-fuzz-F3: The >16-element join gate inspects 16 elements, but the coarse fallback reads only 15
- Severity: Info
- Category: provenance
- Location: internal/taint/propagation/string_exact.go:52-55, 269-277; bytes_exact.go:39-43, 481-489
- Claim: For joins with more than 16 elements, `mayContainJoinedString` / `mayContainJoinedBytes` gate on elements[0..15], while the coarse fallback reserves one slot for the separator and reads only elements[0..14]. When the only taint sits in element 15, the call passes the gate, performs lookups, and publishes nothing. This is consistent with the documented bounded-prefix trade-off, so it is not a defect. It is a wasted slow path and a documentation nuance: the bound is 15 elements plus the separator, not 16.
- Evidence: static reasoning. The fuzzer oracle models the 15+separator prefix and matched across 6.48M execs.
- Fix: cap the gate at `maxInputs-1` elements when `len(elements) > maxInputs`, or document the 15-element prefix.

### prop-engine-fuzz-F4: RepeatBytes looks up the store before its cheap bounds check
- Severity: Info
- Category: perf
- Location: internal/taint/propagation/propagation.go:546-575
- Claim: RepeatBytes runs `MayContain` and `Lookup` and only then checks `withinByteBounds(result)` (propagation.go:569), unlike CopyString, RepeatString, and the other exact paths, which check length first. A result with `len < 2` or larger than MaxRootBytes pays a snapshot copy of up to 4 owners x about 1.5 KiB for nothing.
- Evidence: static reasoning (code order).
- Fix: check `withinByteBounds(result)` before the store lookup. bytes.Repeat never returns an alias, so the alias branch does not need the lookup first.

## Checked and found correct
- Value preservation: every wrapped engine call returned a value byte-identical to the stdlib result across all 24.7M execs, including the clone-returning string paths.
- Range bounds: no produced range ever exceeded the visible value length, including byte results whose roots span `cap` (the Lookup window slice at store/lookup.go:176-178 clips correctly).
- Exact replace segmentation (`mapReplaceSegments`, `mapReplaceByteSegments`) matches strings/bytes.Replace for empty `old` (rune stepping, invalid UTF-8 as width 1), overlapping candidates, counts -1/0/n/>matches, and exactly 32 versus 33 matches.
- `mapValidUTF8Segments` matches bytes.ToValidUTF8 run semantics, including the 32-run exact bound and the coarse fallback beyond it.
- Join/Concat: exact concat with tainted/clean/empty separators; the single-candidate runtime-concat alias path (derive); coarse fallback over 15 elements plus the separator; the 10-range prefix truncation is equivalent to step-wise Concat truncation (ranges/operations.go:305-337).
- Case transforms: the ASCII equal-length exact path, the alias-when-unchanged path, and coarse widening for non-ASCII or length-changing results (invalid UTF-8 grows to U+FFFD). Coarse uses the first source with AND-ed marks, so it never invents sanitization.
- Window derivation: at most 32 windows per call, empty outputs stay clean, and 1-byte derived windows keep provenance while 1-byte fresh roots are refused.
- Owner separation: no cross-owner contribution was observed with 2 concurrent owners, and FuzzOwnerLifecycle confirmed that finish releases charge and values and that slot reuse advances identity (12.6M execs).

## Not covered / open questions
- CoarseFormatString and CoarseFormattedString (fmt paths), json.go, and writer.go were not fuzzed: they fall outside exact string ops.
- All runs were single-goroutine. Contention and TryLock drop behaviour, and more than 4 owners (snapshot fanout), are left to store/race nodes.
- Outputs beyond index 32 of StringWindows and ByteWindows are not asserted (documented cap).
- Fuzzing ran on Go 1.26.6 only, not the machine default go1.27.0.
