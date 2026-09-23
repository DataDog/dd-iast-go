# crash-fuzz-redaction: long fuzz campaigns for redaction, evidence and request source table
Verdict: No crasher in any of the four 8-minute campaigns (47.5M execs in total, no panic, no invariant failure). However, triage found a reproduced SQL redaction bypass: the Oracle q-quote pre-scan desynchronizes the SQL lexer, so literals, including tainted request values, leave the process unredacted. The FuzzAnalyzeSQL oracle cannot detect this class by construction.
Scope covered: internal/taint/redaction/{sql.go,source.go,analyzer.go,command.go,fuzz_test.go,analyzer_test.go,source_test.go}; internal/taint/evidence/{evidence.go,fuzz_test.go,evidence_test.go helpers}; internal/taint/request/{table.go,lookup.go,fuzz_test.go}; iast/database/sql/sql.go and internal/vulnerability/tainted.go:48-57 (how the analysis reaches BuildWithSensitive). Campaigns: FuzzAnalyzeSQL, FuzzMappedPattern, FuzzSnapshotCanonicalization, FuzzAdd at `-fuzztime 8m -parallel=4` on GOTOOLCHAIN=go1.26.6, GOFLAGS=-p=4, run one at a time in a private copy. Cross-checked against dd-trace-java `SqlRegexpTokenizer` and the shared `evidence-redaction-suite.json` (dd-trace-js/dd-trace-py).

## Campaign results

| Target | Execs | New interesting / corpus | Result | Log |
|---|---|---|---|---|
| FuzzAnalyzeSQL | 20,042,256 | 195 / 935 | PASS, exit 0 | evidence/crash-fuzz-redaction/FuzzAnalyzeSQL.txt |
| FuzzMappedPattern | 9,231,937 | 1 / 15 | PASS, exit 0 | evidence/crash-fuzz-redaction/FuzzMappedPattern.txt |
| FuzzSnapshotCanonicalization | 16,062,434 | 135 / 137 | PASS, exit 0 | evidence/crash-fuzz-redaction/FuzzSnapshotCanonicalization.txt |
| FuzzAdd | 2,155,383 | 31 / 37 | PASS, exit 0 | evidence/crash-fuzz-redaction/FuzzAdd.txt |

No new `testdata/fuzz` crasher files were produced by any campaign. The pre-existing committed seed `redaction/testdata/fuzz/FuzzMappedPattern/18764d2e32df910e` passes.

## Findings
### crash-fuzz-redaction-F1: Oracle q-quote pre-scan ignores string-literal state and unredacts later SQL literals, including tainted values
- Severity: Critical
- Category: redaction
- Location: internal/taint/redaction/sql.go:27-43, 108-151
- Claim: `scanOracleQuotes` scans the raw query byte by byte for `q'<open>` (or `Q'`) preceded by a non-identifier byte, without knowing whether it is inside an ordinary `'...'` literal. A standard literal that ends in `q`/`Q` (for example `'Q'`, `'-q'`, `' q'`) followed by punctuation opens a bogus q-quote. If a later `<open>'` pair exists (for example `,'`), the bogus span closes there (`sql.go:131-140`). The query is then split at that span (`sql.go:37-43`) and every dialect lexes the remaining segment out of phase: the text between real literals is lexed as a string, and the real literal bodies are lexed as bare identifiers, which are not sensitive. All six dialect passes share the same split, so the union does not help. Because `BuildWithSensitive` marks a tainted source as redacted only when its part overlaps a sensitive interval (`source.go:66`), a tainted value in such a literal is emitted raw both in the evidence part and as the wire source `value`. Meanwhile harmless SQL text such as ` AND note = ` gets starred. The trigger is an ordinary query such as `... status IN ('Q','R','') AND note = '<user input>'`. The sink is the default SQLi path (`iast/database/sql/sql.go:45` -> `vulnerability/tainted.go:48-57`).
- Evidence: reproducer evidence/crash-fuzz-redaction/zz_review_oracle_desync_test.go (package `redaction`); command `GOTOOLCHAIN=go1.26.6 go test ./internal/taint/redaction/ -run TestReview -count=1 -v`; captured in evidence/crash-fuzz-redaction/oracle_desync_repro.txt:
  - `query="SELECT * FROM jobs WHERE status IN ('Q','R','') AND token = 'hunter2'" status=0 sensitive=[{40 3} {46 14}] exposedSecretBytes="hunter2"`
  - control `('P','R','')` gives `sensitive=[{37 1} {41 1} {61 7}] exposedSecretBytes=""`
  - end to end: `status=Q evidence="SELECT * FROM jobs WHERE status IN ('Q',***,''*************'userSecret42'" sourceRedacted=false sourceValue="userSecret42"`; control `status=P evidence="... ('*','*','') AND note = '************'" sourceRedacted=true`
  - also leaks for `c IN ('q','x','-') AND pwd='hunter2'`.
- Fix: recognize q-quotes only in code context. Do a single left-to-right scan that skips `'...'` (with `''`), `"..."`, `--` and `/* */` before testing for `q'`, which is what dd-trace-java does with one alternation regex, and apply it to the Oracle dialect pass only. Alternatively, fail closed: also lex the unsplit query in every dialect and take the union of both interpretations' intervals, returning `AnalysisDropped` if either interpretation errors. Add the queries above as regression cases.

### crash-fuzz-redaction-F2: SQL comment bodies are not redacted, contrary to the shared normative redaction suite
- Severity: Medium
- Category: redaction
- Location: internal/taint/redaction/sql.go:83-101 (only STRING/DOLLAR/NUMBER/BOOLEAN/NULL are sensitive); pinned by internal/taint/redaction/analyzer_test.go:30
- Claim: the shared cross-tracer suite (`dd-trace-js/.../evidence-redaction-suite.json` "Query with block comment" and "Query with line comment", and the same file in dd-trace-py) expects comment bodies to be emitted as `{"redacted": true}`. dd-trace-java's `SqlRegexpTokenizer` includes `LINE_COMMENT`/`BLOCK_COMMENT` in every dialect pattern. dd-iast-go emits comments verbatim, and its own test asserts `SELECT column -- secret` stays raw. Comments are a common place for credentials and for tainted fragments (`--` injection), and a tainted fragment inside a comment is also left raw because no interval overlaps it. The design-intent doc already flags that the redaction corpus must be validated against the normative shared corpus before GA; this is a concrete divergence.
- Evidence: static comparison (analyzer_test.go:30 `want: "SELECT column -- secret\nFROM table"` versus the shared suite's expected `{"value": "/*"}, {"redacted": true}, {"value": "*/"}`); no separate reproducer needed because the repository's own test passes with the raw comment.
- Fix: treat `sqllexer.COMMENT`/`MULTILINE_COMMENT` bodies (excluding delimiters) as sensitive intervals, update analyzer_test.go:30, and port the shared suite as a table test.

### crash-fuzz-redaction-F3: FuzzAnalyzeSQL's coverage oracle reuses the production q-quote splitter, so it is blind to F1
- Severity: Medium
- Category: test-gap
- Location: internal/taint/redaction/fuzz_test.go:46-54
- Claim: `assertDefaultSQLLiteralsCovered` calls the same `scanOracleQuotes` and lexes the same segments as production, so any desync the splitter introduces is replicated in the oracle. The 20M-exec campaign passed even though F1 is reproducible with a 70-byte query. The oracle also checks only the default dialect.
- Evidence: FuzzAnalyzeSQL.txt (PASS, 20,042,256 execs) together with the F1 reproducer failing on the same code.
- Fix: use an independent oracle, for example "every literal found by lexing the unsplit query in any dialect is covered, unless status != OK", or a differential check against a small reference tokenizer modelled on the shared suite. Seed it with F1's queries.

### crash-fuzz-redaction-F4: FuzzMappedPattern checks only length and budget, not the redaction property
- Severity: Low
- Category: test-gap
- Location: internal/taint/redaction/fuzz_test.go:85-102
- Claim: the harness never asserts that the output is all `*` or a substring of `sourcePattern` at the unique match offset, so a regression that returned `value` (a raw leak) of the right length would still pass. The corpus plateaued at 15 entries over 9.2M execs, so the campaign adds little beyond the unit test.
- Evidence: FuzzMappedPattern.txt (`new interesting: 1 (total: 15)` for the whole 8 minutes).
- Fix: assert `got == strings.Repeat("*", len(value))` or `got == sourcePattern[i:i+len(value)]` where `i` is the unique index of `value` in `source`.

### crash-fuzz-redaction-F5: FuzzSnapshotCanonicalization never exercises marks, drop bounds or distinct owner generations
- Severity: Low
- Category: test-gap
- Location: internal/taint/evidence/fuzz_test.go:14-40
- Claim: every generated range has `Marks == 0`, `OwnerGen == 1`, `Name == Value`, a fixed 16-byte value, and at most 32 inputs. The mark-split merge condition (`evidence.go`, canonicalize merge on `previous.marks == current.marks`), requested-vulnerability suppression, the `MaxCollectedRanges` drop, and source-byte budget drops are therefore never fuzzed. The campaign saturated at 137 corpus entries.
- Evidence: FuzzSnapshotCanonicalization.txt (135 new interesting, flat after roughly 3 minutes).
- Fix: derive marks, owner generation and a separate name from input bytes, allow up to `MaxCollectedRanges+1` inputs, and assert the drop status at the bound.

### crash-fuzz-redaction-F6: FuzzAdd covers only the isolated string `Table.Add` path
- Severity: Info
- Category: test-gap
- Location: internal/taint/request/fuzz_test.go:20-61; internal/taint/request/table.go:130-157
- Claim: production inserts go through `prepareBytes` and the transactional managed-source methods on `Analysis`. The byte-equality branch (`table.go:146-148`) and the prepare/commit split with a failed root publication are not fuzzed. Each exec also does 300 `fmt.Sprintf` plus testify calls, which keeps throughput low.
- Evidence: FuzzAdd.txt.
- Fix: fuzz `prepareBytes`/`prepareString` equivalence (same logical source through the string and byte paths yields the same ID), and move the filler loop out of the per-exec path or shorten it.

## Checked and found correct
- No panic or invariant failure in any campaign: AnalyzeSQL intervals are sorted, non-overlapping, in bounds and at most 256, and non-OK statuses expose no value. mappedPattern keeps a non-negative budget and length parity. Snapshot canonicalization is independent of input order and parts tile the value exactly. The source table has stable IDs, exact dedup, never exceeds `MaxSources`, and never evicts ID 0.
- Literal syntaxes are covered without the q-desync trigger (probe output in oracle_desync_repro.txt): MySQL `\'` escapes, `''` doubling, `E'..'`, `N'..'`, `"..."`, `$$..$$`, `$x$..$x$`, a real `q'[..]'`, and `'q' || '..'`/`'Q'||'x'||'..'` (the empty-body case is correctly skipped).
- `BuildWithSensitive` redacts a tainted source whenever any part overlaps a sensitive interval (source.go:66), and the analyzer-failure fallback redacts everything (confirmed by the `('P',...)` control and the existing tests). With redaction disabled, sink intervals are ignored by design (source.go:48).
- `mappedPattern` only ever returns stars or a slice of the alphanumeric source pattern, so it cannot echo value bytes, and its comparison work is charged before `strings.Index` (source.go:283).
- Evidence collector bounds: 256 ranges, 256 sources, 512-slot probe bounded by the table length, and a 256 KiB source-byte budget with overflow-safe subtraction (evidence.go:240-275). Parts are at most `2*ranges+1` (evidence.go:416-430).
- `Table.prepare` probe is bounded at 512, load is at most 50%, the hash is seeded per table, and commit happens only after a successful prepare (table.go:130-163).

## Not covered / open questions
- The breadth of F1 beyond the demonstrated shapes (for example q/Q-ending literals combined with `)`, `|`, `<` and so on) was not enumerated. Any construct where the bogus span closes early and resynchronizes the lexer is affected.
- Woven end-to-end confirmation of F1 through a real `database/sql` call and a span payload was not run. The unit path is the same function chain (`sql.go:45` -> `tainted.go:57`).
- Config-driven name/value redaction patterns and the 25,000-byte payload fallback are outside these fuzzers.
