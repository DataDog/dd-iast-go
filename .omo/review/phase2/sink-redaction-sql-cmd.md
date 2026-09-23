# sink-redaction-sql-cmd: SQL and command evidence redaction
Verdict: Unsafe: the SQL Oracle q-quote pre-pass can expose a tainted SQL string literal unredacted; command argv redaction and analyzer bounds otherwise behaved as designed in the checked cases.
Scope covered: `internal/taint/redaction/{sql,command,analyzer,source}.go`; `internal/taint/redaction/{analyzer_test,fuzz_test,source_test}.go`; `iast/{database/sql,os/exec}/{sql,exec}.go`; both sink `orchestrion.yml` files; `internal/vulnerability/tainted.go`; `github.com/DataDog/go-sqllexer@v0.2.4`; sibling Java and Python SQL/command analyzers.

## Findings
### sink-redaction-sql-cmd-F1: Oracle q-quote pre-pass can leak a later SQL literal
- Severity: Critical
- Category: redaction
- Location: internal/taint/redaction/sql.go:27-42,108-156
- Claim: `scanOracleQuotes` searches raw bytes without lexical context, then `AnalyzeSQL` removes every matched q-quote span before sending the remaining pieces to each dialect lexer. A `q'…'` byte sequence inside another quoted literal can therefore consume the first literal's closing quote and a later literal's opening quote. The split fragments tokenize as incomplete/non-literal text and leave the later literal body outside `Sensitive`. `BuildWithSensitive` then preserves the tainted source value and evidence part raw, so sensitive data can leave the process despite redaction being enabled.
- Evidence: `.omo/review/evidence/sink-redaction-sql-cmd/malformed_oracle_quote_test.go` + `.omo/review/evidence/sink-redaction-sql-cmd/malformed_oracle_quote.out.txt`; exact command: `cd /tmp/ddiast-review/wt/sink-redaction-sql-cmd && env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test -count=1 -timeout=15m ./internal/taint/redaction -run '^TestReviewMalformedLiteralContainingOracleQuoteDoesNotExposeSuffix$'`; captured output includes `masked="SELECT '?q'[?]' suffix'"` and `source-redacted=false source-value="suffix"`.
- Fix: Replace the raw-byte Oracle pre-pass with a stateful, non-destructive lexer pass that recognizes q-quoted literals only while outside ordinary strings and comments. On an ambiguous or malformed quote boundary, return `AnalysisDropped` so the existing full-redaction fallback is used. Add the reproducer as a permanent regression test.

### sink-redaction-sql-cmd-F2: SQL fuzz oracle repeats the pre-pass it is meant to test
- Severity: Medium
- Category: test-gap
- Location: internal/taint/redaction/fuzz_test.go:34-68
- Claim: `assertDefaultSQLLiteralsCovered` first calls `scanOracleQuotes` and checks lexer output only on the resulting split segments. It therefore uses the same destructive partitioning as `AnalyzeSQL` and cannot assert that literals in the original SQL stream remain covered. The F1 reproducer passes that fuzz oracle's structural premise while leaking `suffix`.
- Evidence: static reasoning only (NEEDS-REPRO); F1's captured reproducer demonstrates the missed semantic case, and a 30-second `FuzzAnalyzeSQL` run completed without detecting it.
- Fix: Make the fuzz oracle independent of `scanOracleQuotes`; for example, use a reference state machine over the original query that tracks ordinary quotes/comments and Oracle q-quotes, then require every literal body it identifies to be fully covered. Seed F1 directly.

## Checked and found correct
- `AnalyzeCommand` rejects more than 256 argv entries and computes joined length before `strings.Join`; at its 32-KiB bound the subsequent `uint32` offsets cannot overflow. `TestAnalyzeCommand` and `TestAnalyzeCommandBounds` passed in the private copy.
- Command redaction intentionally preserves argv[0], plus one argv element for `sudo`/`doas`, and redacts the remainder. This matches the Java `CommandRegexpTokenizer` and Python command analyzer policy; paths and multibyte argument byte offsets are handled by the argv join rather than shell-token parsing.
- SQL scan segments reject lexer errors, empty/noncontiguous tokens, and EOF before the segment is fully consumed. Those guards prevent token-value slicing outside the segment; input, token, and interval limits route to the caller's full-redaction fallback.
- Existing SQL literal/bounds tests passed. A 30-second bounded `FuzzAnalyzeSQL` run with two workers completed without a panic or out-of-bounds interval; this does not mitigate F1 because its oracle has the F2 blind spot.
- The checked `go-sqllexer` version has explicit SQL Server/Oracle backslash handling and multibyte/truncated-UTF-8 tests. `AnalyzeSQL` retains byte offsets, which are the offset unit used by evidence parts.
- Java's `SqlRegexpTokenizer` recognizes Oracle q-literals in its dialect-specific pattern while retaining the generic single-quoted branch; the malformed boundary in F1 consequently still redacts the later ordinary literal rather than splicing it out. Python's regex analyzer is less complete for Oracle q-literals, but neither sibling uses this raw-byte span deletion strategy.

## Not covered / open questions
- SQL comments are intentionally left visible by the current analyzer test suite. A separate review node is examining comment-body policy, so this report does not duplicate that assessment.
- No complete woven application was run: this review exercised the pure redaction package and traced the sink-to-`BuildWithSensitive` call path. The redaction defect is reproducible before weaving and does not depend on database or process execution.
