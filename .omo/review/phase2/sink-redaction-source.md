# sink-redaction-source: source and value redaction
Verdict: Critical - three independent redaction paths serialize attacker-controlled secrets despite redaction being enabled by default.
Scope covered: `internal/taint/redaction/{source,analyzer,sql,command}.go`; their unit/fuzz/overflow tests; `internal/config/{config,parser,loader}.go`; `internal/{vulnerability,spans}/{tainted,payload,orchestrion}.go`; source-model serialization and the relevant README configuration.

## Findings
### sink-redaction-source-F1: Deterministic redaction pattern can equal the secret
- Severity: Critical
- Category: redaction
- Location: internal/taint/redaction/source.go:110-115,213-214,299-303
- Claim: A source selected for redaction gets `alphanumericPattern(len(value))`, a fixed `abcdefghijklmnopqrstuvwxyz...` sequence. For a valid secret such as password value `abc`, both the source and evidence `pattern` serialize exactly `abc`, so the raw secret leaves in the event even though `redacted=true`.
- Evidence: `.omo/review/evidence/sink-redaction-source/review_pattern_and_name_leak_test.go` run with the command captured in `.omo/review/evidence/sink-redaction-source/default-redaction-leaks.out.txt`; key output: `"pattern":"abc","redacted":true` for source name `password`.
- Fix: Replace the reversible fixed alphabet pattern with a non-content-derived mask (for example, `*` repeated to the retained byte length) for both source and evidence patterns; retain only length/truncation metadata, never source bytes.

### sink-redaction-source-F2: Sensitive source names are serialized unchanged
- Severity: Critical
- Category: redaction
- Location: internal/taint/redaction/source.go:107-115; internal/model/source.go:33-40
- Claim: `sourceSensitive` classifies a source by its name, but `NewSourceRedactedString` receives and serializes that same unredacted name. A user-controlled HTTP parameter key `token:abcdefghijklm` matches the default name policy, yet that credential-shaped value is emitted as the wire source `name`.
- Evidence: `.omo/review/evidence/sink-redaction-source/review_pattern_and_name_leak_test.go` run with the command captured in `.omo/review/evidence/sink-redaction-source/default-redaction-leaks.out.txt`; key output: `"name":"token:abcdefghijklm","pattern":"abcdefg","redacted":true`.
- Fix: Keep the complete name only in the private `spans.SourceIdentity` sidecar for deduplication. When source-name matching causes redaction, omit or safely mask `model.Source.Name` before event serialization.

### sink-redaction-source-F3: SQL comments bypass vulnerability-specific redaction
- Severity: Critical
- Category: redaction
- Location: internal/taint/redaction/sql.go:82-100; internal/taint/redaction/analyzer_test.go:30
- Claim: `AnalyzeSQL` marks strings, numbers, booleans, NULLs, and dollar-quoted values, but not line or block comments. A tainted HTTP value placed in a SQL comment is neither matched by the built-in name/value patterns nor classified by the analyzer, so the raw source and raw evidence are sent in the vulnerability event. The existing test explicitly expects comment contents to remain visible.
- Evidence: `.omo/review/evidence/sink-redaction-source/review_sql_comment_leak_test.go` run with the command captured in `.omo/review/evidence/sink-redaction-source/default-redaction-leaks.out.txt`; key output contains both `"value":"hunter2"` source metadata and `"value":"hunter2","source":0` evidence for `SELECT 1 -- hunter2`.
- Fix: Treat SQL line/block comment token bodies as sensitive for every dialect; if a lexer cannot classify a comment safely, return `AnalysisDropped` so `ReportTainted` performs its existing full-redaction fallback.

## Checked and found correct
- Redaction is enabled by default; malformed configured regular expressions fall back to the built-in patterns. Go's RE2 engine avoids catastrophic backtracking (`internal/config/config.go:77-79`, `internal/config/parser/parser.go:49-51`, `internal/config/loader/loader.go:79-103`).
- Non-OK analyzer status causes full redaction before a report is committed (`internal/vulnerability/tainted.go:48-57`), and invalid sensitive intervals reject the result.
- Partial sensitive intervals split literal evidence safely; when the part cap would overflow, `BuildWithSensitive` retries with complete redaction. `TestSensitiveIntervalsOverflowRedactsCompleteEvidence` passed.
- Raw `spans.SourceIdentity` values are retained in a bounded, in-process annotation sidecar for deduplication; only the associated `model.Source` goes to MessagePack/JSON payload encoding (`internal/spans/tainted.go:123-160`, `internal/spans/orchestrion.go:40-54`).
- Focused existing tests passed in the private copy: `go test ./internal/taint/redaction ./internal/spans ./internal/vulnerability -run '^(TestBuild|TestAnalyze|TestSensitive|TestLiteral|TestMapped|TestAlphanumeric|TestMark|TestCanonical|TestTryCommitTainted|TestReportTainted|TestPayload)' -count=1 -timeout 15m`.

## Not covered / open questions
- I did not load-test maximum-size administrator-supplied regular expressions. RE2 removes backtracking risk, but configuration compilation has no application-level pattern-size limit.
- The reproducer serializes the exact event wire model as JSON; the production MessagePack path serializes the same `model.Event` fields and was inspected, but an end-to-end woven SQL sink was not needed to prove the redaction output.
