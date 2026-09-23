# fx-crash-hostile-input-F1: verification of "SQL comment bodies are never redacted"

## Verdict per finding

**crash-hostile-input-F1 — CONFIRMED** (original severity Critical; adjusted severity **Critical**).
The claimed mechanism is real at HEAD 2e23b46, I reproduced it independently at three levels (lexer mechanism, unit analyzer, woven end-to-end), it is reachable under default configuration on Go 1.26.6, it is not a documented limitation, and it directly violates the "sensitive data leaving the process unredacted" product rule.

## Reproduction

All commands run in the private copy `/tmp/ddiast-review/wt/fx-crash-hostile-input-F1` (now removed). Evidence copied to `.omo/review/evidence/fx-crash-hostile-input-F1/`.

1. **Unit reproducer (mine)** — `fx_comment_leak_test.go`, command:
   `GOTOOLCHAIN=go1.26.6 go test -count=1 -run 'TestFx' -v ./internal/taint/redaction/` → `fx-redaction-unit.log`
   - Mechanism test PASSES: across all 6 `sqlDialects`, go-sqllexer emits `COMMENT` / `MULTILINE_COMMENT` tokens whose value carries the secret, proving the tokens reach `sqlSensitiveToken` and fall into its `default` branch.
   - Redaction test FAILS on all 4 shapes; canonical exploit key line:
     `masked evidence: "SELECT * FROM Users WHERE email = '' OR ? --' AND password = '81dc9bdb52d04dc20036dbd8313ed055' AND deletedAt IS NULL"` with `intervals=[{40 4}]` (only the `TRUE` literal is sensitive; the entire comment tail is uncovered).
   - Bonus inconsistency beyond the finding: in a `#` line comment the leading digit of the hash is masked as a NUMBER (`SELECT col # ?dc9bdb...`) while the rest leaks — the leak is not even consistent.
   - The finder's own `hostile_comment_repro_test.go` output (`redaction-comment-test.log`) matches mine exactly (`intervals=[{40 4}]`); I did not need to re-run it.

2. **Woven end-to-end reproducer (mine)** — `fx_exploit.go` (woven library package `testapps/integration`) + `fx_comment_leak_e2e_test.go`, command:
   `cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -count=1 -run 'TestFx' -v -timeout 15m .` → `fx-e2e-woven.log`
   Realistic surface: woven `net/http` + `net/url` sources, woven root-library string concatenation, `database/sql` sink hook (`ExecContext`), mocktracer span, event payload read back from the span tag. Both tests FAIL (leak confirmed). Key captured parts:
   - `part: {Value:' AND password = '81dc9bdb52d04dc20036dbd8313ed055' AND deletedAt IS NULL Redacted:false ...}`
   - `part: {Value:' /* token='81dc9bdb52d04dc20036dbd8313ed055' */ Redacted:false ...}`
   The tainted source part itself IS redacted (`Pattern:abcdefghijkl Redacted:true`); only the application-owned comment content leaks — exactly as claimed. Build: ~29 s reusing the earlier woven cache (~231 s cold, peak RSS ≈ 365 MB, `/usr/bin/time -l` peak footprint ≈ 40 MB — no build-memory concern).
   - Note: a first e2e attempt with the concatenation written inside the `_test.go` file produced zero findings — the injector's root filter excludes the test package (`chains.go` documents this), so taint was dropped before the sink. Moving the query construction into the woven library package fixed the harness; the failure was in my harness, not a refutation.

3. **Cross-tracer corpus (normative expectation)** — verified directly:
   - `dd-trace-js/packages/dd-trace/test/appsec/iast/vulnerability-formatter/resources/evidence-redaction-suite.json`: "Query with line comment", "Query with block comment", and "SQLi exploited" (the exact `81dc9bdb...` case) all expect the comment body as `{redacted: true}` with `--`/`/*`/`*/` delimiters visible.
   - `dd-trace-java/dd-java-agent/agent-iast/src/test/resources/redaction/evidence-redaction-suite.yml`: identical three cases with identical expectations.

## Reachability

- **Default config**: `DD_IAST_ENABLED` defaults to true, `DD_IAST_REDACTION_ENABLED` defaults to true (`internal/config/config.go:73,77`). The default value pattern (`bearer`/`glpat-`/`gh[opsu]_`/JWT/PEM, `config.go:39`) cannot match a plain password hash, and it applies to source values only — the leaked bytes are application-owned comment content that no pattern path touches. The finder's woven-app run with default patterns leaked identically (`spans-woven.json`).
- **Supported toolchain**: reproduced woven on Go 1.26.6 (`GOTOOLCHAIN=go1.26.6`). The gap is pure library logic (`sqlSensitiveToken`), toolchain-independent; Go 1.27.0 is not plausibly different and was not separately needed.
- **Trigger**: any SQLi report whose query contains a comment — canonically the attacker injects `--` (or `/*`), turning the application-owned rest of the query (password literals, etc.) into a comment that ships in clear in the span `_dd.iast.json` payload. Ordinary customer code + an attacker-supplied query parameter suffice.
- **Documented limitation?** No. README documents redaction as enabled and does not exempt comments; `phase1/01-design-intent.md` records corpus validation against the normative shared corpus as a *pending* item ("the RFC-derived redaction corpus must be replaced or validated against the normative shared corpus"), i.e. a known-unvalidated area, not an accepted trade-off. The pinning test `internal/taint/redaction/analyzer_test.go:30` (`comments` case expects `SELECT column -- secret` unredacted) contradicts the normative corpus — it pins the bug, it does not document an accepted limitation.

## Adjusted severity

**Critical** — unchanged. "Sensitive data leaving the process unredacted" is the brief's Critical definition, and the leak is in the canonical exploit shape the product exists to detect, under default configuration. The evidence payload (span meta-struct) leaves the process to the Datadog backend with the application's password literal in clear.

## Root cause

`internal/taint/redaction/sql.go:83-100` — `sqlSensitiveToken` handles STRING, INCOMPLETE_STRING, DOLLAR_QUOTED_STRING/FUNCTION, NUMBER, BOOLEAN, NULL; `sqllexer.COMMENT` and `sqllexer.MULTILINE_COMMENT` fall to `default: return Interval{}, false`, so comment bodies never become sensitive intervals and are emitted verbatim in evidence valueParts. Pinned (not caused) by `internal/taint/redaction/analyzer_test.go:30`.

## Minimal fix

In `sqlSensitiveToken`, add cases for `sqllexer.COMMENT` and `sqllexer.MULTILINE_COMMENT` that redact the comment body while keeping the delimiters visible, matching the shared corpus: for `--`/`#` comments mark from just after the introducer to the token end; for `/* ... */` mark the bytes between `/*` and `*/` (emit `/*`, redacted body, `*/` as separate parts, as java/js do). Replace the `analyzer_test.go:30` "comments" expectation with the shared-corpus expectations, and run the suite against the normative `evidence-redaction-suite.json`/`.yml` corpus as the plans already require.
