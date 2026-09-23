# fx-crash-fuzz-redaction-F1: Oracle q-quote pre-scan desync leaks SQL literals

## Verdict per finding
- **crash-fuzz-redaction-F1: CONFIRMED.** Adjusted severity: **Critical**.
- **sink-redaction-sql-cmd-F1: CONFIRMED.** Adjusted severity: **Critical**. It is a duplicate of crash-fuzz-redaction-F1 and shares its root cause. Its own trigger, `SELECT '?q'[?]' suffix'`, is contrived, but realistic queries reach the same root cause.

The finder's mechanism is correct, with one precision it left out. The bogus span is kept only when the byte after the closing `<open>'` pair is not an identifier byte (`sql.go:141-143`). So `IN ('Q','R','S')` and `VALUES ('Q','u','s3cr3t')` do NOT leak. A leak needs the literal right after that pair to be empty or to start with punctuation or a space.

## Reproduction
All runs used a private copy of HEAD 2e23b46 with `GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6`. Evidence is in `.omo/review/evidence/fx-crash-fuzz-redaction-F1/`.

1. **Woven end-to-end with the DEFAULT redaction config** (my reproducer; this is the primary evidence).
   - Files:
     - `woven_zz_fx3_chain.go` is non-test application code: `"INSERT INTO tickets(state,prio,note,email) VALUES ('Q','1','" + note + "','" + email + "')"`.
     - `woven_zz_fx3_test.go` sends HTTP request parameters `note` and `email` through a woven `database/sql` `ExecContext`. It restores the default name/value patterns (copied from `config.go:38-39`).
   - Command: `cd iast/integration/testapp && /usr/bin/time -l go tool orchestrion go test -count=1 -timeout=20m -run TestFx3 -v .`
   - Output is in `woven_default_config.out.txt`. For note `(urgent) call me back`:
     - `sources=[{"origin":"http.request.parameter","name":"note","value":"(urgent) call me back"},{"origin":"http.request.parameter","name":"email","value":"jane.doe@example.com"}]`
     - `evidence=... {"value":"(urgent) call me back","source":0} ... {"value":"jane.doe@example.com","source":1} ...`
   - Control, note `urgent call me back` (same query, but the note starts with an identifier byte): both sources come out as `"redacted":true` patterns, and every literal body is starred.
   - One user-controlled leading `(` therefore un-redacts its own value AND a second, independent source later in the query.
   - The build peaked at 354 MB RSS, under the 4 GB threshold.
2. **Internal API** (my reproducer): `zz_fx3_test.go`, output in `unit_repro.out.txt`.
   - `LEAK inner-q status=0 qspans=["q'[?]'"] exposed=9/9` is the sink-redaction-sql-cmd shape, re-derived.
   - These did not leak: the `('Q','R','S')` IN-list, `VALUES ('Q','u','s3cr3tTok')`, `'faq'` (the `a` before the `q` is an identifier byte), a real `q'[x]'`, and the `'P'` controls. This confirms that the trigger is narrower than the finder's wording suggests.
3. **Finder reproducers**, re-run unchanged, fail exactly as reported: `exposedSecretBytes="hunter2"` for `('Q','R','')` and `('q','x','-')`, and `sourceValue="userSecret42"` for the end-to-end case.
4. An earlier run of this same node also left supporting files: `woven_repro.txt` and `matrix_repro.txt`. They show a woven `iast/database/sql/testapp` leak of `('Q','a','+33612','<email>')`, and 7 of 10 targeted shapes leaking, including `'/tmp'`, `'%x%'`, `' s3cr3t'` and `IN ('Q','A','')`.

## Reachability
Ordinary customer code triggers this under the default configuration:
- Redaction defaults to on (`internal/config/config.go:77`).
- `AnalyzeSQL` runs on every tainted `database/sql` sink report (`iast/database/sql/sql.go:44` -> `internal/vulnerability/tainted.go:57`).
- The query only has to be built with `+`, which is a supported propagation path.

The trigger has three conditions:
1. A literal whose last byte is `q`/`Q`, preceded by a non-identifier byte. The typical case is a one-letter code such as `'Q'`.
2. That literal is immediately followed by punctuation `P`. Typically `P` is `,`, as in compact `IN (...)` or `VALUES (...)` lists; `, ` with a space does not trigger.
3. The first later `P'` sequence is followed by a literal that is empty or starts with a space, `(`, `+`, `/`, `%`, `-`, `@` and so on.

Condition 3 is frequently user-controlled: free text, phone numbers, paths and LIKE patterns. An attacker can therefore force it and cause OTHER tainted values in the same query to be un-redacted, including values from headers or cookies whose names do not match the default name pattern. Non-tainted hard-coded literals in the evidence are exposed as well.

This is not a documented limitation. The README and 01-design-intent do not mention it, and the design treats SQL literal redaction as a guarantee. It breaks the redaction rule: sensitive data leaves the process on the span, both as wire source values and as evidence parts.

## Adjusted severity
Both findings are **Critical**. A raw request value leaves the process unredacted from valid SQL under the default configuration, which matches the brief's Critical definition. The narrow trigger lowers the likelihood but not the severity class.

The two findings share one root cause, so sink-redaction-sql-cmd-F1 is a duplicate of crash-fuzz-redaction-F1.

## Root cause (file:line)
- `internal/taint/redaction/sql.go:111-113`: `scanOracleQuotes` matches `q'`/`Q'` on raw bytes. Its only context check is the previous byte, and a `'` counts as non-identifier, so it has no notion of "inside an ordinary literal". The closer search at `:131-138` then takes the first `<close>'` pair anywhere.
- `sql.go:37-43`: every dialect, not only Oracle, lexes the segments left after the spans are cut out. Cutting inside a literal flips the lexer's quote parity: real code lexes as a string and gets over-redacted, while later literal bodies lex as identifiers and get no interval.
- `internal/taint/redaction/source.go:66`: a source is marked sensitive only when one of its parts overlaps an interval. With no interval, both the source value and the evidence part are emitted raw.
- `internal/taint/redaction/fuzz_test.go:46-54`: the fuzz oracle reuses `scanOracleQuotes`, so it is blind to this by construction.

## Minimal fix
1. Replace `scanOracleQuotes` with one stateful left-to-right scan that tracks `'...'` (including `''` and `\'`), `"..."`, `--` and `/* */` comments, and recognizes `q'` only in code context.
2. Apply the q-quote split only to the `DBMSOracle` pass; the other five dialects should lex the unsplit query.
3. Fail closed on the Oracle pass as well: also lex the unsplit query and take the union of both interpretations' intervals, or return `AnalysisDropped` if the two disagree on a literal boundary. This stays bounded at 2x the work.
4. Add the queries above as regression tests, and make the fuzz oracle independent of `scanOracleQuotes`.
