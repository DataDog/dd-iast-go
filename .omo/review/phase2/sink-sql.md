# sink-sql: database/sql injection sink instrumentation
Verdict: SQL sink behavior is correct in the exercised Go 1.26.6 and Go 1.27.0 paths; one significant checked-in regression-test gap remains.
Scope covered: `iast/database/sql/orchestrion.yml`, `sql.go`, `sql_test.go`, `testapp/sql_test.go`, `testapp/source_shape_test.go`, `internal/taint/sqlbridge/bridge.go` and its tests; Go 1.26.6 `database/sql/sql.go` public delegation paths; `internal/taint/evidence` collection and mark filtering, `internal/taint/request` lookup, and `internal/vulnerability` reporting/location.

## Findings
### sink-sql-F1: Missing persistent tests for delegated SQL calls and driver.Valuer
- Severity: Medium
- Category: test-gap
- Location: iast/database/sql/testapp/sql_test.go:63-100
- Claim: The checked-in integration matrix exercises the eleven context-method bodies but tests only `DB.QueryRowContext` among `QueryRow` delegations and does not exercise non-context `DB`/`Tx`/`Stmt` methods. The separate argument test passes a plain tainted string, not `driver.Valuer`; no checked-in case asserts that a Valuer returning tainted data or an error is evaluated once and is not query evidence. These paths currently work, but future toolchain/delegation changes can regress without the suite detecting them.
- Evidence: `.omo/review/evidence/sink-sql/review_sql_test.go` and `.omo/review/evidence/sink-sql/review-sql-output.txt`. Install the test beside `testapp/sql_test.go` in a private copy and run from `iast/database/sql/testapp`: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 10m -count=1 -run TestReviewSQL -v .`. Captured output includes `--- PASS: TestReviewSQLParameterValuerIsNotQueryEvidence`, `--- PASS: TestReviewSQLValuerErrorDoesNotChangeResultOrReport`, fourteen passing delegated-operation subtests, and `PASS`. The finding is the absence of these cases in the checked-in suite, not a failing runtime reproducer.
- Fix: Add the private test cases to the checked-in integration suite, including customer-frame location assertions; retain the existing per-boundary count checks.

## Checked and found correct
- `orchestrion.yml:47-117` instruments `PrepareContext` on DB/Conn/Tx and `ExecContext`/`QueryContext` on DB/Conn/Tx/Stmt. The Go 1.26.6 standard library delegates non-context methods and all `QueryRow` variants to those bodies; its internal retry/driver fallback does not enter another public boundary. The checked-in instrumented suite reports one finding per direct operation, two for prepare followed by statement execution, and one despite a driver retry.
- Prepared statements pass `Stmt.query`, not their `args`; bridge `Report` ignores inactive/invalid calls and catches callback panics. Existing tests establish nil-statement panic, driver panic, canceled-context result, and retry behavior. Private tests confirm non-context methods and `QueryRow` for DB, Conn, Tx, and Stmt report at the customer file with nonzero line numbers.
- `sql.go:34-49` collects provenance only for the query string. A private `driver.Valuer` returning tainted parameter data or an error ran once, preserved the SQL result/error, and generated zero findings for a clean query. `internal/taint/evidence/evidence.go:210-238` excludes ranges carrying the SQL-injection secure mark; `TestCollectionSuppressesFullyMarkedLiveSources` passes.
- Existing checks passed in the private copy: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 10m -count=1 -v ./...` in the nested SQL testapp; its full woven suite also passed on Go 1.27.0. Root-module `go test -timeout 10m -count=1 ./internal/taint/sqlbridge ./iast/database/sql ./internal/taint/evidence` passed. The extra private scenarios passed on both toolchains; captured output and test source are under `.omo/review/evidence/sink-sql/`.

## Not covered / open questions
- No live external database backend was used; the deterministic `database/sql/driver` fixture exercised conversion, retry, and error boundaries.
- Runtime creation of secure marks is not an advertised sanitizer feature. Verified the collector's SQL mark suppression using its existing internal test rather than an end-to-end sanitizer call.
- Documented plugin/non-root executable registration and post-owner-finish provenance limitations were not treated as defects.
