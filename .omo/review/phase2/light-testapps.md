# light-testapps: Nested testapp and integration-test quality
Verdict: No actionable findings in the reviewed scope; instrumented, shuffled, repeated tests and executable bootstrap checks passed.
Scope covered: All Go files, `go.mod`, `go.sum`, and bootstrap `symbols.txt` files under `iast/database/sql/testapp`, `iast/os/exec/testapp`, and `iast/integration/testapp`; `.github/workflows/ci.yml` bootstrap/test wiring.

## Findings
None.

## Checked and found correct
- The three nested modules' relative `replace github.com/DataDog/dd-iast-go` directives resolve to the private repository root, as confirmed by `go list -m -json`.
- All three nested `go.sum` files are byte-identical (SHA-256 `4629721fafeadf38095f209a335d9072abc2c8aed11e6180f5e116b1202fff21`); no inconsistent checksum churn was found.
- SQL tests assert sink counts and types, call-site locations, telemetry deltas, canceled-context behavior, argument-vs-query handling, retry behavior, panic preservation, and payload redaction. Integration-chain tests assert exact transformed values, byte ranges, source identity, secure marks, and sink evidence, with clean controls for SQL arguments and JSON reader chains.
- Command tests cover construction versus process-attempt boundaries, failed starts, redacted evidence, and payload encodings. JSON tests cover supported destinations, unsupported destinations, clean inputs, invalid input, custom and panicking unmarshalers, reader reuse, and exact body-source identity.
- The nested suites passed under Orchestrion with test shuffling and again with two shuffled repetitions. The SQL, exec, and integration executable bootstrap binaries all contained every symbol listed in their fixtures. CI also discovers nested Go modules and runs their instrumented tests, shuffled, followed by the symbol checks.

## Not covered / open questions
- This review did not assess production taint-tracking implementation outside the testapp scope.
- Race-detector runs, the complete CI coverage matrix, and toolchains other than Go 1.26.6 were not run.
