# light-config: Configuration parsing and documentation
Verdict: Configuration parsing, fallback, and clamping behavior are correct in the reviewed scope, with one README range omission.
Scope covered: `internal/config/config.go`, `internal/config/init.go`, `internal/config/parser/parser.go`, `internal/config/loader/loader.go`, their config/parser/loader tests, `internal/spans/annotation.go` observer initialization, README runtime configuration table, and relevant phase-1 review notes. Ran `go test -timeout 15m ./internal/config/...` in the private review copy.
## Findings
### light-config-F1: README omits the vulnerability limit maximum
- Severity: Medium
- Category: doc
- Location: README.md:117
- Claim: The README says `DD_IAST_VULNERABILITIES_PER_REQUEST` accepts any integer greater than or equal to 1, but `internal/config/config.go:75` clamps it to the inclusive range 1–64 (`MaxVulnerabilitiesPerRequest`). This misstates the accepted range and the effective value for inputs above 64.
- Evidence: static reasoning only
- Fix: Document the accepted range as 1–64, matching the loader clamp.
## Checked and found correct
- Boolean settings use `strconv.ParseBool`; malformed values warn and use the configured defaults.
- Unsigned integer settings parse base-10 `uint64`; malformed, negative, and overflowing values use defaults. Bounded settings clamp valid out-of-range values and warn. The configured bounds for request sampling (0–100), concurrent requests (0–64), vulnerabilities per request (1–64), and range count (1–64) agree with implementation.
- Telemetry verbosity accepts only the documented case-sensitive `OFF`, `MANDATORY`, `INFORMATION`, and `DEBUG` values. Invalid levels fall back to `INFORMATION`.
- Redaction patterns are compiled as Go regular expressions. Invalid patterns use the built-in defaults; an empty but valid pattern is accepted. Canonical pattern variables take precedence when set, and the compatibility aliases are consulted only when the corresponding canonical variable is unset, as README describes.
- README defaults and behavior for the remaining runtime settings match `config.go`; the two aliases are explicitly named in their canonical rows.
- `config.Observe` replays the initialization-time settings and warnings, and `internal/spans/annotation.go` consumes those observations to register telemetry and start the product when enabled.
- The focused config, loader, and parser tests passed in the private review copy.
## Not covered / open questions
- No full-repository test suite was run; this review was limited to configuration parsing, loading, initialization, and README consistency.
