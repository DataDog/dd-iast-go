# fx-sink-redaction-source-F1: verification of sink-redaction-source-F1 (deterministic redaction pattern can equal the secret)

Verdict per finding: **sink-redaction-source-F1: CONFIRMED** (adjusted severity **Critical**).

Scope covered: `internal/taint/redaction/source.go` (all of `BuildWithSensitive`, `buildWireSources`, `buildParts`, `buildPart`, `mappedPattern`, `alphanumericPattern`, `sourceSensitive`), `internal/model/source.go`, `internal/config/config.go` (default redaction config), `internal/vulnerability/tainted.go`, `internal/spans/orchestrion.go`, `iast/propagation/orchestrion.yml` (operator join points), `iast/integration/testapp` e2e harness; independent unit reproducer (default config, internal API) and an independent woven e2e reproducer (orchestrion, Go 1.26.6, HTTP source → concatenation → `database/sql` sink).

## Verdict per finding

### sink-redaction-source-F1 — CONFIRMED, Critical
The claimed mechanism is real at HEAD 2e23b46:

- `internal/taint/redaction/source.go:110` — for every source selected as sensitive, the wire source is `model.NewSourceRedactedString(origin, name, alphanumericPattern(len(value)))`.
- `internal/taint/redaction/source.go:295-303` — `alphanumericPattern(n)` returns the **fixed** alphabet `"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"` cycled to length n. For a secret of length n that *is* an alphabet prefix (e.g. `"abc"`), the "redacted" pattern is byte-for-byte the secret.
- `internal/taint/redaction/source.go:213-214` + `mappedPattern` (`source.go:279-293`) — evidence parts referencing a sensitive source take `sourcePattern[offset:offset+len(value)]`, an alphabet window. When the tainted substring equals that window (again e.g. `"abc"`), the evidence part pattern is the raw secret. `mappedPattern` also discloses the secret's exact byte offset within the source value and its length for *any* secret (structural leak, minor).

No check anywhere compares the pattern to the value it replaces. `model.NewSourceRedactedString` (`internal/model/source.go:33-40`) serializes `Pattern` verbatim into the wire `Source`; `model.ValuePart.Pattern` likewise. Both JSON and MessagePack codecs serialize the same fields.

Independently reproduced at two levels (see Reproduction). The serialized event contains `"pattern":"abc"` — the actual password — with `"redacted":true`, for both the source and the evidence part.

## Reproduction (commands + key output lines)

1. **Unit / internal API with the real default configuration** (default `DD_IAST_REDACTION_*` built-ins loaded by package init, env cleared):
   `cd /tmp/ddiast-review/wt/fx-sink-redaction-source-F1 && env -u DD_IAST_REDACTION_ENABLED -u DD_IAST_REDACTION_NAME_PATTERN -u DD_IAST_REDACTION_VALUE_PATTERN -u DD_IAST_REDACTION_KEYS_REGEXP -u DD_IAST_REDACTION_VALUES_REGEXP GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test ./internal/taint/redaction -run TestFXPatternMustNotReproduceSecret -count=1 -v -timeout 15m`
   Key output:
   ```
   LEAK model.Source.Pattern == secret: model.Source{Origin:0x1, Name:"password", Value:"", Pattern:"abc", Redacted:true, ...}
   LEAK evidence ValuePart.Pattern == secret: model.ValuePart{Pattern:"abc", Redacted:true, ...}
   LEAK serialized event contains the raw secret: {"sources":[{"origin":"http.request.parameter","name":"password","pattern":"abc","redacted":true}],"vulnerabilities":[...{"pattern":"abc","redacted":true,"source":0}...]}
   ```
2. **Woven e2e (most realistic surface)**: orchestrion-woven testapp, real HTTP request `?password=abc` → `r.URL.Query().Get("password")` → string concatenation (non-test package file) → `db.PrepareContext` + `stmt.ExecContext`, span finish → serialized event (peak build RSS 366 MB, well under the 4 GB finding threshold):
   `cd /tmp/ddiast-review/wt/fx-sink-redaction-source-F1/iast/integration/testapp && env -u ... GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -run TestFXPasswordPatternLeakE2E -count=1 -v -timeout 15m .`
   Key output:
   ```
   password tainted: true
   query tainted: true
   LEAK redacted model.Source.Pattern equals the secret: model.Source{Name:"password", Pattern:"abc", Redacted:true}
   LEAK redacted evidence ValuePart.Pattern equals the secret: model.ValuePart{Pattern:"abc", Redacted:true, SourceIndex:0}
   LEAK serialized event contains the raw password: {"sources":[{"name":"password","pattern":"abc","redacted":true}],"vulnerabilities":[{"type":"SQL_INJECTION",...{"pattern":"*****","redacted":true},{"value":"' WHERE pw = '"},{"pattern":"abc","redacted":true,"source":0},...
   ```
   Note the contrast inside one event: the sink-literal interval is masked `"*****"` while the source-linked part carries the raw `"abc"`.
   Evidence: `.omo/review/evidence/fx-sink-redaction-source-F1/{unit-default-config-pattern-leak.out.txt, woven-e2e-pattern-leak.out.txt, fx_repro_test.go, fx_pattern_leak_test.go, fxhelper.go}`. The finder's own reproducer output (`default-redaction-leaks.out.txt`) is consistent with mine; I did not rely on it.

## Reachability

- **Default configuration**: yes. Redaction is enabled by default with the built-in name/value patterns (`internal/config/config.go:77-79` load defaults; verified live in the unit reproducer where `RedactionNamePattern.MatchString("password")` is true with no env overrides). A source merely needs a sensitive-shaped **name** (password, token, secret, key, …) — the value's content is irrelevant to selection.
- **Supported toolchain**: yes — woven build and test ran on Go 1.26.6 (`GOTOOLCHAIN=go1.26.6`) exactly as targeted.
- **Ordinary customer code**: yes — any woven app that reads a request parameter named e.g. `password` whose value flows into a SQL/command sink. The 30% default request sampling only reduces frequency, not reachability.
- **Precondition for the content leak**: the secret (or the tainted substring, via `mappedPattern`) must equal a window of the fixed alphabet — e.g. `"a"`, `"ab"`, `"abc"`, … `"abcdefghij"` (62 prefixes plus cyclic extensions). This is a narrow but real class: it includes the most common weak passwords (`abc` is a top-10 password), so test/staging credentials genuinely leak. For arbitrary secrets the pattern leaks no content, only length (and, via `mappedPattern`, the secret's exact offset inside the source value).
- **Documented limitation?** No. The README documents `DD_IAST_REDACTION_ENABLED` default `true` and states evidence is "redacted before leaving the process"; `phase1/01-design-intent.md` lists no redaction-pattern trade-off. The repo's own tests (`TestMappedPattern`, `TestAlphanumericPattern`) assert the alphabet-window behavior but never test collision with the value, so the collision is unconsidered, not deliberate. This breaks the redaction product rule ("sensitive data leaving the process unredacted").

## Adjusted severity

**Critical** (unchanged). The actual secret bytes leave the process verbatim in the vulnerability event under default configuration on the supported toolchain; the alphabet-prefix precondition narrows but does not eliminate the class of leaked credentials (confirmed with the common password `abc` at both the unit and woven e2e level).

## Root cause (file:line)

One root cause shared by both leak sites: the redaction mask is a **fixed, content-independent alphabet sequence that can collide with the content it replaces**.
- `internal/taint/redaction/source.go:295-303` — `alphanumericPattern` (the fixed alphabet);
- used at `source.go:110` for `model.Source.Pattern`;
- sliced at `source.go:213-214` via `mappedPattern` (`source.go:279-293`) for evidence `ValuePart.Pattern`.

Not a duplicate of phase-2 F2 (unredacted source **name** serialization — different mechanism at `source.go:107-115`/`model.Source.Name`) or F3 (SQL comment analyzer coverage at `redaction/sql.go:82-100`); those are independent root causes in the same feature. F1 is the single root cause of both the source-pattern and evidence-part-pattern leak.

## Minimal fix

Replace the reversible alphabet with the non-content mask already used for source-less redacted parts (`strings.Repeat("*", n)`, cf. `source.go` `buildPart` `part.Source < 0` branch):
- at `source.go:110`, pass `strings.Repeat("*", len(source.Value))` (or a fixed opaque token) instead of `alphanumericPattern(len(source.Value))`;
- in `buildPart`/`mappedPattern`, return the `"*"` mask (retaining only length/truncation metadata) instead of an alphabet window, which also removes the offset disclosure.

`alphanumericPattern` can then be deleted. Existing tests (`TestMappedPattern`, `TestAlphanumericPattern`, fuzz corpus) need updating to the new expectation.

## Checked and found correct / notes

- `mappedPattern`'s ambiguity, budget, and bounds guards work as designed; the fallback mask `"*"` is correct — the leak is only which string is used as the *pattern source*.
- Full-redaction fallback, interval splitting, overflow retry, and the `MAX_SIZE_EXCEEDED` path are unrelated to this finding.
- Observation (out of scope, for the record): the `+` operator propagation join point did **not** apply inside the external `_test` package file of the woven testapp (concat in the test file stayed untainted; concat in a non-test package file propagated). The repo's own e2e tests route concatenation through non-test package files (`chains.go`), so this may be expected orchestrion behavior for test packages; flagged for the orchestrion-coverage reviewers, not counted against F1.

## Not covered / open questions

- Whether the Datadog backend applies any secondary masking to event payloads (out of process; the in-process product rule is violated regardless).
- Cross-language "pattern" redaction semantics (dd-trace-java/js use different representations) — not needed for the verdict.
