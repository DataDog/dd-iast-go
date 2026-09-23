# fx-sink-redaction-source-F2: verification of "Sensitive source names are serialized unchanged"

Verdict: CONFIRMED as a mechanism, but the Critical rating is overstated; adjusted to Medium.

Scope covered: `internal/taint/redaction/source.go` (BuildWithSensitive, buildWireSources,
sourceSensitive, mappedPattern), `internal/model/source.go`, `internal/config/config.go`
(default patterns), `internal/taint/request/{http,lazy}.go` (source-name construction for
headers/parameters/cookies), `internal/spans/{payload,orchestrion}.go` (wire encodings), README
redaction documentation, and cross-language IAST redaction semantics in the dd-trace-java,
dd-trace-js, and dd-trace-py sibling clones.

## Verdict per finding

### sink-redaction-source-F2 — CONFIRMED (severity adjusted Critical → Medium)

1. **Mechanism at HEAD 2e23b46 — real.** `internal/taint/redaction/source.go:107-115`:
   when `sensitive[index]` is true, `buildWireSources` calls
   `model.NewSourceRedactedString(source.Origin, source.Name, alphanumericPattern(len(source.Value)))`
   — the value is replaced by a pattern, but `source.Name` is passed through verbatim.
   `internal/model/source.go:33-40` stores that name unchanged in the serialized `Source.Name`
   field (`msg:"name,omitempty"`). The name is exactly the string that `sourceSensitive`
   (source.go:299-303) matched against `DD_IAST_REDACTION_NAME_PATTERN`.

2. **Reproduced independently, twice** (details below):
   - internal API: public `taint.TaintString` with a named parameter source →
     `evidence.CollectString` → `redaction.BuildSources` → `model.Event` encoded with the
     **production MessagePack encoder** (`MarshalMsg`, the `spans.Finished` meta-struct path).
   - woven build (`go tool orchestrion`, Go 1.26.6): real HTTP request with query key
     `token:abcdefghijklm` → lazy parameter source → `database/sql` prepare+exec sinks →
     event captured from the finished span's `_dd.iast.json` tag.

   The default configuration classifies the source as sensitive (`token` matches the built-in
   name pattern) and replaces its value, yet serializes `name:"token:abcdefghijklm"` raw — the
   exact shape the built-in value pattern (`token:[a-z0-9]{13}`) exists to catch.

3. **Reachability.** Yes, under default configuration and a supported toolchain, via ordinary
   woven customer code: any sampled request in which a client-controlled *key* (query parameter
   key, header name, cookie name — all fully client-controlled, see `request/lazy.go:163-220`,
   `request/http.go:97-155`) is credential-shaped and whose value reaches a SQL/command sink.
   Corroborating variants captured in this node's evidence dir by an earlier parallel run of
   the same node: a GitHub PAT (`ghp_…`) as a query key and a JWT as a header name both leak
   through `http.request.parameter.name` / `http.request.header.name` sources (for those
   origins the source *value* is the key itself, so the value pattern redacts the value while
   the identical name string still serializes).

4. **Documented limitation / product-rule analysis.**
   - Not documented: the README describes `DD_IAST_REDACTION_NAME_PATTERN` as the pattern "used
     to identify source names that must be redacted"; nothing states names are exempt from
     redaction, so this is not a README-documented limitation.
   - However, keeping the name is the **deliberate, uniform product-family design**: Java
     (`dd-trace-java .../iast/model/json/SourceAdapter.java:75-80` writes `source.getName()`
     verbatim for redacted sources), JS (`sensitive-handler.js` + `vulnerabilities-formatter/
     index.js:31-33` deletes only `source.value`), and Python (`_sensitive_handler.py` +
     `reporter.py:361-363` sets `source.value = None`, keeps `name`) all redact the value and
     keep the name. Source names are the actionable metadata of a vulnerability report
     ("which parameter was tainted"); masking all names would gut the report.
   - The strict redaction guarantee ("credential-shaped strings never leave the process") *is*
     bypassed through the name field, which weakly breaks the "sensitive data leaves unredacted"
     product rule — but only for strings a client placed in a key/name position. End-user and
     server-held secrets travel in source *values*, which are redacted. This is why the
     Critical rating (whose bar is "sensitive data leaving the process unredacted") is
   overstated: the leaked bytes are attacker-chosen, attacker-supplied request structure, in
     the rare shape of a credential.

## Reproduction (commands + key output)

Internal API (evidence: `evidence/fx-sink-redaction-source-F2/internal-api-run.out.txt`,
test: `evidence/fx-sink-redaction-source-F2/fx_name_leak_test.go`):

```
cd /tmp/ddiast-review/wt/fx-sink-redaction-source-F2 && env -u DD_IAST_REDACTION_ENABLED \
  -u DD_IAST_REDACTION_NAME_PATTERN -u DD_IAST_REDACTION_VALUE_PATTERN \
  -u DD_IAST_REDACTION_KEYS_REGEXP -u DD_IAST_REDACTION_VALUES_REGEXP \
  GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test ./internal/taint/redaction \
  -run TestFxSensitiveSourceNameSerializedUnredacted -count=1 -timeout 15m -v
```
Key output: `LEAK (MessagePack meta-struct path): credential-shaped source name serialized
unredacted: "\x82\xa7sources\x91\x84\xa6origin\xb6http.request.parameter\xa4name\xb3token:abcdefghijklm
\xa7pattern\xa8abcdefgh\xa8redacted..."` (test fails by design on detection).

Woven build (evidence: `evidence/fx-sink-redaction-source-F2/woven-run.out.txt`,
test: `evidence/fx-sink-redaction-source-F2/fx_name_leak_woven_test.go`):

```
cd /tmp/ddiast-review/wt/fx-sink-redaction-source-F2/iast/integration/testapp && \
  env -u DD_IAST_REDACTION_* ... GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 \
  /usr/bin/time -l go tool orchestrion go test . \
  -run TestFxSensitiveSourceNameLeavesProcessUnredacted -count=1 -timeout 15m -v
```
Key output: `LEAK: credential-shaped source name left the process unredacted:
{Origin:http.request.parameter Name:token:abcdefghijklm Value: Pattern:abcdefgh Redacted:true
Truncated:}` — captured from the finished span after a real HTTP request whose query key
`token:abcdefghijklm` value reached `database/sql` prepare+exec sinks. Peak RSS 366 MB
(no build-time memory finding).

(The testapp package init in `e2e_test.go` overrides the built-in patterns with `never-match`;
my woven test restores the documented defaults from `internal/config/config.go` verbatim inside
the test and restores `never-match` on cleanup.)

## Adjusted severity

**Medium** (was Critical). The mechanism is real and default-reachable, but the only data that
can leak through this path is client-controlled key/name structure (an attacker exfiltrating
their own token shape to the backend), never user or server secrets, which live in values and
are redacted; and keeping names is the deliberate cross-language IAST design. It is a genuine
narrow bypass of the redaction contract that should be fixed (a credential-shaped name leaves
with `redacted:true`), i.e. an incorrect edge case with limited impact.

## Root cause (file:line)

`internal/taint/redaction/source.go:110-111` (`buildWireSources`: `NewSourceRedactedString(
source.Origin, source.Name, ...)`) together with `internal/model/source.go:36-40`
(`NewSourceRedactedString` stores `name` verbatim). Duplicate relationship: F2 shares its root
cause with sink-redaction-source-F1 — the same `buildWireSources`/`NewSourceRedactedString`
call site decides what a "redacted" wire source retains (F1: a content-derived pattern that can
equal the secret; F2: the unredacted name). One root cause, two serialized fields. F3 (SQL
comment analyzer coverage, `redaction/sql.go`) is unrelated.

## Minimal fix

In `buildWireSources` (source.go:107-115): keep the full name only in the private
`spans.SourceIdentity` sidecar (already retained for deduplication), and when the *name itself*
matches the redaction value pattern (i.e., the name is credential-shaped), mask or omit the wire
`model.Source.Name` (e.g., replace with `strings.Repeat("*", len(name))` or a fixed tag such as
`"<redacted>"`). Masking only credential-shaped names preserves the actionable "which parameter
was tainted" metadata for ordinary names (`password`, `token`, `Authorization`) exactly as Java/
JS/Python IAST emit today, while closing the bypass for names that carry secret material.

## Checked and found correct

- The source *value* redaction itself works on this path: the parameter value was replaced by
  a pattern and `Redacted:true` (both reproducers).
- `sourceSensitive` correctly applies the name pattern to names and the value pattern to values;
  non-OK analyzer status triggers full redaction (verified in phase 2, spot-checked here).
- Name length is bounded in practice: `taint.TaintString` rejects source names > 64 KiB, and the
  encoded event is capped at 25,000 bytes.
- Woven build health: no build-time memory finding (366 MB peak RSS).

## Not covered / open questions

- The adjacent hole is *worse* than F2 as filed but is a separate finding: a credential-shaped
  name that contains no name-pattern keyword (e.g., `glpat-…` as a parameter *key* of the plain
  parameter source) is not classified sensitive by `sourceSensitive` at all, so both name and
  value serialize raw. The `parameter.name`/`header.name` origins cover it only when the value
  pattern matches. Worth filing/merging as its own item.
- I did not test customer-configured `DD_IAST_REDACTION_NAME_PATTERN` values beyond defaults.
