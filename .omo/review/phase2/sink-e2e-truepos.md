# sink-e2e-truepos: woven vulnerable demo app, SQLi/CMDi true/false positives end to end
Verdict: Detection is correct end to end: all 39 documented-supported SQLi/CMDi flows report the right type, source origin and name, exact evidence ranges, and file:line location, on both the meta_struct and `_dd.iast.json` channels, and 16 of the 17 clean controls stay silent (the exception is F2). One Critical redaction bypass was reproduced: an injected SQL comment exposes the application's own literals. Two Medium false positives were also reproduced, both on exotic or documented-limitation shapes.
Scope covered: I built a new demo module (`evidence/sink-e2e-truepos/demoapp`). It is `package main` in the root module, woven with the pinned Orchestrion using the documented aggregate `_ "github.com/DataDog/dd-iast-go"` plus `dd-trace-go/contrib/net/http/v2`, so server spans are created like a customer's. There are no explicit spans. It uses a fake `database/sql` driver and runs real `sh`/`ls` processes. It was driven over real HTTP by a plain-built driver with a fake trace-agent that advertises `span_meta_structs` and decodes the MessagePack `meta_struct.iast` and `_dd.stack`. The same binary was also run under mocktracer (the `_dd.iast.json` fallback), with dedup off, and in a 32-way overlapping-concurrency phase. Go 1.26.6. The woven build took about 40 s with a max RSS of about 455 MB. Code read: `internal/taint/redaction/{sql,source,command}.go`, `internal/vulnerability/{tainted,report}.go`, `internal/spans/{annotation,owner,orchestrion,payload}.go`, `iast/net/http/orchestrion.yml`, `iast/{database/sql,os/exec}/{orchestrion.yml,*.go}`, `internal/taint/propagation/string_coarse.go`, `internal/taint/request/{scope,owner,reader}.go`, `internal/taint/store/owner.go`.

## Findings
### sink-e2e-truepos-F1: An injected `--` hides the application's SQL literals from redaction and ships them in clear
- Severity: Critical
- Category: redaction
- Location: internal/taint/redaction/sql.go:83-100 (`sqlSensitiveToken`: only STRING/INCOMPLETE_STRING/DOLLAR_QUOTED*/NUMBER/BOOLEAN/NULL are sensitive; `COMMENT`/`MULTILINE_COMMENT` fall into `default`)
- Claim: SQL evidence redaction treats literal tokens as sensitive but treats comment tokens as clean. A textbook SQLi payload such as `admin' --` turns the rest of the application's query into one `COMMENT` token. Every application literal after the injection point is then emitted verbatim in the span payload. In the same run, the byte-identical query with a benign input redacts those literals. So an attacker, or any scanner, decides whether the application's secrets are redacted. Clean application comments (`/* api_key=... */`) and tainted comment text are also never redacted. dd-trace-java redacts both comment forms (`dd-trace-java/.../iast/sensitive/SqlRegexpTokenizer.java:22-23`, used by every dialect at lines 214-241). This corroborates crash-hostile-input-F1, reproduced here over the real wire path.
- Evidence: `.omo/review/evidence/sink-e2e-truepos/nodedup-output.txt` lines 127-135, and `nodedup-results.json`. Handler `demoapp/handlers.go` `sqlLogin` builds `"SELECT id FROM users WHERE name = '" + user + "' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42"`. Command: `./driver -bin ./demo -mode agent -nodedup` (see README.txt). Captured meta_struct evidence:
  - control `user=alice`: `SELECT id FROM users WHERE name = '[abcde#0]' AND pw_hash = '***********************' AND tenant = **`
  - `user=admin' --`: `SELECT id FROM users WHERE name = '[abcdefghi#0]' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42`
  - `/sql/comment`: `SELECT id FROM users /* api_key=sk_live_CLEANCOMMENT */ ORDER BY [name /* token=ghp_TAINTEDSECRETINCOMMENT */#0]` (agent-output.txt:45-47)
- Fix: Return the comment body interval (excluding the `--`, `/*` and `*/` delimiters) as sensitive for `sqllexer.COMMENT` and `sqllexer.MULTILINE_COMMENT` in `sqlSensitiveToken`, matching Java. Add the `admin' --` versus benign-control pair to the redaction corpus.

### sink-e2e-truepos-F2: fmt.Sprintf reports SQLi when the tainted argument contributes no bytes (%T)
- Severity: Medium
- Category: false-positive
- Location: internal/taint/propagation/string_coarse.go:115-145 (`coarseFormattedStringHit`/`coarseFormatStringHit` accumulate every tainted direct string argument regardless of verb)
- Claim: `fmt.Sprintf("SELECT id FROM users /* %T */", userInput)` produces `SELECT id FROM users /* string */`, which contains no user bytes. It is still reported as SQL_INJECTION, with the whole query attributed to the parameter and the unredacted source value `x' OR '1'='1` attached. This is a false positive on a supported function. I rate it Medium rather than High because verbs that do not render their argument (`%T`, `%p`, `%.0s`, a skipped `%[n]`) are very rare in real SQL construction. The realistic `%s`, `%v` and `%d` (of `len`/`Atoi`) paths behaved correctly. This corroborates prop-string-coarse-F2 and prop-semantics-parity-F2 at the sink.
- Evidence: `.omo/review/evidence/sink-e2e-truepos/agent-output.txt`, case `neg-fp-sprintf-type`: `evidence: [SELECT id FROM users /* string */#0]`, `source: origin=http.request.parameter name=name value=x' OR '1'='1`, `FAIL: types map[SQL_INJECTION:1] want map[]`. Mock mode (`mock-output.txt`) shows the same result. Command: `./driver -bin ./demo -mode agent`.
- Fix: Skip arguments whose verb does not render the value. Alternatively, publish coarse taint only when the result actually contains bytes derived from a tainted argument; for example, require a verb in {s, v, q, x, X} with non-zero precision.

### sink-e2e-truepos-F3: Clean in-place overwrite of an io.ReadAll body still reports SQLi with the body as source
- Severity: Medium
- Category: false-positive
- Location: internal/taint/request/reader.go:67-88,90-125 (body adopted as a byte root spanning `cap`); iast/propagation/operators.go:198 (`BytesToString` looks up the unchanged key)
- Claim: This challenges the documented limitation that `copy`, `append` and index writes are unsupported, because the outcome is a false positive on a supported sink. After `body, _ := io.ReadAll(r.Body)`, the handler does `copy(body, "SELECT id FROM users ORDER BY name")`, which overwrites every byte with a clean constant, and then `q := string(body)`. The result is a SQL_INJECTION finding whose evidence is the constant, fully attributed to `http.request.body`. The unrelated original body is attached as the source value. The shape is contrived (a same-length in-place overwrite), so the impact is limited. The limitation is documented but produces a wrong report rather than a safe miss.
- Evidence: `.omo/review/evidence/sink-e2e-truepos/agent-output.txt`, case `doc-fp-body-overwrite`: `evidence: [SELECT id FROM users ORDER BY name#0]`, `source: origin=http.request.body ... value=name; DROP TABLE users; -------xxx`, `FAIL: types map[SQL_INJECTION:1] want map[]`. The same result appears in mock and nodedup runs.
- Fix: Document that clean in-place writes can leave stale provenance. Preferably, keep a cheap content fingerprint (length plus hash of the first and last 8 bytes) on adopted body roots and drop the root when `BytesToString` sees a mismatch.

### sink-e2e-truepos-F4: The checked-in e2e suite never exercises contrib server spans or the meta_struct wire path
- Severity: Low
- Category: test-gap
- Location: iast/integration/testapp/request_event_test.go:22-50; iast/integration/testapp/e2e_test.go:195-213
- Claim: The repository harness starts spans explicitly with `tracer.StartSpanFromContext`, which is bound by a dedicated advice. It reads only the mocktracer `_dd.iast.json` fallback because `SetMetaStruct` returns false without a real tracer. It never covers the customer configuration, where spans come from `contrib/net/http`'s `Server.Serve` wrapper and IAST binds only through the application-handler advice, nor the MessagePack `meta_struct.iast`/`_dd.stack` path. Both work today (below), but a regression in either would pass CI.
- Evidence: `.omo/review/evidence/sink-e2e-truepos/demoapp` (adoptable harness); agent-output.txt shows `channel=meta_struct.iast` for every positive, location `spanId` equal to the contrib server span ID (43/43 in nodedup-results.spans.json), and `_dd.stack` frame 0 equal to the sink line.
- Fix: Adopt the plain-built driver and fake agent as a nested-module e2e test that weaves `contrib/net/http` and asserts the meta_struct payload.

### sink-e2e-truepos-F5: fmt-built queries yield evidence that marks the whole template as user input
- Severity: Info
- Category: provenance
- Location: internal/taint/propagation/string_coarse.go:90-145
- Claim: This documented coarse behavior has a practical consequence, noted here for triage. `fmt.Sprintf("... WHERE name = '%s'", in)` is the most common Go SQL-building idiom, and its evidence is a single 48-character run of asterisks (`sql-sprintf-literal`). That is because the whole query is one tainted range and the source overlaps a literal. Evidence for `%s` in a non-literal position is the entire query as `source#0`. Findings are correct but nearly unactionable in the UI. Taint also survives `%x` into `X'..'` hex literals (`obs-fp-sprintf-hex`), which is consistent with encoder propagation elsewhere.
- Evidence: agent-output.txt, cases `sql-sprintf`, `sql-sprintf-literal`, `sql-inline-sprintf`, `obs-fp-sprintf-hex`.
- Fix: Consider exact `%s`/`%v` range mapping for simple format strings.

### sink-e2e-truepos-F6: 6 of 32 overlapping requests were not analyzed despite a limit of 64
- Severity: Info
- Category: perf
- Location: internal/taint/store/owner.go:20-24 (`ownerMu.TryLock` failure leads to a disabled owner and `DecisionCapacityDropped`)
- Claim: With `DD_IAST_MAX_CONCURRENT_REQUESTS=64` and sampling at 100%, a burst of 32 requests held at a barrier left 6 spans (19%) with `_dd.iast.enabled=0`. Drops are safe; there was no false or foreign attribution. This corroborates the existing admission-contention findings (perf-contention / life-soak) from the e2e side.
- Evidence: `.omo/review/evidence/sink-e2e-truepos/conc-output.txt` and `conc-results.json`: `conc-clean-03`, `conc-tainted-06/10/16/24` and `conc-clean-21` have `iast_enabled 0`. `TOTAL FAILS=0`. Every analyzed tainted request carried only its own `col` value.
- Fix: See the existing admission findings (bounded retry or per-slot CAS instead of a global TryLock).

## Checked and found correct
- True positives, each with type, source origin and name, and file:line checked against a `runtime.Caller` marker on the sink line, on both channels (agent-output.txt, mock-output.txt; `TOTAL FAILS=0` on the first 41-case run):
  - SQL built with `fmt.Sprintf`, `+` (including inline in the call argument), `strings.Builder`, `strings.Join`/`ToLower`/`TrimSpace`, or a shared `bytes.Buffer`.
  - Input from JSON `Decoder`, `Unmarshal`, typed `map[string]string`, `io.ReadAll`+`string()`, query `Get` or map index, `FormValue` (urlencoded and multipart), `PathValue`, `URL.Path`, `RawQuery`, `Header.Get`/map index, `Authorization`, or `Cookie`.
  - Two sources (`SELECT [col#0] FROM [table#1]`), prepare plus exec (two findings, at `handlers.go:221` PrepareContext and `:226` stmt.ExecContext in the evidence copy), `db.Query` without a context, a method `ServeHTTP` handler, a func-literal handler, and a goroutine using the request context.
  - CMDi via `sh -c` (the process still ran: `X-Out=ddiast-42`), `ls -d <arg>`, inline concat, and `strings.Join`.
- Exact evidence ranges are right, for example `SELECT id FROM users ORDER BY [name; DROP TABLE users#0] LIMIT **`, and `[name--x#0]` for `/sql/urlpath/name--x` with source `/sql/urlpath/name--x`.
- Redaction:
  - Name pattern: `password` gives `pattern=abcdefghijklmn`.
  - Value pattern: `Bearer ...` gives the mapped sub-pattern `hijklmnopqr`.
  - A tainted value inside a literal redacts the source. Clean literals and numbers are masked.
  - Command evidence keeps only argv[0] (`sh ***[...]`), matching Java.
  - An unterminated `/*` falls back to full redaction.
- No false positives in these 16 controls (the 17th, `%T`, is F2):
  - bound parameter, `strconv.Atoi` then `Itoa`/`%d`, byte-identical clean literal, allowlist map lookup, branch-selected constant;
  - `strings.ReplaceAll(in, in, "name")`, `Builder.Reset` reuse, shared `bytes.Buffer` reused by a later request with the identical clean bytes;
  - clean JSON document decoded inside a tainted request, `Query().Set` or `Header.Set` with a literal, `%d` of `len(in)`;
  - a tainted global built in request A and used in request B (no cross-request bleed), `exec` with constant argv, `exec` with an `Atoi`-sanitized number.
- Validation without conversion (`Atoi(id)` checked, original `id` concatenated) correctly still reports.
- Wire and trace: the real tracer sent `meta_struct.iast` (the agent advertised support) with `_sampling_priority_v1=2` on vulnerable spans and 1 otherwise, and `_dd.iast.enabled=1` on every analyzed span. The mocktracer path fell back to `_dd.iast.json` with identical evidence (`diff` of evidence lines: identical). Location `spanId` equals the root server span in all 43 vulnerabilities of the final nodedup run (`nodedup-results.spans.json`). `_dd.stack` frame 0 is the sink line. Default dedup suppresses a second payload at an already-reported location (`sql-login-comment-injection` in agent-output.txt), as designed. `-nodedup` restores it.
- `+=` (`doc-fn-sql-plus-assign`) is a silent miss, as documented.
- Header source names use Go's canonical form (`X-Sort`, `Authorization`) rather than lowercase. I did not treat this as a defect.

## Not covered / open questions
- Go 1.27.0: not run, because woven `json.Decoder` builds are known to fail (sink-json-sources-F1).
- Default sampling (30%) and default max concurrency (2): the runs forced sampling to 100%.
- Real DB drivers and a real Datadog agent/backend ingestion of `meta_struct` (the fake agent only decodes the payload).
- Framework routers (gin, echo, chi), gRPC, and `exec.Cmd.Path` divergence (already sink-exec-F1).
