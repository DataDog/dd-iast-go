# fx-sink-e2e-truepos-F1: SQL comments bypass SQL evidence redaction

## Verdict per finding
| id | verdict | original | adjusted |
|---|---|---|---|
| sink-e2e-truepos-F1 | CONFIRMED | Critical | Critical |
| sink-redaction-source-F3 | CONFIRMED (duplicate, same root cause) | Critical | Critical |

The mechanism is real. At HEAD 2e23b46, `sqlSensitiveToken` (`internal/taint/redaction/sql.go:83-100`) returns sensitive intervals only for `STRING`/`INCOMPLETE_STRING`, `DOLLAR_QUOTED_*`, and `NUMBER`/`BOOLEAN`/`NULL`. go-sqllexer's `COMMENT` (`--`/`#`, which runs to the newline) and `MULTILINE_COMMENT` fall into `default: return Interval{}, false`. So:
- (F1) An injected `--` or `#` turns the application's trailing literals into one comment token, and they are emitted verbatim.
- (F3) Tainted text inside a comment is emitted raw in both the evidence and the source `value`, unless the default name or value pattern happens to match.
- Clean application comment bodies are emitted raw as well.

The repository test pins this behavior (`analyzer_test.go:30`, `want: "SELECT column -- secret\nFROM table"`).

It also contradicts the normative cross-tracer corpus, `dd-trace-js/.../vulnerability-formatter/resources/evidence-redaction-suite.json`, which expects:
- "Query with line comment": `{"value":" --"},{"redacted":true}`
- "Query with block comment": `{"value":"/*"},{"redacted":true},{"value":"*/"}`

dd-trace-java redacts `LINE_COMMENT`/`BLOCK_COMMENT` bodies for every dialect (`SqlRegexpTokenizer.java:22-23`, 83-89, 214-241). An unterminated `/*` is lexed as `ERROR` (go-sqllexer `scanMultiLineComment`), so `AnalysisDropped` leads to full redaction. That explains why the finder's block-comment injection case was safe and the `--` case was not.

## Reproduction
Both reproducers are my own, run in a private copy (`/tmp/ddiast-review/wt/fx-sink-e2e-truepos-F1`) with every `DD_IAST_REDACTION_*` variable unset, so the defaults applied.

1. **Woven, real surface** (`evidence/fx-sink-e2e-truepos-F1/fxrepro/main.go`). This is a new `package main` module woven with the documented aggregate `_ "github.com/DataDog/dd-iast-go"` plus `contrib/net/http`. Handlers build queries with `+` from `r.URL.Query().Get`. The program uses a fake driver and captures `_dd.iast.json` through mocktracer.
   `cd <copy>/fxrepro && GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 /usr/bin/time -l go tool orchestrion go build -o ../fxdemo . && cd .. && DD_IAST_ENABLED=true DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false ./fxdemo`
   The build exited 0 after 265 s wall time under shared load, with a max RSS of 0.46 GB. Key lines from `woven-output.txt`:
   - `user=alice`: `...'"},{"pattern":"abcde",...},{"value":"' AND pw_hash = '"},{"pattern":"***********************","redacted":true},{"value":"' AND tenant = "},{"pattern":"**","redacted":true}`
   - `user=admin' --`: `{"pattern":"abcdefghi","redacted":true,"source":0},{"value":"' AND pw_hash = 'app-secret-literal-7f3a' AND tenant = 42"}`. The same sink line, `main.go:29`, gave the same hash.
   - `note=hunter2-customer-note` into `... ORDER BY name -- ` + note: source `"name":"note","value":"hunter2-customer-note"`, and evidence `{"value":"hunter2-customer-note","source":0}`.
   - clean app comment: `{"value":"SELECT id FROM users /* api_key=sk_live_CLEANCOMMENT */ ORDER BY "}`.
   - The driver received the byte-identical query in every case. Host behavior is unaffected; this is only a leak.
2. **Internal API** (`evidence/fx-sink-e2e-truepos-F1/fx_comment_test.go`, run through `AnalyzeSQL` and then `BuildWithSensitive` into the `model.Event` JSON). Output is in `unit-output.txt`, from `go test ./internal/taint/redaction -run 'TestFXCommentRedaction|TestAnalyzeSQLLiterals' -count=1 -v` (PASS, log-only):
   - corpus line comment: `intervals=[]`, evidence `{"value":" -- This is a line comment"}`. The corpus expects a `{"redacted":true}` part here.
   - corpus block comment: `intervals=[]`, evidence `"/*\nThis is a block comment\n*/"` in clear.
   - `admin' --`: `intervals=[{35 5}]`, and `'app-secret-literal-7f3a' AND tenant = 42` is in clear.
   - `SELECT 1 -- hunter2`: the source is `"value":"hunter2"` and the evidence is `{"value":"hunter2","source":0}`. This matches the F3 finder's output exactly.
   - **Additional variant**, MySQL `admin' #`: the six-dialect union yields misaligned intervals `[{35 5} {44 15} {78 2} {84 16}]`. The evidence then leaks fragments: `{"value":"'app-secret-literal"}` ... `{"value":"f3a'"}`. MySQL lexes `#` as a comment, while the other dialects still lex the literals, but at shifted boundaries.

I also inspected the finder's own artifacts: `sink-e2e-truepos/nodedup-output.txt` lines 127-130 and `agent-output.txt:45-47`, and `sink-redaction-source/default-redaction-leaks.out.txt`. They agree with my runs.

## Reachability
- **Default configuration: yes.** Redaction is on by default (README:119). No option redacts comments. The default name and value patterns only rescue a comment body that happens to look like `password`, `token`, or `Bearer`.
- **Default sampling (30%) and concurrency (2)** only reduce how often a request is analyzed. They do not prevent it. I forced 100% sampling and disabled dedup for determinism only. With dedup on, the first request to reach a given sink location decides what is reported. An attacker or a DAST scanner sending `' --` is often that first request, because `' --` and `' #` are the canonical SQLi probes.
- **Customer code:** ordinary `+` or `fmt` concatenation into `db.QueryContext`, which is the supported primary SQLi path, woven with Go 1.26.6.
- **Documented limitation: no.** Neither the README nor `phase1/01-design-intent.md` lists comment redaction as a trade-off. Design-intent notes that the RFC-derived redaction corpus "must be replaced or validated against the normative shared corpus", and that shared corpus fails on comments. It breaks the product requirement that evidence "is redacted before leaving the process".

## Adjusted severity
**Critical, for both findings.** The brief lists "sensitive data leaving the process unredacted" under Critical. Here, application secrets (hard-coded literals, comment bodies) and tainted user secrets ship in clear under default configuration, and attacker-chosen input decides whether they do. The two findings share one root cause (`sql.go:98`, the default branch of `sqlSensitiveToken`), so fixing it once closes both, along with the MySQL `#` fragment variant.

## Root cause (file:line)
- `internal/taint/redaction/sql.go:83-100`: `sqlSensitiveToken` has no `sqllexer.COMMENT`/`sqllexer.MULTILINE_COMMENT` case, so the `default` branch at line 98-99 treats them as clean.
- `internal/taint/redaction/analyzer_test.go:30` locks in the wrong expectation.
- There is no shared-corpus comment case in the Go tests.

## Minimal fix
In `sqlSensitiveToken`:
```go
case sqllexer.COMMENT: // "--..." or "#..." (lexer stops before '\n')
	prefix := 2
	if strings.HasPrefix(value, "#") { prefix = 1 }
	return checkedInterval(start+prefix, start+len(value))
case sqllexer.MULTILINE_COMMENT: // "/*...*/" (unterminated is ERROR -> dropped)
	return checkedInterval(start+2, start+len(value)-2)
```
`checkedInterval` already rejects empty bodies. Then:
- change `analyzer_test.go:30` to expect `SELECT column --?\nFROM table`;
- import the two shared-corpus comment cases;
- add the `admin' --` / `admin' #` versus benign-control pair to the redaction tests.

Because the six dialect tokenizations are unioned, the MySQL `COMMENT` interval then covers the entire `#` tail, which also closes the fragment leak. Optimizer hints such as `/*+ ... */` become redacted too, which matches Java.
