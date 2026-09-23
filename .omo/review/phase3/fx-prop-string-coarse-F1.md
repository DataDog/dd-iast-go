# fx-prop-string-coarse-F1: formatting-method false taint

Target: `2e23b4614320defd0d32177a69888dcab73f4d11`.
No production files were changed.

## Verdict per finding

| Finding | Verdict | Adjusted severity |
| --- | --- | --- |
| `prop-string-coarse-F1` | **CONFIRMED** | **High** |
| `hooks-yml-fmt-strconv-url-F1` | **CONFIRMED** | **High** |

These are duplicates of one root cause. Independent, woven HTTP-to-SQL
execution produced a real `SQL_INJECTION` span event for a query constructed
entirely from constants. This extends both finders' evidence beyond inspecting
ranges or calling the evidence collector.

Qualification: implementing a formatting interface does not make its method
active for every verb. The defect is confirmed where fmt actually invokes the
method. The reproduction covers the appropriate verbs for all four interfaces.

## Reproduction

Evidence directory: `.omo/review/evidence/fx-prop-string-coarse-F1/`.

- `main.go`: independently authored executable; neither finder fixture was used.
- `COMMANDS.md`: complete private-copy setup, placement, build, run, and cleanup.
- `woven-go126.txt`: untruncated captured stdout, stderr, and exit status for all
  ten cases.
- `build-go126.txt`, `build-go127.txt`: captured build results and resource data.

After placing `main.go` at
`iast/integration/testapp/cmd/fx-coarse/main.go` in the private copy:

```sh
cd /tmp/ddiast-review/wt/fx-prop-string-coarse-F1/iast/integration/testapp
GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 /usr/bin/time -l timeout 900 \
  go tool orchestrion go build \
  -o /tmp/ddiast-review/wt/fx-prop-string-coarse-F1/fx-coarse-126 \
  ./cmd/fx-coarse

for mode in stringer error formatter gostring sprint sprintln bytes explicit clean direct; do
  printf '\nMODE=%s\n' "$mode"
  DD_TRACE_STARTUP_LOGS=false timeout 30 \
    /tmp/ddiast-review/wt/fx-prop-string-coarse-F1/fx-coarse-126 "$mode"
  printf 'EXIT=%s\n' "$?"
done
```

Go 1.26.6 build: exit 0; peak RSS 447,840,256 bytes, below 4 GiB.
The executable makes a real HTTP request, obtains its tainted query parameter
through `r.URL.Query().Get("sort")`, formats it, and calls
`database/sql.DB.ExecContext`. A recording driver checks the actual query
received; only the external database is replaced. The byte case obtains its
source through `io.ReadAll(r.Body)`. There are no manual source-taint calls,
wrapper calls, sink reports, or sink-registration imports. A mock tracer
captures the finished span locally. Completion is channel-signaled after span
finish, not inferred from a delay.

The named string `column` allowlists to `"name"` or `"id"`; the supplied marker
selects `"id"`. Separate `Error`, `Format`, and `GoString` implementations ignore
their receiver altogether and emit `"id"`.

Key captured output, abridged only here:

```text
CONFIG enabled=true sampling=30 concurrent=2 vulnerabilities=2 dedup=true redaction=true
MODE=stringer
"InputTainted":true,"Query":"SELECT id FROM accounts"
"Ranges":[{"Start":0,"Length":23,"Source":{"Origin":"http.request.parameter","Name":"sort","Value":"untrusted_sort_marker"},"Marks":{}}]
"Calls":1
"type":"SQL_INJECTION"
"evidence":{"valueParts":[{"value":"SELECT id FROM accounts","source":0}]}
ASSERTION FAILED: constant-only SQL must have no taint and no SQL_INJECTION event
EXIT=1
```

| Case | Observed ranges / SQL events | Exit |
| --- | --- | --- |
| Named-string `Stringer`, `%s` | 1 full-output range / 1 event | 1 |
| Named-string `error`, `%s` | 1 full-output range / 1 event | 1 |
| Named-string `Formatter`, `%v` | 1 full-output range / 1 event | 1 |
| Named-string `GoStringer`, `%#v` | 1 full-output range / 1 event | 1 |
| `Sprint` and `Sprintln` with `Stringer` | Each: 1 full-output range / 1 event | 1 each |
| Named-byte-slice `Stringer`, `%s` | 1 full-output body-source range / 1 event | 1 |
| Explicit `.String()` before `Sprintf` | 0 / 0 | 0 |
| Untainted named-string argument | 0 / 0 | 0 |
| Original tainted string, no method | 1 / 1, expected positive control | 0 |

Each method executes exactly once. Every false-positive query is
`SELECT id FROM accounts` (plus the native newline for `Sprintln`), with no input
marker. The two negative controls yield the same SQL bytes without taint or a
finding. Assertions fail for the reported provenance defect, not formatting,
source activation, or driver failure. Startup agent-connection warnings are
preserved in the evidence; local span capture succeeds.

The same build command with `GOTOOLCHAIN=go1.27.0` and output
`fx-coarse-127` exits 1:

```text
# encoding/json
... dec.r undefined (type *Decoder has no field or method r)
... dec.d undefined (type *Decoder has no field or method d)
```

This independently reproduces the unrelated JSON compatibility blocker
described in `phase1/base-test-127.md`. Consequently no Go 1.27 runtime result
is claimed. Go 1.27 build peak RSS was 301,711,360 bytes.

## Reachability

**Reachable under defaults on supported Go 1.26.6: yes, for sampled requests.**
Direct root-application `fmt.Sprint*` calls are advertised in `README.md:32`
and matched by `iast/propagation/orchestrion.yml:706-731`. Executable bootstrap
activates the SQL sink; the repro uses that automatic path.

The executable retains production defaults for enablement, quotas,
deduplication, and redaction. It logs the default sampling of 30 percent, then
sets only sampling to 100 percent for deterministic execution. At default
sampling the identical active-request path is reachable
(`internal/taint/request/scope.go:81-103,148-158`). Each case runs in a fresh
process, so default deduplication is not disabled or bypassed by a shared test
fixture.

**Documented limitation: no, not this defect.** README, phase-1 design intent,
and the phase-5 plan were checked. The plan at
`_docs/plans/taint-tracking-net-http-sqli-cmdi-phase-5.md:59-68` deliberately
permits coarse ranges and the first contributing source, with at most sixteen
inputs. That explains widening when data contributes; it does not document
attributing receiver bytes that fmt never emitted to constant method output.
No formatting-method exclusion was found. Even a broad interpretation of the
coarse policy conflicts with product rule 4: accurate provenance and no false
taint. The explicit `.String()` negative control distinguishes this from a
general lack of sanitizer support.

## Adjusted severity

**High for both IDs:** an ordinary supported formatting call creates wrong
provenance and a demonstrated false-positive SQL injection report under the
normal sampled-request configuration.

There is no demonstrated host-value change or crash, so Critical is unwarranted.
This is not merely an imprecise range or a missing test: the sink publishes an
actual false vulnerability.

## Root cause (file:line)

1. `iast/propagation/coarse.go:49-61` computes native formatting once, then sends
   the original arguments and materialized output to coarse propagation.
2. `internal/taint/propagation/string_coarse.go:206-220` selects a key solely by
   reflected string/byte-slice kind. Named receiver backing remains the tainted
   source identity even when fmt substitutes a constant method result.
3. Its callers at `string_coarse.go:115-145` accumulate that key unconditionally.
   `propagation.go:721-735` selects its source and intersects marks;
   `string_coarse.go:174-198` publishes a full-output range.
4. `internal/taint/evidence/evidence.go:209-218` accepts the unmarked range;
   `iast/database/sql/sql.go:34-49` proceeds to `ReportTainted`. The captured
   finished-span event proves this downstream path, rather than assuming it.

The Go 1.26.6 implementation in `src/fmt/print.go:622-678` was also read:
method dispatch precedes underlying-value formatting for the reproduced verbs.
Both findings identify the same erroneous receiver-to-output attribution.

## Minimal fix

Do not treat a method-rendered argument's raw backing as a contributing value.
The smallest conservative mitigation is to exclude values implementing
`fmt.Formatter`, `fmt.Stringer`, `error`, or `fmt.GoStringer` from raw-argument
coarse collection and explicitly document method formatting as unsupported.
Do not call user methods again to inspect their output.

That blanket exclusion is a mitigation, not a complete provenance fix: it can
lose taint when a method returns the input, or when the selected verb does not
invoke that interface (for example `%#v` on a type implementing only `Stringer`).
A coverage-preserving fix must respect actual per-verb method dispatch and
propagate the method's actual materialized output without double evaluation.
Keep the reproduced constant-method cases and direct/explicit controls as
regressions. No candidate production fix was applied in this verification.
