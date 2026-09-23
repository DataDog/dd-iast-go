# fx-crash-diff-strings-F1: fmt coarse propagation taints output bytes that do not come from the tainted argument

Verdict: CONFIRMED. Reproduced independently with my own woven reproducer on go1.26.6 through the real `fmt.Sprint*` call-site replacement; the same root cause underlies prop-string-coarse-F1/F2 and hooks-yml-fmt-strconv-url-F1/F4.

Scope covered: `internal/taint/propagation/string_coarse.go` (all of `CoarseFormatString`/`CoarseFormattedString`, `formatArgumentKey`, `publishCoarseOwners`), `iast/propagation/coarse.go:49-61`, `iast/propagation/orchestrion.yml` fmt join points (lines 713-724), `iast/database/sql/sql.go:34-44` + `internal/taint/evidence/evidence.go` (sink path), README:26-32, phase1 design-intent limitations list.

## Verdict per finding

### crash-diff-strings-F1 (High, false-positive) — CONFIRMED
- Location (HEAD 2e23b46): `internal/taint/propagation/string_coarse.go:115-146` (hit functions), `:175-204` (`publishCoarseOwners` taints `[0, len(clone))` unconditionally), `:206-219` (`formatArgumentKey` keys every `reflect.String`/`[]byte`-kind argument).
- Claim verified: `formatArgumentKey` (`string_coarse.go:206-219`) returns a store key for any string-kind argument, without checking whether `fmt` renders that argument's bytes. `publishCoarseOwners` (`string_coarse.go:175-204`) then adopts one range covering the whole result clone with the argument's source. So the result is fully tainted whenever a string-kind argument implements `fmt.Stringer`/`error`/`fmt.Formatter` (fmt renders the method's return value instead of the bytes), or when the verb does not render the operand (`%T`, `%.0s`, `%[2]s`), or when the argument is a format-string-only input to `CoarseFormattedString`. A Stringer that maps attacker input to a fixed constant (standard allowlist/sanitizing idiom) yields a fully tainted string, which the SQL sink analyzer accepts (verified end-to-end to `evidence.CollectString` = `StatusCollected`, the exact first step of `iast/database/sql.Report`, `iast/database/sql/sql.go:34-44`).
- The original finding's evidence (`crash-diff-strings/targeted.log`) matched my independent run line-for-line.

## Reproduction

My own minimal reproducer (independent of the finder's harness), in the private copy at `iast/internal/fxfmtrepro/` (copied to `.omo/review/evidence/fx-crash-diff-strings-F1/`): `fxrepro.go` makes direct `fmt.Sprintf`/`fmt.Sprint` calls in plain functions — the exact call shape the `fmt.Sprint*` join points (`iast/propagation/orchestrion.yml:713-724`, `replace-function: iast/propagation.FmtSprint*`) rewrite. `fxrepro_test.go` taints `1' OR '1'='1` via `taint.TaintString` in a real `request.Begin` scope, then checks `taint.IsTaintedString` + `strings.Contains` on each result, and runs the real sink analysis (`evidence.CollectString`) on the composed query.

```
cd /tmp/ddiast-review/wt/fx-crash-diff-strings-F1 && /usr/bin/time -l \
  env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -v -count=1 \
  -timeout 15m -run 'TestFmt' ./iast/internal/fxfmtrepro/
```

Key output (woven-go1.26.6.log; deterministic, reproduced twice):

```
Sprintf-Stringer-sanitize result="level=AUDIT_OK"  tainted=true containsSource=false
Sprint-Stringer           result="AUDIT_OK"        tainted=true containsSource=false
Sprintf-%T                result="type=string"     tainted=true containsSource=false
Sprintf-%.0s              result="xy"              tainted=true containsSource=false
Sprintf-%[2]s-skip        result="constant"        tainted=true containsSource=false
control-%d                result="n=12"            tainted=false containsSource=false
positive-%s               result="q=1' OR '1'='1"  tainted=true containsSource=true
query="SELECT * FROM t WHERE level='AUDIT_OK'" tainted=true containsSource=false
CollectString status=1 sources=1 parts=1
part[0]="SELECT * FROM t WHERE level='AUDIT_OK'"
```

The control (`%d`) is correctly untainted and the positive control (`%s`) correctly tainted, so the oracle is sound and the five failures are pure false taint. Peak RSS 105 MB.

## Reachability

Reachable under default configuration (30% sampling; any sampled request): any root-package direct `fmt.Sprint*`/`Sprintf` call with a tainted string-kind argument that (a) implements `fmt.Stringer`/`error`/`fmt.Formatter`, or (b) is not rendered by the format (`%T`, precision 0, skipped argument index). `fmt.Sprint*` is an advertised propagation (README:32 "Formatting and encoding | `fmt.Sprint*` ..."). Not a documented limitation: the README "Propagation coverage" section and the phase-1 design-intent documented-miss list say nothing about Stringer/format-verb over-taint, and this is not a "safe miss" — it is false taint, breaking product rule 4 (no false taint) and producing false-positive SQLi reports with attacker-free "evidence" on a supported path.

## Adjusted severity

High — wrong provenance (false-positive vulnerability) on a supported, advertised path; matches the brief's High definition (not Critical: no crash/behavior change/memory issue; the host result is byte-identical). Duplicates: prop-string-coarse-F1, prop-string-coarse-F2, hooks-yml-fmt-strconv-url-F1, hooks-yml-fmt-strconv-url-F4, prop-semantics-parity-F2, and crash-diff-strings-F1 all share ONE root cause: `formatArgumentKey`'s kind-only argument selection feeding `publishCoarseOwners`'s whole-result taint.

## Root cause

- `internal/taint/propagation/string_coarse.go:206-219` — `formatArgumentKey` selects any `reflect.String`/`[]byte`-kind argument, ignoring whether fmt renders its bytes.
- `internal/taint/propagation/string_coarse.go:186-192` — `publishCoarseOwners` adopts `ranges.Range{Start: 0, Length: len(clone)}` regardless of what fmt emitted.

## Minimal fix

In `formatArgumentKey` (`string_coarse.go:206`), return false for arguments whose type implements `fmt.Formatter`, `fmt.Stringer`, `error`, or `fmt.GoStringer` (cheap type assertions, mirroring fmt's `handleMethods` precedence); this converts each false positive into a safe miss, the direction this codebase prefers. Optionally, for plain-string arguments, a bounded `strings.Contains(result, arg)` check (for small arguments) before publishing would also cover the verb-skip cases (`%T`, `%.0s`, `%[2]s`). Add a regression test with an allowlisting Stringer.

## Checked and found correct

- `formatArgumentKey` reflection calls cannot panic and never invoke user methods (confirmed by reading; matches prop-string-coarse's host-safety analysis).
- The `%d` control and `%s` positive control behave correctly, so the coarse pipeline keys and publishes only when a string-kind argument is present — the defect is specifically the "rendered bytes" gap.

## Not covered / open questions

- go1.27.0 woven builds are broken at `encoding/json` advice (known base-test-127-F1), so only go1.26.6 was exercised.
- Did not re-run the finder's fuzz harness; not needed — the targeted mechanism is deterministic and was reproduced twice.
