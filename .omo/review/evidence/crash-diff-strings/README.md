# crash-diff-strings evidence

Harness in `harness/` (copied from the private copy `/tmp/ddiast-review/wt/crash-diff-strings/iast/internal/crashdiff/`; place it at `iast/internal/crashdiff/` of a repo copy to re-run). `harness-testdata/` holds the harness-bug crasher input from run 1:

- `impl.go`: `Impl` table of ~65 operations. `Woven` holds direct calls /
  operators (rewritten by Orchestrion); `Native` holds function values and
  method expressions; `Reflect` calls every `Native` entry through
  `reflect.Value.Call`/`CallSlice`. Neither Native nor Reflect is woven
  (proved by `TestWeavingAsymmetry`).
- `diff_test.go`: `FuzzStringsDiff` (fuzz entry), `TestDiffRandom` (PRNG
  campaign with per-op statistics), `TestWeavingAsymmetry`.
  Each case opens 1-2 real request scopes (`request.Begin`), taints a/b/c/[]byte
  via `taint.TaintString`/`TaintBytes` with per-iteration unique source names,
  runs every op on Woven, Native and Reflect, and requires `reflect.DeepEqual`
  outcomes (strings, bools, ints, error type+text, panic value, callback /
  `String()` invocation counts; slicing ops compare panic presence only).
  Then a taint oracle checks every woven output: ranges in bounds, only
  sources tainted in *this* iteration (stale values from finished requests are
  fed back as inputs), source value equality, and for exact ops every tainted
  byte must occur in the source value. A chain of up to 24 ops feeds woven
  outputs forward. Window misses are replayed in isolation.
- `extra_test.go`: `TestTargetedEdges` (fmt coarse over-taint, Join alias).

Commands (run in the private copy, `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4`):

```
go tool orchestrion go test -count=1 -run '^$' -fuzz '^FuzzStringsDiff$' -fuzztime 15m -parallel 2 ./iast/internal/crashdiff
go tool orchestrion go test -count=1 -v -run 'TestWeavingAsymmetry|TestDiffRandom|TestTargetedEdges' ./iast/internal/crashdiff
```

Outputs: `fuzz.log` (15-minute run), `fuzz-run1-harness-oom.log` (first run,
killed by a harness-only exponential-growth bug, see report), `random-go1.26.6.log` (50k iterations, seed 42),
`random-go1.27.0-nojsonv2.log` (30k iterations, seed 7),
`random-go1.27.0-buildfail.log` (plain go1.27.0 woven build failure, known
base-test-127-F1), `targeted.log`.
