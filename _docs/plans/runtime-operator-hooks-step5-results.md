# Runtime operator hooks: step 5 results

This file records the step 5 measurements and the negative controls of plan
[runtime-operator-hooks](./runtime-operator-hooks.md). Delete it with the plan.

## Environment

- darwin/arm64 (Apple M5 Pro, macOS 26.7), go1.26.6, Orchestrion v1.13.1.
- linux/amd64: `golang:1.26.6` container under colima (Rosetta), 4 CPUs.

## Gate benchmarks (plan section 9.3)

Commands (repository root; a separate GOCACHE for the woven build):

```console
GOTOOLCHAIN=go1.26.6 go test -c -o /tmp/fix5-bench/plain.test ./iast/runtime
GOTOOLCHAIN=go1.26.6 GOCACHE=/tmp/gocache-fix5-woven go tool orchestrion go test -c -o /tmp/fix5-bench/woven.test ./iast/runtime
# 10 interleaved rounds; in each round: GOGC default (plain, woven), then GOGC=off (plain, woven)
./<bin>.test -test.run='^$' -test.bench='^BenchmarkRuntime' -test.benchtime=300ms -test.count=1
benchstat plain-default.txt woven-default.txt
benchstat plain-off.txt woven-off.txt
```

Delta = woven median - plain median (benchstat, n=10). Gate: section 9.3,
with the user decision after step 5 (clean: <= +3 ns + 1.5 ns for each
operand; tainted stack: <= +1 us). Allocations: equal in all cases, except
`RuntimeTainted/*` (+1 allocation, the gate).

| Case | GOGC default | GOGC=off | Gate | Result (default / off) |
|---|---|---|---|---|
| Off/concat2-heap | +2.58 ns | +0.94 ns | <= +2 ns | FAIL / pass |
| Off/concat4-heap | +2.62 ns | +1.43 ns | <= +2 ns | FAIL / pass |
| Off/concat6-heap | +2.82 ns | +1.51 ns | <= +2 ns | FAIL / pass |
| Off/concat16-heap | +3.15 ns | +1.37 ns | <= +2 ns | FAIL / pass |
| Off/concat2-stack | +0.49 ns | +0.47 ns | <= +2 ns | pass / pass |
| Off/concat4-stack | +1.14 ns | +1.02 ns | <= +2 ns | pass / pass |
| Off/concat6-stack | +1.75 ns | +1.44 ns | <= +2 ns | pass / pass |
| Off/concat16-stack | +3.62 ns | +2.98 ns | <= +2 ns | FAIL / FAIL |
| Off/b2s-heap | +2.00 ns | +0.17 ns | <= +2 ns | pass / pass |
| Off/b2s-stack | +0.45 ns | +0.40 ns | <= +2 ns | pass / pass |
| Off/s2b-heap | +1.98 ns | +0.02 ns | <= +2 ns | pass / pass |
| Off/s2b-stack | +0.23 ns | +0.21 ns | <= +2 ns | pass / pass |
| Off/r2s-heap | -0.45 ns | -1.55 ns | <= +2 ns | pass / pass |
| Off/r2s-stack | -0.02 ns | +0.01 ns | <= +2 ns | pass / pass |
| Off/s2r-heap | +6.55 ns (±8 %) | -0.32 ns | <= +2 ns | FAIL (noise) / pass |
| Off/s2r-stack | -0.81 ns | -0.15 ns | <= +2 ns | pass / pass |
| Clean/concat2-heap | +5.87 ns | +5.64 ns | <= +6 ns | pass / pass |
| Clean/concat4-heap | +7.34 ns | +7.15 ns | <= +9 ns | pass / pass |
| Clean/concat6-heap | +9.22 ns | +8.82 ns | <= +12 ns | pass / pass |
| Clean/concat16-heap | +18.17 ns | +17.29 ns | <= +27 ns | pass / pass |
| Clean/concat2-stack | +5.08 ns | +4.81 ns | <= +6 ns | pass / pass |
| Clean/concat4-stack | +6.72 ns | +6.39 ns | <= +9 ns | pass / pass |
| Clean/concat6-stack | +8.17 ns | +7.99 ns | <= +12 ns | pass / pass |
| Clean/concat16-stack | +17.85 ns | +18.39 ns | <= +27 ns | pass / pass |
| Clean/b2s-heap | +4.22 ns | +3.85 ns | <= +4.5 ns | pass / pass |
| Clean/b2s-stack | +3.78 ns | +3.77 ns | <= +4.5 ns | pass / pass |
| Clean/s2b-heap | +4.52 ns | +4.26 ns | <= +4.5 ns | pass (re-measure: +4.45 ns pooled, see below) / pass |
| Clean/s2b-stack | +3.93 ns | +3.97 ns | <= +4.5 ns | pass / pass |
| Clean/r2s-heap | +2.39 ns | +3.65 ns | <= +4.5 ns | pass / pass |
| Clean/r2s-stack | +3.24 ns | +3.32 ns | <= +4.5 ns | pass / pass |
| Clean/s2r-heap | +3.16 ns | +4.67 ns (±7 %) | <= +6 ns (user decision) | pass (pooled re-measure: +5.49 ns, noisy) |
| Clean/s2r-stack | +3.67 ns | +4.05 ns | <= +4.5 ns | pass / pass |
| S2SOff/s2b-heap | +0.34 ns | +0.09 ns | <= +2 ns | pass / pass |
| S2SOff/s2b-stack | +0.23 ns | +0.23 ns | <= +2 ns | pass / pass |
| S2SOff/s2r-heap | -3.19 ns | +0.22 ns | <= +2 ns | pass / pass |
| S2SOff/s2r-stack | -0.83 ns | -0.13 ns | <= +2 ns | pass / pass |
| Tainted/concat2-stack | +615 ns | +629 ns | <= +1 us, +1 alloc | pass / pass |
| Tainted/b2s-stack | +426 ns | +422 ns | <= +1 us, +1 alloc | pass / pass |
| Tainted/s2b-stack | +421 ns | +424 ns | <= +1 us, +1 alloc | pass / pass |
| Tainted/r2s-stack | +814 ns | +819 ns | <= +1 us, +1 alloc | pass / pass |
| Tainted/s2r-stack | +838 ns | +844 ns | <= +1 us, +1 alloc | pass / pass |

A second GOGC=off run of `BenchmarkRuntimeOff` only (10 interleaved rounds,
`-test.benchtime=1s`) gave the same shape: concat stack +0.45 / +1.19 / +1.61
/ +3.51 ns for 2 / 4 / 6 / 16 operands, concat heap +0.74 to +1.39 ns.

The gate-off rows above compare a woven binary with an unwoven one. This
method is not valid for the gate-off rows: see the next section. With the
correct method, all the gate-off cases pass the +2 ns gate.

## Gate-off investigation (after the step 5 measurement)

### Result

The gate-off hook code is correct and small. It is the same as in the step 2
prototype. The FAIL rows above come from two measurement errors, not from
the hooks:

1. **GC cost of the woven build (heap cases, GOGC default only).** The
   woven binary also links the tracer and all the integrations. It has
   approx. 1 MB more live heap. At the 4 MB minimum heap goal of the test,
   there are 31 % more GC cycles, and each mark phase is approx. 2 times
   longer (`GODEBUG=gctrace=1`, `concat2-heap`, 2e7 operations: 369 cycles,
   mark 0.17 ms, live 1 MB; unwoven: 281 cycles, 0.09 ms, 0 MB). A woven
   binary without hooks is +1.4 to +2.1 ns slower than unwoven in all the
   heap cases, also `b2s-heap` and `s2b-heap`. With GOGC=off this difference
   is 0 (-0.65 to +0.25 ns).
2. **Code placement (all cases with a loop).** The same hook instructions,
   with the text moved by 16 to 208 bytes (a padding function in the injected
   runtime declarations), change `concat16-stack` from 41.4 to 44.5 ns
   (go1.26.6, 7 builds; the data addresses are the same in these 7 builds).
   The repository build (no padding) gives 46.3 ns. The effect is larger
   when the case has more loop iterations (`s2b-stack`: 0.02 ns range;
   `concat16-stack`: 4.9 ns range). This is why the cost "grows with
   the number of operands". The repository build (no padding) is the worst
   of the 8 placements on go1.26.6. A binary is deterministic, so a second
   run of the same binary gives the same bias. The mechanism in the CPU
   (branch prediction or fetch alignment) is not isolated.

The benchmark source is not the cause: the cases, the allocation sizes
(48 / 48 / 48 / 64 B for heap concat) and the unwoven times (within 0.8 ns)
are the same as in the prototype.

No code change to the hooks is necessary. The comment of
`iast/runtime/bench_test.go` now gives the correct method.

### Method

Scripts and data: `/tmp/perf5` (`run.sh`, `delta.py`, `padtable2.py`,
`mkpad.py`, `res/`). Each build uses its own GOCACHE. Each round runs every
binary once, and the order rotates each round. `-test.benchtime=300ms`,
`-test.count=1`, `-test.benchmem`, GOGC default unless stated.

| Binary | Build |
|---|---|
| plain | `go test -c ./iast/runtime` |
| woven (hook) | `go tool orchestrion go test -c ./iast/runtime` (repository) |
| nohook | the same, in a copy of the module where `iast/runtime/orchestrion.yml` has no prepend-statements aspect (the `runtime.g` declarations stay) |
| min, minnohook | as woven / nohook, but `orchestrion.tool.go` has only Orchestrion and `iast/runtime` (the closest build to the step 2 prototype) |
| pad k (hook, nohook) | as woven / nohook, plus `func __dd_iast_pad()` with k stores and `func init() { __dd_iast_pad() }` in the injected declarations: the runtime text after the pad moves by 16 to 208 bytes |

The step 2 prototype module (`/tmp/concathook-gate-perf/D-atomic`) cannot
run again: a clean-up of `/tmp` deleted its sources and binaries (only the
`benchstat.txt` files stay). The min build replaces it.

go1.27.1: the full woven build fails in `encoding/json` (`dec.r undefined`,
the json v2 decoder, plan encoding-json-v2). For go1.27.1, "woven" is the
repository without the `iast/encoding/json` integration ("nj").

### Generated code (go1.26.6 and go1.27.1, darwin/arm64)

- Woven `runtime/string.go` (`orchestrion go build -a -work runtime`): the
  prepended block is the template of step 2 critic round 9, before the first
  statement of the original body. Only one other runtime function is woven
  (`goexit1`, dd-trace-go).
- `go tool objdump`, hook vs nohook: the only difference in the 6 functions
  is the prepended block (24 instructions in `concatstrings`; 4 run when the
  gate is off: `ADRP`, `ADD`, `LDARW`, `CBZW` to the original body) and one
  spill in a different position. The gate check is the first code after the
  prologue. No new spill before the gate, no new stack check. Frames:
  `concatstrings` 112 -> 128 B (as in the prototype), the other 5 do not
  change (112 / 48 / 64 / 128 / 80 B, as in the prototype).
- `concatstring2..5`, `memmove`, `rawstringtmp` and the benchmark functions
  are the same instructions in all the builds (only addresses change).
  `concatstring2..5` still call `concatstrings`; they are not inlined in the
  callers in any build.
- The gate variable is in `__DATA` between 4-byte variables that the
  benchmark does not write (no false sharing).

### Numbers, gate off, delta of medians (ns)

"Step 5" is the table above (GOGC default). "Woven - plain" and "Hook -
nohook" are 12 rounds of the same run. "Pooled" is hook - nohook over 8
code placements (pad k = 0, 1, 3, 5, 7, 9, 11, 13; 10 rounds each; 80 runs
for each side), 95 % bootstrap CI. "Range" is the per-placement hook -
nohook, lowest to highest.

go1.26.6:

| Case | Step 5 | Woven - plain | Nohook - plain | Hook - nohook | Pooled [95 % CI] | Range (8 placements) | Gate |
|---|---:|---:|---:|---:|---:|---:|---|
| concat2-heap | +2.58 | +2.37 | +1.65 | +0.72 | **+0.39** [+0.20, +0.64] | -0.04..+1.31 | pass |
| concat4-heap | +2.62 | +2.62 | +1.75 | +0.86 | **+0.31** [-0.01, +0.56] | -0.30..+1.40 | pass |
| concat6-heap | +2.82 | +2.57 | +1.43 | +1.14 | **+0.30** [+0.03, +0.62] | -0.34..+1.80 | pass |
| concat16-heap | +3.15 | +4.09 | +0.90 | +3.20 | **-1.35** [-1.71, -0.92] | -2.44..+2.75 | pass |
| concat2-stack | +0.49 | +0.57 | -0.10 | +0.67 | **+0.44** [+0.30, +0.56] | -0.03..+1.02 | pass |
| concat4-stack | +1.14 | +1.11 | +0.04 | +1.07 | **+0.33** [+0.24, +0.50] | -0.10..+1.31 | pass |
| concat6-stack | +1.75 | +1.43 | -0.02 | +1.45 | **+0.55** [+0.30, +0.89] | -0.38..+1.88 | pass |
| concat16-stack | +3.62 | +1.62 | -0.20 | +1.83 | **+0.01** [-0.68, +0.96] | -1.94..+4.36 | pass |
| b2s-stack | +0.45 | +0.41 | +0.00 | +0.41 | **+0.16** [+0.11, +0.22] | -0.09..+0.49 | pass |
| s2b-stack | +0.23 | +0.19 | -0.04 | +0.24 | **+0.16** [+0.10, +0.20] | -0.01..+0.23 | pass |
| b2s-heap | +2.00 | +2.18 | +2.04 | +0.13 | - | - | pass |
| s2b-heap | +1.98 | +2.03 | +2.11 | -0.08 | - | - | pass |
| r2s-heap / r2s-stack | -0.45 / -0.02 | +0.60 / -0.28 | +0.28 / -0.48 | +0.32 / +0.21 | - | - | pass |
| s2r-heap / s2r-stack | +6.55 / -0.81 | +6.75 / +1.07 | +7.63 / +0.85 | -0.88 / +0.21 | - | - | pass (noise, see step 2) |

go1.27.1 (woven = nj):

| Case | Woven - plain | Nohook - plain | Hook - nohook | Pooled [95 % CI] | Range (8 placements) | min - minnohook | Gate |
|---|---:|---:|---:|---:|---:|---:|---|
| concat2-heap | +2.78 | +2.25 | +0.53 | **+0.33** [+0.06, +0.58] | -0.11..+0.93 | +0.88 | pass |
| concat4-heap | +2.51 | +2.36 | +0.15 | **+0.44** [+0.18, +0.71] | +0.04..+0.70 | +1.12 | pass |
| concat6-heap | +2.06 | +1.98 | +0.08 | **+0.17** [-0.09, +0.44] | -0.63..+0.74 | +1.59 | pass |
| concat16-heap | +0.95 | +2.25 | -1.30 | **-1.04** [-1.74, -0.66] | -2.16..+0.35 | +1.29 | pass |
| concat2-stack | +0.44 | +0.09 | +0.35 | **+0.40** [+0.26, +0.53] | +0.22..+1.16 | +1.13 | pass |
| concat4-stack | +0.13 | -0.12 | +0.25 | **+0.21** [+0.12, +0.30] | +0.10..+0.39 | +1.16 | pass |
| concat6-stack | +0.32 | -0.23 | +0.55 | **+0.34** [+0.14, +0.49] | -0.60..+0.59 | +1.32 | pass |
| concat16-stack | -0.68 | -0.40 | -0.28 | **-0.48** [-1.13, -0.23] | -1.75..-0.00 | +0.94 | pass |
| b2s-stack | +0.23 | +0.02 | +0.21 | **+0.21** [+0.18, +0.24] | +0.16..+0.26 | +0.13 | pass |
| s2b-stack | +0.23 | +0.07 | +0.16 | **+0.24** [+0.23, +0.25] | +0.21..+0.25 | +0.24 | pass |

The placement effect changes direction between builds: on go1.26.6 the
repository build is the worst placement and min is good (min - minnohook:
+0.47 ns worst); on go1.27.1 min is the bad one (+0.9 to +1.3 ns) and the
repository build is good. The step 2 prototype had one placement for each Go
version.

GOGC=off, go1.26.6, heap cases, 8 rounds: nohook - plain -0.65 to +0.25 ns
(the GC effect is gone); woven - nohook +0.61 / +1.06 / +1.23 / +1.91 ns for
concat 2 / 4 / 6 / 16 (the placement effect of the repository build stays).

The steady cost of the gate check is the `s2b-stack` / `b2s-stack` value,
+0.16 to +0.24 ns in every build and placement.

### s2b-heap re-measure (gate on, clean)

Method: as above (hook - nohook, the same 16 go1.26.6 binaries: pad k = 0,
1, 3, 5, 7, 9, 11, 13), GOGC default, `run.sh res/clean-heap 10 300ms
'^BenchmarkRuntimeClean$/^(s2b|b2s|s2r|r2s)-heap$' default`, 10 interleaved
rounds, 80 runs for each side. `padtable2.py` for the pooled median and the
95 % bootstrap CI; `benchstat` of the pooled files gives the same medians.
Allocations are equal (1 allocation; 48 B, or 160 B for `s2r-heap`). Gate:
+3 ns + 1.5 ns x 1 operand = +4.5 ns.

| Case | Pooled [95 % CI] | Range (8 placements) | Worst placement | Gate (pooled) |
|---|---:|---:|---:|---|
| s2b-heap | **+4.45** [+3.91, +4.86] | +3.97..+4.60 | +4.60 (k=0) | pass (margin 0.05 ns) |
| b2s-heap | **+3.84** [+3.56, +4.26] | +3.52..+4.15 | +4.15 (k=3) | pass |
| r2s-heap | **+2.05** [-1.67, +6.12] | -2.77..+5.83 | +5.83 (k=13) | pass (noise) |
| s2r-heap | **+5.49** [+2.95, +7.29] | +2.79..+8.33 | +8.33 (k=13) | FAIL (noise) |

`s2b-heap` passes with the pooled median, but the margin is small: the CI
and 3 of 8 placements (k = 0, 9, 13) are above +4.5 ns. The step 5 value
(+4.52 ns) is woven - plain, one placement, and includes the GC cost of the
woven build. `r2s-heap` and `s2r-heap` are noisy (range of 8.6 and 5.5 ns;
`s2r-heap` nohook medians are bimodal, 37 to 42 ns, as in step 2): the
`s2r-heap` FAIL is not a reliable result.

### Consequence for step 7

The gate-off row of 9.3 must use the hook - nohook comparison over more than
one code placement (the pooled value). A comparison with an unwoven binary
measures the GC cost of the linked integrations and one code placement.

## Negative controls (plan section 9.1 item 5 and step 5e)

Each control changes one file, runs the command, and restores the file (the
restored file was compared with a copy, `cmp`). Test command:
`DD_IAST_REQUIRE_WOVEN=1 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -count=1 ./iast/runtime/`.

| Control | Change | Result |
|---|---|---|
| `_ = buf` | `iast/runtime/orchestrion.yml`: `buf = nil` -> `_ = buf` (6 wrappers) | FAIL: 14 tests (TestConcatCases, TestRuneConversions, TestStackResults, TestAllocs, TestSparseRoot, TestConfirmUnknownForcesHeap, TestConfirmPanic, TestRecursionGuard, TestStackGrowth, TestIndependentStores, TestFanout, TestBypassTokenGateChange, TestBypassTokenStaleBound, TestBypassTokenSequence) |
| guard check | `__dd_iast_ok`: remove `&& gp.__dd_iast_in_hook == 0` | FAIL: TestRecursionGuard |
| `s2sGate` | the 2 string-to-slice aspects: `if atomic.Load(&__dd_iast_rt_s2s_gate) != 0 {` -> `if true {` | FAIL: TestStringToSliceSwitchOff |
| token clear | the 6 wrappers: remove `gp.__dd_iast_bypass = 0` after the inner call | FAIL: TestBypassTokenGateChange |
| `stringDataOnStack` | 3 wrappers: `!stringDataOnStack(r)` -> `true` | FAIL: TestBypassTokenGateChange, TestBypassTokenSequence |
| direct call | `__dd_iast_concatstrings`: `__dd_iast_orig_concatstrings(buf, a)` -> `concatstrings(buf, a)`; command `.github/runtime-escape-compare.sh default m <dir>` | FAIL: `escape go1.26.6-darwin-arm64-default-m: DIFFERENT` (`leaking param: buf to result ~r0 level=0` -> `leaking param: buf`) |
| admission ignores an index failure | `internal/taint/store/interior.go` `indexRoot`: `if result != insertOK {` -> `if false && result != insertOK {` | FAIL: TestForcedIndexFullIsNotTainted ("the rune root is refused") |
| `ConfirmUnknown` is clean | `internal/taint/runtimebridge/hooks.go`: `!= ConfirmClean` -> `== ConfirmTainted` (2 pre-checks) | FAIL: TestConfirmUnknownForcesHeap |

## Flaky tests fixed after the step 5 review

| Test | Before | After |
|---|---|---|
| TestConcurrentReadersDuringTierMoveNeverMiss | linux/amd64 unwoven: 0 of 10 runs pass (interior_test.go:543, `extended` false) | 10 of 10 runs pass; also 4 processes at the same time x `-test.count=10`: all pass |
| TestEventLogsHaveNoForeignEvidence | darwin/arm64, `DD_TELEMETRY_HEARTBEAT_INTERVAL=0.001` (a flush each 1 ms): 8 of 10 runs pass | 30 of 30 runs pass |
| TestIndexCapacityLimitsProcessRoots | depended on the heap address distribution (one run: 29 270 of 32 768 admitted, below the 90 % limit) | no fill limit; invariants only. New TestIndexHoldsFullCapacity: controlled addresses, all 32 768 entries are used, a root with a full window is refused |

User decision after the re-measure: the gate-on clean limit for the two rune conversions is <= +6 ns (plan section 9.3). `s2r-heap` (+5.49 ns pooled, worst placement +8.33 ns) passes it; the spread between placements is 5.5 ns.
