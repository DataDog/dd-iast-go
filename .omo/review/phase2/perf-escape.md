# perf-escape: Inlining and escape behavior of woven call sites and advice functions
Verdict: Weaving adds heap allocations to ordinary customer code whether or not IAST is enabled, sampled, or tainted. The worst case is +1 alloc on every woven `[]byte`->`string` assignment, which is avoidable. The operator "cheap gate" is never inlined into customer code, and the zero-alloc behavior of `+` chains holds only because of that accident. Correctness is unaffected. These are per-call overhead issues on the host hot path (rule 2).
Scope covered: `iast/propagation/{operators,strings,bytes,coarse,writer}.go`, `orchestrion.yml` (concat, conversion, slice aspects), `internal/taint/propagation/{propagation,operator_concat,conversion,string_exact,bytes_exact,string_coarse,writer}.go`, `internal/taint/operatorbridge`, README (Propagation coverage). Pinned orchestrion `23afa71d6dcb` flag plumbing (`internal/jobserver/pkgs/resolve.go`, `internal/toolexec/aspect/oncompile.go`). Built a 23-function customer sample (`perfsample`, root module, private copy) plain vs woven with `GOTOOLCHAIN=go1.26.6`, `-m=2`/`-m -m`, and allocs/op benchmarks, both without a request (inactive) and with an active untainted request scope. Also a plain go1.27.0 cross-check and three prototype-fix iterations plus a woven test run.

Method notes: allocs/op is deterministic, and inactive and active-untainted runs give identical counts. So every delta below is a static escape decision, not runtime gate work. Wall-clock ns/op in the logs is noisy (shared machine) and is not used for any claim. The first woven build of the sample ran against a warm cache. The peak RSS of every woven build/test was <= 300 MB, so no build-memory finding.

Plain -> woven allocs/op (evidence `bench-plain.txt`, `bench-woven.txt`; sample in `sample.go`, `sample_test.go`, `extra_test.go`):

| Customer idiom | plain | woven | cause |
|---|---|---|---|
| `s := string(b); s == "GET"` (ConvLocal) | 0 | 1 (3 B) | F1 |
| `s := string(b); len(s[1:])` (StringSliceLocal) | 0 | 1 (24 B) | F1 |
| `string(b) + ":x"` as a local map key (ConcatConvOperand) | 0 | 1 | F3 |
| 8- and 16-operand local concat | 0 | 1 (16 B) | F4 |
| `buf.String() == "abc"` | 0 | 1 | F5 |
| `strconv.Quote(a)` length | 1 | 2 | F5 |
| local `strings.Builder` / `bytes.Buffer` | 1 | 2 (+32 B / +48 B) | F6 (documented) |
| 2-5 operand concat, `buf[:n]` on `make([]byte,64)`, string slicing, `Cut`, `TrimSpace`, `SplitSeq`/`FieldsSeq` ranges, `Join` of a slice literal, `Sprintf`, `ToLower` | = | = | no delta |

## Findings
### perf-escape-F1: Every woven []byte->string assignment/declaration/return heap-allocates, even with IAST off
- Severity: High
- Category: perf
- Location: iast/propagation/operators.go:197-204; iast/propagation/orchestrion.yml:327-341
- Claim: `BytesToString[go.shape.[]uint8]` costs 131 against a budget of 80 in customer packages, so it is never inlined. Its `result := string(value)` is returned and escapes (`operators.go:199:19: string(propagation.value) escapes to heap`). In plain Go, a non-escaping `s := string(b)` uses a 32-byte stack buffer (`sample.go:24:14: string(b) does not escape`). Every wrapped conversion therefore gains a heap allocation on every execution. That includes sampled-out requests, code outside requests, and processes with IAST disabled, because the `HasValues()` gate runs only after the allocation. README:31 advertises these conversions as "allocation-preserving", which is false for non-escaping results. Assignment and declaration of `string(b)` is among the most common idioms in parsing and handler code, so this is a per-call cost many times larger than the necessary price of a gate check.
- Evidence: `.omo/review/evidence/perf-escape/bench-plain.txt` vs `bench-woven.txt`: `BenchmarkSample/ConvLocal 0 B/op 0 allocs/op` -> `3 B/op 1 allocs/op`, and `StringSliceLocal 0 -> 24 B/op 1 allocs/op`. The same counts appear under `BenchmarkActive/...`. `woven-m2.txt` and `woven-pkgscoped-m2.txt` show the escape. Commands, run in the private copy: `GOTOOLCHAIN=go1.26.6 go test -run '^$' -bench . -benchtime=20000x ./perfsample`, and the same prefixed with `go tool orchestrion`. Prototype `prototype-fix-v3.patch` restores `ConvLocal 0 allocs/op` and `StringSliceLocal 0 allocs/op` (`bench-woven-prototype-v3.txt`), and woven `iast/propagation` plus `internal/taint/propagation` tests pass (`prototype-v3-woven-tests.txt`).
- Fix: Emit a non-generic, inlinable gate in the template: `{{ .AST.Fun }}(iastprop.BytesToStringValue([]byte(x)))` with `func BytesToStringValue(v []byte) string { if !operatorbridge.HasValues() { return string(v) }; return bytesToStringSlow(v) }`, where the slow path is `//go:noinline` and keeps the current allocate-and-adopt behavior. Inline cost is 78. It must be non-generic because of F2. Add a woven `testing.AllocsPerRun` regression test.

### perf-escape-F2: The operator fast gate is never inlined in customer builds, and ConcatN zero-alloc depends on that accident
- Severity: Medium
- Category: perf
- Location: iast/propagation/operators.go:18-196 (concatNResult), 197-304; internal/taint/operatorbridge/bridge.go:17
- Claim: If the instantiating package does not import `internal/taint/operatorbridge`, the Go inliner does not inline `operatorbridge.HasValues` into instantiated generic bodies from `iast/propagation`. Customer packages never import it, since it is `internal`. Every woven concat, slice and conversion therefore makes out-of-line calls before the "allocation-free operator fast gate": for example, `StringSliceLow` shape cost 133 means it is not inlined, and `HasValues` is another call inside it. This is a plain Go behavior, not Orchestrion's: it reproduces with `go build` on go1.26.6 and go1.27.0. Non-generic transitive inlining works, as `utf8.DecodeRuneInString` does in `plain-m2.txt`. Worse, 2-7 operand concats stay allocation-free only because of this. When `HasValues` is inlinable (blank import), `concat2Result`/`concat3Result` drop to 79/80, get inlined, and push `Concat2`/`Concat3` to 91/94, over budget. Their results then escape. So any toolchain inliner tweak or future Orchestrion import injection silently flips 2-3 operand concats to +1 alloc.
- Evidence: `.omo/review/evidence/perf-escape/gate-transitive-inlining.txt`. Without the import: `cannot inline propagation.concat2Result...: cost 126`, and `BytesToString... cost 131`. With `_ ".../operatorbridge"`: `inlining call to operatorbridge.HasValues`, `can inline concat2Result ... cost 79`, `cannot inline propagation.Concat2[go.shape.string]: ... cost 91`. The go1.27.0 section is identical to the no-import case. Woven bench with a natural import (`gate.go`): `ConcatLocal 8 B/op 1 allocs/op`, `ConcatLocal2 3 B/op 1`, `ConcatConvOperand 8 B/op 2`. Without it: 0, 0, and 1.
- Fix: Mark every `concatNResult` `//go:noinline`, which prototype v2 verified keeps Concat2-5 at 0 allocs. Route gates through non-generic inlinable helpers, as in F1. Add alloc-count tests for woven 2-, 3-, 7- and 8-operand concats, so budget drift fails CI.

### perf-escape-F3: copy() into the local inputs array makes every concat/Join operand leak to the heap
- Severity: Medium
- Category: perf
- Location: internal/taint/propagation/string_exact.go:56; internal/taint/propagation/bytes_exact.go:43
- Claim: `copy(inputs[:inputCount], elements[:inputCount])` is modelled by escape analysis as flowing element contents to the heap (`string_exact.go:50:36: parameter elements leaks to {heap} ... copy(...) (copied slice)`). Through `JoinString` -> `internal.ConcatN` -> `concatNResult`, every operand of a woven `+` chain and of `strings.Join`/`bytes.Join` leaks (`sample.go:15: leaking param: method`, `path`). The compiler-optimized zero-copy `string(b) + "x"`, which the design deliberately leaves unwrapped as an optimized conversion context, becomes a real heap string.
- Evidence: `bench-plain.txt` -> `bench-woven.txt`: `BenchmarkExtra/ConcatConvOperand 0 allocs/op` -> `3 B/op 1 allocs/op`. The woven dump shows `sample.go:159: string(b) escapes to heap`. With the loop fix (`prototype-fix-v2.patch`/`v3`): `elements does not escape` (`prototype-v2v3-m-diagnostics.txt`) and `ConcatConvOperand 0 B/op 0 allocs/op` (`bench-woven-prototype-v3.txt`).
- Fix: Replace both `copy` calls with `for i := 0; i < inputCount; i++ { inputs[i] = elements[i] }`.

### perf-escape-F4: Concat wrappers for 8-16 operands are not inlinable, so their non-escaping results always heap-allocate
- Severity: Medium
- Category: perf
- Location: iast/propagation/operators.go:90-196
- Claim: The `Concat8`..`Concat16` shape functions cost 81..97, so `a+...+h` runs in an out-of-line body and escapes (`operators.go:91:60: ... escapes to heap`). Plain Go stack-allocates a non-escaping result of up to 32 bytes. This adds +1 alloc per execution, unconditionally.
- Evidence: `bench-woven.txt`: `ConcatLocal8 16 B/op 1 allocs/op` and `ConcatLocal16 16 B/op 1 allocs/op`, against 0 in `bench-plain.txt`. It is not fixed by prototypes v1-v3 (Concat8 was 152 with a gate-first body).
- Fix: Needs design work. Options are a caller-side temporary via the template (for example, compute the result once and pass it together with the operands through a non-generic helper), or capping wrapped arity where the budget allows. At minimum, document it and cover it with an alloc test.

### perf-escape-F5: Non-inlinable wrappers force fresh results that plain code keeps on the stack to escape
- Severity: Low
- Category: perf
- Location: iast/propagation/writer.go:190-200; coarse.go:86-99; strings.go:19-22
- Claim: `bytes.Buffer.String`, `strconv.Quote*` and `strings.Clone` inline natively, and their fresh result can stay on the stack. The wrappers (`BufferString` 220, `StrconvQuote` 146, `StringsClone` 98) cannot be inlined, so the result escapes (`coarse.go:87:44: string(strconv.appendQuotedWith(...)) escapes to heap`; `writer.go:193:23`).
- Evidence: `bench-woven.txt`: `BufferStringLocal 0 -> 3 B/op 1 allocs/op`, `QuoteLocal 1 -> 2 allocs/op`. A gated `BufferString` prototype still costs 123 (`woven-prototype-m2.txt`), so this is not a one-liner.
- Fix: Use a tiny non-generic inlinable gate wrapper that returns the native call when `!WriterActive()`/inactive, with a `//go:noinline` slow path. Accept Clone.

### perf-escape-F6: Writer receiver escape is unconditional; the README says it only "can" happen
- Severity: Low
- Category: doc
- Location: README.md:70-71; iast/propagation/writer.go:19-200
- Claim: This is a documented and accepted trade-off. Measured: any local `strings.Builder`/`bytes.Buffer` with at least one wrapped call is `moved to heap` in every woven build, regardless of enablement, sampling or taint. The cost is +1 alloc, +32 B for a Builder and +48 B for a Buffer. "Can make a stack receiver escape" understates it: it always does.
- Evidence: `woven-m2.txt` (`perfsample/sample.go:54: moved to heap: sb`, `:64: moved to heap: buf`). `BuilderLocal 8 B/1 -> 40 B/2`, `BufferLocal 64 B/1 -> 112 B/2`.
- Fix: Reword the README ("always escapes; +1 allocation per local writer, even with IAST disabled").

### perf-escape-F7: No named-call wrapper is inlinable, and none has an inlinable pre-gate
- Severity: Low
- Category: perf
- Location: iast/propagation/strings.go:19-218; bytes.go:15-194; coarse.go:19-104; writer.go:19-200
- Claim: All ~75 strings/bytes/fmt/url/strconv wrappers exceed the budget (98-220). Buffer wrappers use `defer` (`cannot inline BufferWrite: unhandled op DEFER`). Natively inlined `strings.Cut`/`CutPrefix`/`TrimPrefix`/`Builder.WriteString`/`String` become two or more out-of-line calls (the wrapper, then `internal.StringWindow` at cost 268, which only then checks `ActiveStore()`) even with IAST disabled. Unlike the operators, there is no call-site gate. There are no extra allocations: CutLocal and TrimLocal stay at 0.
- Evidence: `advice-m2.txt` (for example `cannot inline StringsCut: function too complex: cost 209`, `cannot inline StringWindow: ... cost 268`).
- Fix: Optional. For hot, natively inlinable APIs (Cut*, Trim*, Builder String/WriteString), split into an inlinable `if inactive { return native }` plus a noinline slow path, as in F1.

### perf-escape-F8: Woven builds reject -gcflags=-m=2
- Severity: Info
- Category: ci
- Location: orchestrion@23afa71d6dcb toolexec compile-flag handling (child builds reuse parent flags, internal/jobserver/pkgs/resolve.go:197-224)
- Claim: `go tool orchestrion go build -gcflags='-m=2'` fails with `invalid boolean value "2" for -m`. The first failure came while resolving woven dependency `iobridge`, and a later one on the target package. Plain `go build` with the same compiler accepts the flag. `-m -m` or package-scoped gcflags work.
- Evidence: `.omo/review/evidence/perf-escape/woven-m2-flag-error.txt`.
- Fix: Report upstream, and use package-scoped `-gcflags='<pkg>=-m -m'` in audit docs.

## Checked and found correct
- Byte and string slicing wrappers do not make operands escape: `make([]byte, 64) does not escape` in the woven build, and `ByteWindow`/`StringWindow` do not leak input or output. ByteSliceLocal and StringSlice are 0 allocs apart from F1's conversion.
- The `SplitSeq`/`FieldsSeq`/`Lines` wrappers fully inline into range loops. All func literals `does not escape`, with 0 extra allocs. A non-ranged `SplitSeq` passed to a function is 2 allocs plain and 2 woven.
- `FmtSprintf` keeps `... argument does not escape` (21 B / 2 allocs plain and woven). `StringsJoin` keeps the `[]string{...}` literal on the stack. `ToLower` of already-lowercase input stays at 0.
- Allocation counts are identical for inactive and active-untainted runs. The runtime gates (`ActiveStore()==nil`, `MayContain`) prevent all work-driven allocation, and every delta is static.
- The v3 prototype for F1-F3 keeps woven `iast/propagation` and `internal/taint/propagation` tests green (`prototype-v3-woven-tests.txt`).

## Not covered / open questions
- Wall-clock cost of the extra calls in F2/F7 (the machine was shared, so no timing claims), and GC impact at production allocation rates.
- `iast/net/http`, `io`, `bufio`, `encoding/json`, `database/sql` and `os/exec` advice escape behavior. These are call-per-request or call-per-sink, not per-expression, and were not dumped.
- Behavior with PGO (`-pgo=auto`) builds, which raise inline budgets for hot sites and could change F2/F4 outcomes.
- Whether Orchestrion should inject a blank import of the bridge. Per F2, that would currently regress Concat2/3.
