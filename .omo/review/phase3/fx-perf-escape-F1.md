# fx-perf-escape-F1: byte-to-string conversion allocations

## Verdict per finding

**perf-escape-F1: CONFIRMED.** At HEAD `2e23b46`, woven short, nonempty
`[]byte`-to-`string` conversions used only locally allocate once where plain Go
allocates zero times. This holds for a local assignment and a returned
conversion subsequently used locally. The word "every" is too broad: an empty
conversion allocated zero times in both builds, and conversions that already
escape in plain Go need not gain an allocation. The actionable hot-path
regression is real. The local and return cases are **one root cause**, not two
findings.

## Reproduction (commands + key output lines)

Independent fixture: `.omo/review/evidence/fx-perf-escape-F1/repro.go` and
`repro_test.go`, placed in `<copy>/reviewf1/` after copying the repository into
the required private workspace. Captured output:
`.omo/review/evidence/fx-perf-escape-F1/output.txt`. Commands ran in
`/tmp/ddiast-review/wt/fx-perf-escape-F1` with `GOFLAGS=-p=4` and
`GOTOOLCHAIN=go1.26.6`, and all exited 0:

```sh
go test -timeout 10m -count=1 -run '^Test(Short|Empty)ByteConversionAllocation$' -bench '^BenchmarkShortHeaderConversion$' -benchtime=20000x -benchmem -v ./reviewf1
/usr/bin/time -l go tool orchestrion go test -timeout 10m -count=1 -run '^Test(Short|Empty)ByteConversionAllocation$' -bench '^BenchmarkShortHeaderConversion$' -benchtime=20000x -benchmem -v ./reviewf1
DD_IAST_ENABLED=false /usr/bin/time -l go tool orchestrion go test -timeout 10m -count=1 -run '^TestShortByteConversionAllocation$' -v ./reviewf1
DD_IAST_REQUEST_SAMPLING=0 /usr/bin/time -l go tool orchestrion go test -timeout 10m -count=1 -run '^TestShortByteConversionAllocation$' -v ./reviewf1
```

Plain `local`/`returned`: **0/0 allocs/run**; woven under defaults: **1/1**;
woven with IAST disabled: **1/1**; woven with sampling set to zero: **1/1**.
The empty-input control was **0** in both builds. Benchmark:
`0 B/op 0 allocs/op` plain versus `16 B/op 1 allocs/op` woven. Woven peak RSS
was 106,201,088 bytes, below the brief's 4 GB reporting threshold. No
wall-clock performance conclusion is drawn.

Compiler escape diagnostics from the same fixture:

```text
reviewf1/repro.go:6:17: string(raw) does not escape
reviewf1/repro.go:23:24: string(raw) does not escape
./iast/propagation/operators.go:198:6: cannot inline propagation.BytesToString[go.shape.[]uint8]: function too complex: cost 131 exceeds budget 80
./iast/propagation/operators.go:199:19: string(propagation.value) escapes to heap in BytesToString[go.shape.[]uint8]:
```

## Reachability

**Yes, by default on the supported Go 1.26.6 toolchain.** A direct
`name := string(raw)` or a conversion returned from a helper in a root
application package receives the aspect even without an active request. The
weave and compiler diagnostics confirm the fixture's actual call to
`BytesToString`, not just an Orchestrion build flag. Default configuration
enables IAST and samples 30% of requests (`internal/config/config.go:68-70`);
neither a sampled-in request nor any request at all is needed for the extra
allocation. The disabled and zero-sampling runs demonstrate that configuration
cannot avoid it.

**Not a documented/accepted limitation.** `README.md:31` calls these
assignment/declaration/return conversions "allocation-preserving"; the
deliberate omission of compiler-optimized comparison/call/map-key contexts
does not cover this supported form. The accepted writer-receiver escape
trade-off concerns a different operation. An unavoidable per-execution heap
allocation on this hot path violates the repository rule to avoid unnecessary
host slowdown.

## Adjusted severity

**High (unchanged):** a routine, short conversion gains a heap allocation on
every call even when IAST is inactive, a hot-path overhead several times larger
than the necessary gate check under the brief's High criterion.

## Root cause (file:line)

`iast/propagation/orchestrion.yml:327-341` inserts the generic wrapper at
eligible conversion expressions. `iast/propagation/operators.go:197-204`
converts at line 199 **before** `HasValues()` at line 200. The shape-specific
wrapper costs 131 in the caller (inlining budget 80), so a short conversion
that the native caller could keep on its stack escapes inside the out-of-line
wrapper. One mechanism covers assignment, declaration, and locally consumed
return forms.

## Minimal fix

Emit a non-generic, inlinable gate helper at the conversion site, explicitly
convert named byte slices to `[]byte` in the aspect while retaining the
outer target-string conversion, and move the existing taint-adoption branch
behind a non-inlinable slow helper. Keep the inactive native `string(value)`
conversion visible to caller escape analysis; lock its zero-allocation
behavior with a woven allocation test for short local and returned values.
