# Plan: runtime operator hooks and interior-pointer taint lookup

## Status

- **State:** approved; revised after critic rounds 1, 2, 3, 5, 6, 7, 8 and 9 (see appendices A to G, and H.6 for round 9), after the user answers Q2-Q9 (section 12), and after step 2 (the hook template is now variant D, without `defer`; section 2.2 and appendix H)
- **Replaces:** the operator part of [taint-tracking-net-http-sqli-cmdi-phase-6.md](./taint-tracking-net-http-sqli-cmdi-phase-6.md) (sections 3.2, 3.3, 3.4, 4.1, 4.2, 4.3 and 10)
- **Evidence:** prototype `/tmp/concathook` (`REPORT.md`, v1 and v2 sections, and `artifacts/`); step 2 gate `/tmp/concathook-gate/REPORT.md` (with the section "Performance investigation (gate off)", artifacts in `/tmp/concathook-gate/artifacts/perf/`, module `/tmp/concathook-gate-perf/D-atomic`); Go sources of go1.26.6 and go1.27.1
- **Toolchains:** Go 1.26.6 (the `go` line of every `go.mod`) and Go 1.27.1. Supported: go1.26.x and go1.27.x only (Q3, section 3.10)
- **Orchestrion target:** v1.13.1 (decided from facts, section 6.3)

### User decision (Romain)

Remove the unmerged Orchestrion pin completely. Do not wait for DataDog/orchestrion#881.

### Why this plan exists

Three review findings block the release:

| ID | Severity | Finding |
|---|---|---|
| C2 | Critical | `go.mod` pins `github.com/DataDog/orchestrion v1.12.2-0.20260828141217-23afa71d6dcb` (unmerged PR #881). The released Orchestrion (v1.13.1) has no `string-concat`, `type-conversion` or `slice-expression` join point. Minimal version selection picks the released version in customer builds, and our aspects then fail to load. |
| C4 | Critical | The AST wrappers change Go semantics. Go does not evaluate some operands (for example the array in `len([N]T{a + b})` or `cap(...)`, and some `range` operands). A wrapper call makes the expression non-constant, so Go now evaluates it. This can panic or run side effects. |
| H27 | High | The wrappers allocate even when IAST is off. |

This plan moves operator propagation into the Go runtime (concat and conversions) and into the taint store (slicing). Then no source-expression join point is necessary.

### Terms used in this plan

- **Hook:** code that Orchestrion injects into a `runtime` function body.
- **Bridge:** a small package that the runtime hook calls through `//go:linkname`. It has almost no dependencies.
- **Gate:** one `uint32` global. Zero means "off". The runtime reads it first.
- **Root:** a managed allocation that the store holds strongly until the request owner finishes. See `internal/taint/store/root.go`.
- **Window:** a part `[offset, offset+length)` of one root.
- **Interior pointer:** a data pointer that points inside a root, not only at its first byte.
- **Granule:** a fixed-size, aligned address block (4 KiB in this plan).

## 1. Current state (facts from the code)

### 1.1 Operator aspects that need the unmerged Orchestrion

File `iast/propagation/orchestrion.yml`:

| Aspect IDs | Join point | Wrapper in `iast/propagation/operators.go` |
|---|---|---|
| `operator string concat 2` ... `operator string concat 16` | `string-concat` | `Concat2` ... `Concat16` |
| `operator bytes to string conversion` | `type-conversion: {from: bytes, to: string}` | `BytesToString` |
| `operator string slice` | `slice-expression: {operand: string}` | `StringSliceAll`, `StringSliceLow`, `StringSliceHigh`, `StringSliceBounds` |
| `operator byte slice` | `slice-expression: {operand: bytes}` | `BytesSliceAll`, `BytesSliceLow`, `BytesSliceHigh`, `BytesSliceBounds`, `BytesSliceFull`, `BytesSliceFullZero` |

Internal code that only these wrappers use:

- `internal/taint/propagation/operator_concat.go`: `Concat2` ... `Concat16`. Each one calls `JoinString(elements, "", result)` (`internal/taint/propagation/string_exact.go`).
- `internal/taint/propagation/conversion.go`: `BytesToString(input, result)`.
- `internal/taint/operatorbridge`: the `HasValues()` fast gate.

The named wrappers (`strings.Cut`, `bytes.TrimSpace`, `fmt.Sprintf`, and so on) use `function-call`, `method-call` and `function-body`. These join points exist in released Orchestrion. They stay.

### 1.2 Store lookup is exact-key only

`internal/taint/store`:

- `Key{Pointer, Length, Kind}` is the lookup key (`store.go`).
- `Store.MayContain(key)` hashes the key, takes `shard.mu.TryRLock()`, and probes at most `ProbeLimit` (64) slots (`lookup.go`). Contention is a miss.
- `Store.Lookup(key, &snapshot)` copies at most `MaxSnapshotOwners` (4) owner entries. It validates owner generation, owner state, root generation and `root.setGen`, under `lifecycleMu.TryRLock` and `rootsMu.TryRLock`.
- A value slot stores `rootOff`; ranges are root-relative (`ranges.Slice(..., window.rootOff, end)`).
- `Owner.Derive(key, root)` (`root.go`) calls `putWindow`. `putWindow` checks `inWindow(pointer, length, root.base, root.span)` and inserts one exact slot.

Result: `s[i:j]` is tainted only when some hook calls `Derive` for that exact pointer and length. Today, the slice aspects do this through `internal.StringWindow` and `internal.ByteWindow` (`internal/taint/propagation/propagation.go`).

### 1.3 Root lifetime (important for address reuse)

- `rootRecord.stringAnchor` / `rootRecord.bytesAnchor` hold the root memory strongly (`store.go`).
- `Owner.Finish()` (`owner.go`) takes `lifecycleMu.Lock()` and `rootsMu.Lock()`, clears every anchor, and sets `root.generation` to 0.
- Adoption (`AdoptString`, `AdoptBytes`) requires that the value starts at its allocation base. Span is `len` for strings and `cap` for bytes.

Thus, while a root generation is live, the GC cannot free or reuse any address in `[base, base+span)`. After `Finish`, every stale reference fails the generation check.

### 1.4 Limits (`internal/taint/store/limits.go`)

| Constant | Value |
|---|---|
| `MaxOwners` | 64 |
| `MaxRootsPerOwner` | 512 (so at most 32 768 roots in the process) |
| `ProcessRootBytes` | 8 MiB |
| `RequestRootBytes` | 2 MiB |
| `MaxRootBytes` | 64 KiB |
| `Shards` x `SlotsPerShard` | 256 x 128 = 32 768 value slots |
| `ProbeLimit` | 64 |
| `MaxSnapshotOwners` | 4 |
| `ProcessValueLimit` / `RequestValueLimit` | 16 384 / 4 096 value slots |
| `MaxValuesPerRoot` | 256 |

Step 3 deletes the value table and all its limits: `Shards`, `SlotsPerShard`, `ProbeLimit`, `ProcessValueLimit`, `RequestValueLimit`, `MaxValuesPerRoot`, `compactionThreshold`, `tombstone` (section 5.4, Q4). Today every root uses one value slot (`putWindow` at admission), so the current store admits at most 16 384 roots in the process (and 512 in one request, from `MaxRootsPerOwner`), and derived windows use the same slots.

### 1.5 Runtime weaving precedent

dd-trace-go v2.11.0-rc.1 already weaves `runtime` with released Orchestrion (`internal/orchestrion/gls.orchestrion.yml`):

- `struct-definition: runtime.g` + `add-struct-field: __dd_gls_v2 any`;
- `inject-declarations` with `//go:linkname __dd_orchestrion_gls_get __dd_orchestrion_gls_get.V2`. The definition in `runtime` has a push `//go:linkname`, so the linker check permits the reference (section 3.9);
- `function-body` on `goexit1` with `prepend-statements`.

Every application that uses dd-trace-go with Orchestrion already rebuilds `runtime`. This plan adds more aspects to the same rebuild.

## 2. Prototype evidence and hook template

### 2.1 Phase 0 prototype (summary of `/tmp/concathook/REPORT.md`)

- Released Orchestrion v1.13.1 can weave `runtime.concatstrings` and `runtime.concatbytes`.
- Historical correction. Phase 0 section 4.1 said that result values are not observable (Phase 0 claim (a)). That statement is not correct: `fieldAt` in `internal/injector/aspect/advice/code/dot_function.go` gives the name `__result__N` to unnamed results, so `{{ .Function.Result 0 }}` gives `__result__0`. The function is identical in the current pin (v1.12.2-0.20260828141217-23afa71d6dcb) and in v1.13.1 (checked with `diff`). v1.4.0 has it too. The v1 and v2 prototypes used it: a `defer` read the result. The template of this plan (variant D, section 2.2) does **not** use it: the wrapper gets the result as a normal return value. The runtime functions keep their unnamed results.
- A bodyless `//go:noescape` linknamed declaration keeps escape analysis the same: `concatstring2..5` still say `[]string{...} does not escape`. (This removes Phase 0 blocker (b).)
- Gate off with the `defer` template: **0 extra allocations, 0 extra bytes**, approx. +0.5 to +1.4 ns for each concat in the Phase 0 runs. Step 2 measured up to +4.4 ns for conversions with the same template, and found that the `defer` is the cause (appendix H). Variant D removes the `defer`.
- v2 pre-check: if `buf != nil` and one operand is tainted, the hook sets `buf = nil`. Then the runtime puts a short result on the heap, and the result hook can see it. Cost with gate on and clean operands: approx. +4.6 ns (go1.27.1) / +5.3 ns (go1.26.6) for each short non-escaping concat. Cost with a tainted operand: 0 -> 1 allocation (<= 32 B), approx. +11 ns.
- `atomic.Load` from `internal/runtime/atomic` (Orchestrion alias `__orchestrion_atomic`) costs less than 1 ns on arm64. It is not measurable (step 2 variant C: no difference against a plain load).
- Results in a stack buffer are detected with `stringDataOnStack` and skipped. A negative control proved that the test detects this.
- Pass on go1.27.1 and go1.26.6, with and without `-race`.
- Not tested in Phase 0: amd64, `-gcflags=all=-N -l`, the GLS aspect in the same build. Step 2 tested all three (appendix H).

### 2.2 Hook template: variant D (no `defer`)

Source: `/tmp/concathook-gate/artifacts/perf/yaml/D-atomic.orchestrion.yml` (generated by `artifacts/perf/gen.py` from one table of the 6 functions). Step 2 selected it (appendix H). Critic round 9 moved the context check before the wrapper call and added the signature assertions (appendix H.6). Step 5 copies it into `iast/runtime/orchestrion.yml`.

How it works, for each hooked function `<fn>`:

1. **Outer entry** (prepended statements in `runtime.<fn>`): one atomic load of the gate. Gate 0: the original body runs. This is the only added work with the gate off. The frame, the prologue and the result of `<fn>` do not change (appendix H).
2. Gate not 0: read the bypass token of the current `g`. Token 1: this is an inner entry (item 4). Token 0: call the `//go:nosplit` context check `__dd_iast_ok()` (3.3). It returns false: the original body runs directly (no wrapper frame, no token, no bridge call). It returns true: after step 7, call the bridge filter check `__dd_iast_rt_<x>_hit(args)` (section 13.4; `slicerunetostring` calls it first in its wrapper). It returns false (no input can be tainted): the original body runs directly. It returns true: `return __dd_iast_<fn>(args)`.
3. **Wrapper** `__dd_iast_<fn>` (`//go:noinline`, in the shared declarations, section 3.5): the pre-check with the guard (3.2.1, 3.4) and `buf = nil` on a hit; set the bypass token; call the original function through the alias `__dd_iast_orig_<fn>`; clear the token; call the result hook with the guard when the result is not on the stack. The wrapper has no context check: its only caller called `__dd_iast_ok()` immediately before.
4. **Inner entry** (the same prepended statements, in the call from the wrapper): the gate is not 0 and the token is 1, so it clears the token and runs the original body. It does not call `__dd_iast_ok()`.

Rules that this template depends on:

- **Context check before the wrapper** (3.3, critic round 9): the wrapper is a normal function, so it has a stack check at entry. On `g0` or `gsignal`, a failed stack check calls `morestack`, and `morestack` on `g0` or `gsignal` is fatal (`runtime/asm_arm64.s` and `asm_amd64.s` call `badmorestackg0` / `badmorestackgsignal`, `runtime/proc.go`: a fatal error). Thus the prepended code calls `__dd_iast_ok()` **before** the wrapper, and when the context is not safe, no frame with a stack check is added. `__dd_iast_ok()` is `//go:nosplit` and has no call (`getg()` is a compiler intrinsic; `mp.preemptoff == ""` is a length compare), so it cannot grow the stack. Step 2 disassembly (go1.26.6 and go1.27.1, arm64): it is inlined into all 6 functions with default flags; with `-gcflags=all=-N -l` it is a leaf function with no frame, no stack check and no call. Test: 9.1 item 15.
- **Alias rule** (3.8, 3.9, R3, R21): the wrapper calls the original function **only** through a body-less `//go:linkname __dd_iast_orig_<fn> runtime.<fn>` + `//go:noescape` declaration. It never calls `<fn>` directly.
- **Bypass token rules** (3.4.2): set immediately before the inner call, consumed at the inner entry, cleared again by the wrapper after the inner call.
- **Signature check** (3.9 item 6): the alias and the wrapper repeat the signature of `<fn>`. Three compile-time assertions for each function (`<fn>`, the alias, the wrapper, all assigned to one func type) make a signature change or a mismatch a build failure.
- **Q2 switch in a nested `if`** (4.3): `stringtoslicebyte` and `stringtoslicerune` check `s2sGate` in an `if` inside the gate check, not with `&&`, so that their gate-off path stays `LDARW` + `CBZW`.
- No `{{ .Function.Result 0 }}` and no result renaming. The escape comparison (3.8) needs no `__result__0` normalization.

YAML (concat; the other five functions follow the same pattern, sections 4.2, 4.3, 4.5; full file in the artifact):

```yaml
  - id: iast-runtime-decls
    join-point:
      struct-definition: runtime.g
    advice:
      - add-struct-field:
          name: __dd_iast_in_hook
          type: uint8
      - add-struct-field:
          name: __dd_iast_bypass
          type: uint8
      - add-blank-import: unsafe
      - inject-declarations:
          links:
            - github.com/DataDog/dd-iast-go/internal/taint/runtimebridge # prototype: example.com/gate/bridge
          template: |-
            //go:linkname __dd_iast_rt_gate __dd_iast_rt.gate
            var __dd_iast_rt_gate uint32

            //go:linkname __dd_iast_rt_s2s_gate __dd_iast_rt.s2s_gate
            var __dd_iast_rt_s2s_gate uint32

            //go:linkname __dd_iast_rt_concat_pre __dd_iast_rt.concat_pre
            //go:noescape
            func __dd_iast_rt_concat_pre(a []string) bool

            //go:linkname __dd_iast_rt_concat_hook __dd_iast_rt.concat_hook
            //go:noescape
            func __dd_iast_rt_concat_hook(res string, a []string)

            // ... the other 8 bridge declarations (concat_bytes_hook, bytes_pre,
            // from_bytes, str_pre, to_bytes, runes_pre, from_runes, to_runes)

            //go:nosplit
            func __dd_iast_ok() bool {
              gp := getg()
              mp := gp.m
              return gp == mp.curg && mp.locks == 0 && mp.mallocing == 0 && mp.preemptoff == "" && gp.__dd_iast_in_hook == 0
            }

            //go:linkname __dd_iast_orig_concatstrings runtime.concatstrings
            //go:noescape
            func __dd_iast_orig_concatstrings(buf *tmpBuf, a []string) string

            var _ func(*tmpBuf, []string) string = concatstrings
            var _ func(*tmpBuf, []string) string = __dd_iast_orig_concatstrings
            var _ func(*tmpBuf, []string) string = __dd_iast_concatstrings

            // The only caller is the prepended code of the original function, after
            // __dd_iast_ok() returned true. Thus this function has no context check.
            //go:noinline
            func __dd_iast_concatstrings(buf *tmpBuf, a []string) string {
              gp := getg()
              if buf != nil {
                gp.__dd_iast_in_hook = 1
                hit := __dd_iast_rt_concat_pre(a)
                gp.__dd_iast_in_hook = 0
                if hit {
                  buf = nil
                }
              }
              gp.__dd_iast_bypass = 1
              r := __dd_iast_orig_concatstrings(buf, a)
              gp.__dd_iast_bypass = 0
              if len(r) != 0 && !stringDataOnStack(r) {
                gp.__dd_iast_in_hook = 1
                __dd_iast_rt_concat_hook(r, a)
                gp.__dd_iast_in_hook = 0
              }
              return r
            }

            // ... alias, 3 assertions and wrapper for concatbytes,
            // slicebytetostring, stringtoslicebyte, slicerunetostring,
            // stringtoslicerune

  - id: iast-concatstrings
    join-point:
      all-of:
        - import-path: runtime
        - function-body:
            function:
              - name: concatstrings
    advice:
      - prepend-statements:
          imports:
            atomic: internal/runtime/atomic
          template: |-
            {{- $buf := .Function.Argument 0 -}}
            {{- $a := .Function.Argument 1 -}}
            if atomic.Load(&__dd_iast_rt_gate) != 0 {
              if __dd_iast_gp := getg(); __dd_iast_gp.__dd_iast_bypass != 0 {
                __dd_iast_gp.__dd_iast_bypass = 0
              } else if __dd_iast_ok() {
                return __dd_iast_concatstrings({{ $buf }}, {{ $a }})
              }
            }
```

Generated code (woven go1.27.1, checked again after critic round 9; the files `artifacts/perf/D-atomic-woven-string.go.txt` and `D-atomic-woven-runtime2.go.txt` show the first D). The result is not renamed, and Orchestrion adds the import as `__orchestrion_atomic`:

```go
// runtime/string.go
func concatstrings(buf *tmpBuf, a []string) string {
//line <generated>:1
	{
		if __orchestrion_atomic.Load(&__dd_iast_rt_gate) != 0 {
			if __dd_iast_gp := getg(); __dd_iast_gp.__dd_iast_bypass != 0 {
				__dd_iast_gp.__dd_iast_bypass = 0
			} else if __dd_iast_ok() {
				return __dd_iast_concatstrings(buf, a)
			}
		}
	}
//line /opt/homebrew/Cellar/go/1.27.1/libexec/src/runtime/string.go:30
	idx := 0
	... original body ...

// runtime/runtime2.go (type g)
	__dd_iast_in_hook uint8
	__dd_iast_bypass  uint8
	__dd_gls_v2       any
```

Gate-off machine code (arm64, `stringtoslicebyte`, go1.27.1 and go1.26.6): `ADRP` + `ADD` + `LDARW` of the gate, then `CBZW` to the original body. Nothing else. The inlined `__dd_iast_ok()` adds 12 instructions to the gate-on branch only; the frame sizes do not change (appendix H.6).

Changes in step 5 against the step 2 artifact: `links:` names `internal/taint/runtimebridge` **and** `internal/taint/propagation` (3.2 rule 6: the propagation package registers the callbacks); the real bridge implements `confirm` (3.2.1). (The context check before the wrapper and the signature assertions are in the artifact since critic round 9.)

Change after step 7 (section 13.4): the template above is the step 5 form. In the current `iast/runtime/orchestrion.yml`, the prepended code calls a bridge filter check after `__dd_iast_ok()`, and calls the wrapper only on a filter hit. The filter check returns its arguments unchanged, and the code stores them in the arguments, so that no argument is live across the call (no new spill at the entry, thus the gate-off path does not change):

```go
} else if __dd_iast_ok() {
  var __dd_iast_hit bool
  if buf, a, __dd_iast_hit = __dd_iast_rt_concat_hit(buf, a); __dd_iast_hit {
    return __dd_iast_concatstrings(buf, a)
  }
}
```

`slicerunetostring` is the exception: there, the filter check in the prepended code makes the frame larger than the small-frame limit, so its wrapper calls the filter check first.

## 3. Design A: concatenation hook

### 3.1 Runtime entry points

Verified in `GOROOT/src/runtime/string.go` (go1.26.6 and go1.27.1):

| Function | Signature | Notes |
|---|---|---|
| `concatstrings` | `(buf *tmpBuf, a []string) string` | `concatstring2..5` call it with `[]string{...}` |
| `concatbytes` | `(buf *tmpBuf, a []string) []byte` | `concatbyte2..5` call it. The compiler uses it for `[]byte(a + b)` (`walkStringToBytes` -> `walkAddString`) |

The compiler (`cmd/compile/internal/walk/expr.go`, `walkAddString`) passes a stack `tmpBuf` (32 bytes) only when the result does not escape. Chains with more than 5 operands call `concatstrings` directly. Constant chains are folded at compile time and are never tainted.

### 3.2 New bridge package `internal/taint/runtimebridge`

Model: `internal/taint/jsonbridge/bridge.go` (dependency-minimal, only `sync/atomic` and `unsafe`, callbacks installed with `Register`).

Rules:

1. Imports: only `sync/atomic` and `unsafe`. CI runs `go list -deps ./internal/taint/runtimebridge` and fails on any other package (except `runtime` and its internal closure).
2. The gate is a zero-initialized BSS `uint32`. It is correct before any `init` function runs: zero means "off".
3. The gate mirrors "the process store has at least one **indexed root**" (a root with `indexed == true`, section 5.2.2). After step 3 there is no value table and no value counter (section 5.4), so `indexedRoots` is the only activity counter of the store. The store keeps `indexedRoots atomic.Int32` and binds it to `gate` in `Store.BindRuntimeBridge()` (rule 6). Publication order (5.2.2): increment `indexedRoots` **before** `indexed = true` is stored; decrement it only **after** `indexed = false` is stored and the refs are removed. Thus, while a reader validates a ref under `rootsMu.TryRLock` with `indexed == true`, `indexedRoots > 0`. A mutation does not change `indexedRoots` (5.2.3). The other bridges that read the value counter today also move to `indexedRoots` in step 3: `jsonbridge.BindActiveValues(store.ActiveValues())` becomes `jsonbridge.BindActiveValues(store.IndexedRoots())`, and `operatorbridge` (deleted in step 5) replaces `addOperatorValues`.
4. The untainted path (`pre` before a filter hit, and the first checks of `hook`) does not allocate, does not concat, does not lock, has no `defer`, and does not call a `func` value. It reads the interior filter (section 5.2) inline.
5. Every path that runs store code (`confirm` after a filter hit, and the tainted-path callbacks) is a `//go:noinline` bridge function with `defer` + `recover`. The runtime-side wrapper (section 2.2) sets the per-g guard (section 3.4) before **each** bridge call (`pre` and `hook`) and clears it after. (The `defer` rule applies to the bridge, not to the runtime side: the woven runtime has no `defer`, section 2.2.) If no binding is installed, the bridge function returns.
6. **One binding for the gate and the filter; callbacks use the bound store.** The bridge holds `binding atomic.Pointer[Binding]`. `Binding` contains the filter pointer and the `confirm` function (section 3.2.1). It does not contain the callbacks: `request` cannot import `propagation` (import cycle `propagation` -> `request`). Only `request.defaultManager` (`internal/taint/request/scope.go:46-60`) calls `manager.store.BindRuntimeBridge()`. That function returns `false` and changes nothing when the store already has an indexed root (a root that is indexed before the gate is bound is not counted in the gate); else it does `binding.CompareAndSwap(nil, b)`, then stores the string-to-slice switch word (section 4.4), then records the store for `store.RuntimeStore()`, then binds the store's `indexedRoots` counter to `gate` (rule 3). A second call returns `false` and changes nothing. `store.New()` does not install anything. Thus a test store, or any store other than the process store, never changes `gate` and is never visible to the hooks. The gate can be non-zero only after the binding is stored, so `pre` and `hook` always read a filter of the same store that changes the gate.
   - **Callbacks.** `internal/taint/propagation` installs the 6 tainted-path callbacks with `runtimebridge.Register` in its `init` function. The callbacks get the store from `store.RuntimeStore()`, which is the store of the binding. Thus the filter, `confirm` and the callbacks always use one store, also when `Register` runs before or after `BindRuntimeBridge`.
   - **Link rule (step 5).** The runtime aspect cannot import `propagation`, and a build can enable the runtime aspect with no other import of `propagation` (for example, only the `net/http` source aspect, which imports `request` but not `propagation`). Then the binding exists but no callback is registered: `pre` forces results to the heap and the result hooks propagate nothing. Rule: the `links:` list of the runtime declarations aspect names `internal/taint/runtimebridge` **and** `internal/taint/propagation`. Orchestrion adds each link-time dependency that the program does not import as a blank import of the synthetic main file (`internal/toolexec/aspect/oncompile-main.go` in v1.13.1), so the `init` function of `propagation` runs (the Go linker runs only the `init` functions of packages that `main` imports directly or indirectly, `cmd/link/internal/ld/inittask.go`). If this is not possible with Orchestrion v1.13.1, step 5 stops for user review; the fallback is to move the callbacks to a package that `request` imports, and to register them in `request.defaultManager` before `BindRuntimeBridge`.

#### 3.2.1 Pre-check must not allocate for clean operands

A filter bucket can be non-zero for a clean operand (hash collision, or another root in the same granule). If `pre` returned `true` on a filter hit, the runtime would set `buf = nil` and allocate a clean result on the heap. That breaks the 0-allocation gate.

Rule: `pre` returns `true` only when a **live, validated** root contains an operand **and** one of the root ranges overlaps the operand window. It must never return `false` for a tainted operand (no false negative).

1. For each operand: compute the filter buckets inline (section 5.2, two loads). If all are zero, continue. This is the common case. A zero filter is a proof of "clean": every visible root is indexed and counted in the filter (section 5.2.2, admission rule).
2. On the first filter hit, call the `//go:noinline` function `confirmSlow` (sketch below). It has `defer` + `recover`. It calls `binding.Confirm(ptr uintptr, n uint32) ConfirmResult` for this operand and the remaining ones. `ConfirmResult` is a `uint8` enum in the bridge (the store imports it): `ConfirmClean`, `ConfirmTainted`, `ConfirmUnknown`.
3. `confirm` is a store function. It runs the interior probe and the validation of section 5.2.3 steps 1-2, with `TryRLock` only. Then it scans the root ranges (inline and overflow, at most `MaxRanges` = 64, no copy) for one range that overlaps `[p-base, p-base+n)`. It does not allocate. It returns:
   - `ConfirmClean`: no live root contains the operand, or no range overlaps the window (a clean part of a sparse tainted root);
   - `ConfirmTainted`: a live root contains the operand and a range overlaps;
   - `ConfirmUnknown`: a `TryRLock` failed. Counter `preContention`.
4. `pre` returns `true` for `ConfirmTainted` and for `ConfirmUnknown`. Contention thus costs at most one heap allocation (<= 32 B). It does not lose taint. A recovered panic also returns `true` (counter `hookPanic`).
5. `confirm` takes `uintptr`, not a pointer. Thus it cannot keep the operand live and it cannot make the operand escape (section 3.8).
6. Remaining race: the owner finishes between `pre` and the result hook. Then one heap allocation happens for an operand that was tainted when `pre` ran. This is correct and bounded. The counter `preStale` exists in the store (step 3), but step 4 does not record it: the result function does not know whether `pre` ran or what it returned (the runtime does not pass the `pre` result, and the variant D signatures of appendix H stay as they are). A result hook that finds no taint is also the normal case for a result that was on the heap before `pre` (`buf == nil`). To record `preStale` needs a per-g flag or one more argument; that costs more than the information is worth. The counter stays 0.

Cost: filter miss: two loads for each operand. Filter hit: one `confirmSlow` call (one open-coded defer, <= 40 probed entries, <= 64 range checks; target <= 50 ns), 0 allocations. The rate of filter hits depends on the index load (section 5.3, benchmark under sparse, typical and full load in section 9.2).

Sketch:

```go
// Package runtimebridge is the dependency-minimal bridge that the woven
// runtime calls. It must not import any package that the runtime hooks weave.
package runtimebridge

//go:linkname gate __dd_iast_rt.gate
var gate uint32 // zero = off. The store changes it with sync/atomic.

//go:linkname s2sGate __dd_iast_rt.s2s_gate
var s2sGate uint32 // 1 = []byte(s) and []rune(s) propagation on (section 4.4)

type ConfirmResult uint8

const (
	ConfirmClean ConfirmResult = iota
	ConfirmTainted
	ConfirmUnknown // a TryRLock failed: treat as tainted in pre
)

// Binding is the store part only: filter and confirm of one store (rule 6).
// It has no callbacks.
type Binding struct {
	Filter  *Filter
	Confirm func(p uintptr, n uint32) ConfirmResult // store: no alloc
}

// Callbacks are the tainted-path functions (may allocate). They are not in
// Binding: the propagation package registers them with Register, and they
// use store.RuntimeStore(), so they always use the store of the binding.
type Callbacks struct {
	Concat      func(result string, operands []string)
	ConcatBytes func(result []byte, operands []string)
	FromBytes   func(result string, input []byte)
	ToBytes     func(result []byte, input string)
	FromRunes   func(result string, input []rune) // section 4.5
	ToRunes     func(result []rune, input string)
}

var (
	binding   atomic.Pointer[Binding]   // set once (CAS), by the process store only
	callbacks atomic.Pointer[Callbacks] // set by propagation.init via Register
)

// Bind installs b once for the process. A second call returns false.
func Bind(b *Binding, options Options) (*Gate, bool)

// Register installs the callbacks, separately from Bind. A registration
// before or after Bind gives the same result.
func Register(c *Callbacks) *Callbacks { return callbacks.Swap(c) }

//go:linkname concatPre __dd_iast_rt.concat_pre
func concatPre(a []string) bool {
	b := binding.Load()
	if b == nil {
		return false
	}
	for i := range a {
		s := a[i]
		if len(s) != 0 && filterHit(b.Filter, uintptr(unsafe.Pointer(unsafe.StringData(s)))) {
			return confirmSlow(b, a[i:])
		}
	}
	return false // no defer and no call on this path
}

//go:noinline
func confirmSlow(b *Binding, a []string) (hit bool) {
	defer func() {
		if recover() != nil {
			hookPanic.Add(1)
			hit = true // fail toward the heap: one allocation, no taint loss
		}
	}()
	for _, s := range a {
		p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
		if len(s) != 0 && filterHit(b.Filter, p) && b.Confirm(p, uint32(len(s))) != ConfirmClean {
			return true
		}
	}
	return false
}
```

Runtime-side shape of the pre-check: it is in the wrapper `__dd_iast_concatstrings` of section 2.2 (called only after the context check passed, 3.3), before the inner call:

```go
if buf != nil {
	gp.__dd_iast_in_hook = 1
	hit := __dd_iast_rt_concat_pre(a)
	gp.__dd_iast_in_hook = 0
	if hit {
		buf = nil
	}
}
```

`filterHit`, `bucketS`, `bucketL` and `FilterBuckets` live in the bridge, and the store imports them, so the two sides cannot disagree on the hash.

After step 7 (section 13.4), the prepended code calls the same filter check before the wrapper, with the bridge functions `__dd_iast_rt.concat_hit`, `bytes_hit`, `str_hit`, `str_hit_runes` and `runes_hit`. A clean input with a filter miss thus does not enter the wrapper, the pre-check or the result hook. The pre-check and the result hook still check the filter (they run only after a hit).

### 3.3 Runtime context checks

The prepended code of `<fn>` (section 2.2) does this check **before** it calls the wrapper, when the gate is not 0 and the bypass token is 0. Only when all of these are true does it call the wrapper, and thus the bridge. When the check is false, the original body runs directly: no wrapper call, no token, no bridge call. The gate-off path and the inner entry (token 1) do not run this check.

Why before the wrapper (critic round 9): the wrapper is a normal Go function with a stack check at entry. On `g0` or `gsignal`, a failed stack check calls `morestack`, and `morestack` on `g0` or `gsignal` is fatal (`runtime/asm_arm64.s` and `asm_amd64.s` call `badmorestackg0` / `badmorestackgsignal` in `runtime/proc.go`: "fatal: morestack on g0", a fatal error that `recover` cannot stop). If the check ran inside the wrapper (the first variant D), a hooked function that runs near the end of a `g0` stack would crash the process only because the gate is on. `__dd_iast_ok()` itself cannot grow the stack: it is `//go:nosplit` and has no call (`getg()` is an intrinsic; the other operations are loads and compares). The linker's nosplit check covers its frame (none with default flags: it is inlined; none with `-N -l`: it is a leaf with no frame, step 2 disassembly). Step 2 test: 9.1 item 15.

The check stays true until the wrapper body starts. Between the check and the first statement of the wrapper, only the stack check of the wrapper runs. On a user goroutine, `morestack` there can grow the stack or preempt the goroutine. `newstack` preempts only when `m.locks`, `m.mallocing` and `m.preemptoff` are clear; after a move to another M, the goroutine is `curg` of that M, the new M holds no lock for it, and the guard is a field of the goroutine. Thus the result of the check is still correct in the wrapper.

- `gp == gp.m.curg`: not on `g0` or `gsignal` (no system stack, no signal handler).
- `gp.m.locks == 0`: not while the runtime holds a lock or does `acquirem`.
- `gp.m.mallocing == 0` and `gp.m.preemptoff == ""`: `gopanic` throws (a fatal error that `recover` cannot stop) when one of these, or `m.locks`, is set (`runtime/panic.go`, go1.27.1 lines 830-845). The bridge recovers panics (section 3.2 rule 5), so the bridge must run only where a panic is recoverable.
- The per-g recursion guard is clear (section 3.4).

Thus `__dd_iast_ok()` is:

```go
//go:nosplit
func __dd_iast_ok() bool {
	gp := getg()
	mp := gp.m
	return gp == mp.curg && mp.locks == 0 && mp.mallocing == 0 && mp.preemptoff == "" && gp.__dd_iast_in_hook == 0
}
```

Field names (`m.curg`, `m.locks`) are runtime internals. If Go renames them, the woven runtime does not compile. That failure is loud, and it is the wanted result. Step 6 adds a check for each supported Go version.

### 3.4 Recursion guard and bypass token

Decision: add two fields to `runtime.g` with the GLS precedent, in the shared declarations aspect (section 2.2, 3.5):

```yaml
  - id: iast-runtime-decls
    join-point:
      struct-definition: runtime.g
    advice:
      - add-struct-field:
          name: __dd_iast_in_hook
          type: uint8
      - add-struct-field:
          name: __dd_iast_bypass
          type: uint8
```

Step 2 generated `__dd_iast_in_hook uint8`, `__dd_iast_bypass uint8` and the GLS field `__dd_gls_v2 any` next to each other in one `type g` (appendix H). Every `g` has its own fields, also `g0` and `gsignal`. Only code that runs on that `g` reads or writes them, so no atomic is necessary.

#### 3.4.1 Recursion guard `__dd_iast_in_hook`

The tainted path runs store code. That code can concat strings, convert `[]byte` to `string`, or allocate. Such calls enter the hook again.

The wrapper (section 2.2) sets `gp.__dd_iast_in_hook = 1` before **every** bridge call (`pre`, `hook`, and the conversion equivalents) and sets it to 0 after. The context check (section 3.3) returns false when the field is not 0. A panic inside the bridge must not leave the field at 1: every bridge function that runs store code recovers (section 3.2 rule 5), so the call always returns and the wrapper always clears the field. The filter-only part of `pre` cannot panic (it reads `a[i]` for `i < len(a)` and a fixed-size array with a masked index).

Second protection: the bridge's untainted path has no concat and no conversion (9.1 item 8 checks it).

Tests (woven build): a test-only `confirm` that panics: `pre` returns `true`, the guard is 0 after the call, and the next concat runs the hook normally. A test-only `confirm` that does a concat and a `string(b)`: the nested operations do not enter the bridge (`hookEntries` unchanged).

#### 3.4.2 Bypass token `__dd_iast_bypass`

Purpose: the wrapper calls the original function again (the inner call). The token tells the inner entry to run the original body, and not the wrapper again. The token is a one-shot message from the wrapper to the next entry on the same `g`. It is not a lock and not a recursion guard.

Rules:

1. **Set:** only a wrapper sets the token to 1. It does this immediately before the inner call, with no other statement between them. A wrapper runs only after `__dd_iast_ok()` returned true in the outer entry (2.2 item 2, critic round 9), thus only on a user goroutine (`gp == gp.m.curg`); the token of `g0` and `gsignal` is never set. When the context check fails, no token is set: the original body runs directly. Between the store and the inner entry, no Go code of this `g` runs: only the call and the stack check. `morestack` runs on `g0`, and `g0` has its own token.
2. **Consume:** at the inner entry, the prepended statements read the gate. When the gate is not 0, they read the token **before** the context check: they see the token, set it to 0, and run the original body (no `__dd_iast_ok()` call). Thus in the normal case the token is 1 only from the store to the inner entry, and it is 0 while the original body runs. Only the next hooked entry on the same `g` can consume it, and in the normal case that entry is the inner call.
3. **Clear after the call (decision for a gate change):** the wrapper sets the token to 0 again after the inner call returns, unconditionally. Reason: the gate can change to 0 between the outer entry and the inner entry. Then the inner entry does not read the token (the token check is inside `if gate != 0`), and the original body runs with the token at 1. The clear after the call removes it. The same applies to the Q2 switch `s2sGate` (the nested `if` after the gate check in `stringtoslicebyte` and `stringtoslicerune`, 4.3); it is stored once at bind time, so it does not change in practice. Thus, when a wrapper returns, the token is always 0. The step 2 YAML does this (`gp.__dd_iast_bypass = 0` after each `__dd_iast_orig_<fn>` call).
4. **Remaining stale-token cases:** (a) the gate changes to 0 before the inner entry **and** the original body panics (only a fault on an invalid pointer is recoverable in these bodies; the other errors are `throw`); (b) the gate changes to 0 before the inner entry, then to non-zero again, and the original body runs a hooked function on the same `g`. In both cases the token stays 1 for one more entry. That entry runs the original body without the wrapper and clears the token: **one missed propagation** for this `g`. No crash, no wrong taint, no leak. If the goroutine exits first, the runtime reuses the `g` record (`gfget` does not clear our fields), and the first hooked call of the next goroutine on it can miss once. Same bound. No counter records this loss: a counter would add work to the gate-on path of every call.
5. **Panic when the gate stays on:** the inner entry already consumed the token, so a panic in the original body leaves nothing.
6. **Guard interaction:** the token is always 0 when a wrapper calls the bridge (`pre` runs before the store; the result hook runs after the clear). A nested hooked call inside the bridge thus sees token 0 at its outer entry and calls `__dd_iast_ok()`, which returns false (guard set). The original body then runs directly: no wrapper, no token, no bridge call, no extra frame. There is no loop: a wrapper is entered only when the guard is 0, and an inner entry never calls a wrapper while its token is 1. (The first variant D entered the wrapper here and took a token path inside it: two more frames. Critic round 9 removed that path.)
7. **Stack results:** the wrapper calls the result hook only when the result is not on the stack (`!stringDataOnStack(r)`, or a 1-byte string view of the slice data for `[]byte` and `[]rune` results), as before (section 3.8).

Rejected alternative: clear the token at every entry, also when the gate is 0 (read the token before the gate). It removes case 4, but it adds a `getg()` and one load to the gate-off path, which was not measured. Case 4 needs a gate change inside a window of a few instructions; the loss is one propagation.

Tests (woven build, step 5):

- Gate change: a test-only `pre` stores 0 in the gate and returns `false`; the test stores the gate value back after the operation. The next hookable operation on the same goroutine enters the bridge (`hookEntries` +2 for a concat). Run it for each of the 6 functions. Negative control (9.1 item 5): remove the clear after the inner call; the test must fail.
- Stale-token bound: the same gate change, then a fault in the original body (for example `string(b)` of an invalid pointer with `n > 1`), recovered by the test. With the gate on again, at most 1 of the next 2 hookable operations on the goroutine does not enter the bridge.
- Sequence: 1 000 mixed operations with the gate on, on one goroutine, each one enters the bridge (no lost token).
- Nesting: the `confirm` and callback tests of 3.4.1 run with all 6 operations nested; the stack-growth test of 3.8 stays green.
- System stack (critic round 9): the `g0` test of 9.1 item 15 (no wrapper, no token and no bridge call on `g0`).

### 3.5 Where to inject the declarations

Prototype risk 4: if `concatstrings` is renamed, the declarations aspect does not match, and the other aspects reference undefined names. The runtime build then fails with an unclear error.

Decision: inject all shared declarations on a join point that always exists and that the GLS aspect also uses: `struct-definition: runtime.g` (aspect `iast-runtime-decls`, section 2.2). They are: the two `runtime.g` fields (3.4), `add-blank-import: unsafe` (the wrappers use `unsafe.String`), the gate variables, the 11 bridge function declarations, `__dd_iast_ok`, and for each of the 6 hooked functions the alias `__dd_iast_orig_<fn>`, the wrapper `__dd_iast_<fn>` and the 3 signature assertions (3.9 item 6). Each function aspect then references only these names. Names: `__dd_iast_rt_<name>` for the bridge pulls (linker symbols `__dd_iast_rt.<name>`), `__dd_iast_ok`, `__dd_iast_<fn>` for the wrappers, `__dd_iast_orig_<fn>` for the aliases (linker symbol `runtime.<fn>`, 3.9 item 5).

The wrappers refer to `tmpBuf`, `tmpStringBufSize` and `stringDataOnStack` (R3). If Go renames one of them, the runtime does not compile (loud).

### 3.6 Hook behavior on the result

In `concat(result, operands)` on the tainted path:

1. `len(result) == 0`: return (empty is never tainted).
2. `len(result) > store.MaxRootBytes`: record a `bytes` drop and return.
3. **Identity fast path:** `concatstrings` returns `a[idx]` when only one operand is not empty (`count == 1`). If the data pointer and length of `result` equal one operand, return. The interior lookup (section 5) already finds the operand's taint.
4. `stringDataOnStack(result)`: the wrapper already skips it (section 2.2). With the v2 pre-check, a tainted operand never gives a stack result.
5. Otherwise the result is a fresh allocation from `rawstring(l)` (strings) or `rawbyteslice(l)` (bytes). `mallocgc` returns the allocation base. The result is complete: it starts at the base and nobody else holds it yet. This is the "audited" case that `Owner.AdoptString` and `Owner.AdoptBytes` require. Adopt it. Do not clone it.
6. Ranges: for each contributing owner, compose the operand ranges shifted by the cumulative operand lengths. Reuse the logic of `joinStringHit` (`string_exact.go`) with an empty separator and without `strings.Clone`. Share the same result between at most `MaxSnapshotOwners` owners, as `publishStringCopy` does today.
7. More than 16 operands: do **not** reuse `coarseStringHit`. It inspects only the first `maxInputs` (16) inputs (`propagation.go:363-378`), and `joinStringHit` keeps only 15 (`string_exact.go:51-65`). A taint in operand 17 or later is lost. Add `coarseConcatHit(result, operands)`: it scans **all** operands with `MayContain` + `Lookup` (the operand count is fixed by the source code; no allocation), keeps at most `MaxSnapshotOwners` owners, and gives each owner its own ranges of each operand (the ranges of its `Lookup` of the operand, shifted by the cumulative operand lengths; only ranges of the owner that touch merge), with the source of the first range of the owner and the marks that all its ranges have. Thus a range of one owner never covers a byte that the owner does not taint, also in an operand that two owners share, and the evidence of a report for one owner masks the bytes of the other owners (step 4 reviews: one range over `[0, len(result))` for each owner, and then one range from the first to the last tainted byte of each operand, made the bytes of owner B the evidence of owner A). The `limit` of the first match bounds the range count; the ranges after the limit are dropped. It records one `ranges` drop for each owner because the ranges are not exact. The exact path (<= 16 operands) records one `ranges` drop for each owner when the range limit truncates its ranges. Tests: 17 operands with only operand 17 tainted; 40 operands with only operand 40 tainted; 5 owners (the fifth is a `fanout` drop).
8. For `concatbytes`, the result is a `[]byte`. Adopt it as a bytes root with `span = cap(result)` (section 4.4 gives the mutable-bytes model).

Rule for `count == 1` with `buf == nil`: the runtime copies a stack operand to the heap (`!stringDataOnStack(a[idx])` is false). The result is then a fresh allocation, so step 5 applies.

### 3.7 Limits and fan-out

- The hook uses the existing store limits. It adds no new table (the interior index of section 5 is a store table, not a hook table).
- Every failure is a drop with an existing counter (`full`, `bytes`, `ranges`, `contention`, `fanout`) or a new one (`indexFull`, `preStale`; `preStale` is not recorded, see 3.2.1 item 6). The hook never blocks: it uses the store's `TryLock` / `TryRLock` paths.

### 3.8 Escape and GC contract

The runtime side declares the bridge functions without a body and with `//go:noescape`. The compiler trusts this declaration and does not analyze the bridge body. Thus the bridge must obey this contract. A violation is memory corruption, not only a wrong taint.

**Alias rule (variant D).** The wrapper calls the original function through the body-less alias `__dd_iast_orig_<fn>` (`//go:linkname __dd_iast_orig_<fn> runtime.<fn>` + `//go:noescape`), never directly. Evidence (step 2 investigation, appendix H): with a direct call `concatstrings(buf, a)`, the wrapper and `<fn>` are one recursive escape-analysis batch. Then the compiler reports `leaking param: buf` (heap) in place of `leaking param: buf to result ~r0 level=0` for all 6 functions and for `concatstring2..5` / `concatbyte2..5`. The escape comparison failed in all 6 cells (and in a 30-line reproduction). With the alias, the escape tags of `<fn>` come from its own body only, and they are identical to the unwoven runtime (6/6 cells). The `//go:noescape` of the alias is not exact (`buf` flows to the result). This is safe only because: (1) it changes only the tags that the compiler uses at call sites of the alias; (2) the only call site of the alias is the wrapper; (3) the only caller of the wrapper is the prepended code of `<fn>`, which passes its own arguments and returns the result directly; the escape tags of `<fn>` (from its body) already describe that flow for the callers of `<fn>`. Thus no code outside `runtime` sees the inexact tags. A new call site of an alias or of a wrapper is not permitted.

| Argument | What the bridge can do | What the bridge must never do |
|---|---|---|
| `a []string` (operands) in `pre` and `hook` | read `len`, data pointers as `uintptr`, and bytes during the call | keep `a`, its backing array, or any operand after return; pass an operand as a pointer or `string` to code that can keep it |
| `ptr *byte, n int` / `s string` / `a []rune` (conversion inputs) | the same as operands | the same as operands |
| `result` (concat or conversion) | keep it as a root anchor **only if** it is heap memory | keep it when it is stack memory |

Why the result rule is safe:

1. The wrapper calls `hook` only when `!stringDataOnStack(result)`. So the result is in the heap (from `rawstring` / `rawbyteslice`) or it is a heap operand (the `count == 1` identity case, where the bridge returns before it keeps anything, section 3.6 step 3).
2. A heap object that `rootRecord.stringAnchor` / `bytesAnchor` holds is a normal GC root through a Go pointer. The GC keeps it. Stack growth does not move heap memory.
3. Operands can be in a stack `tmpBuf` of an earlier concat. The bridge functions are normal Go functions, so the stack can grow and move during the call. When the stack moves, the runtime updates Go pointers in frames, but not `uintptr` values. Thus the bridge converts each operand to a `Key` (`uintptr` + length) once, and after that it never reads operand bytes through the `Key`. A stale stack `Key` is only a lookup key. No root contains stack memory (roots are heap allocations, section 1.3), so such a key gives a miss and nothing more.

Checks (step 2, step 5 and the step 6 CI job, on go1.26.6 and go1.27.x, with default flags and with `-gcflags=all=-N -l`):

- Compare `-gcflags=runtime=-m` output (step 2 compared it; step 5 adds `-m=2`) for every hooked function and for `concatstring2..5`, `concatbyte2..5`, `slicebytetostring`, `stringtoslicebyte`, `slicerunetostring`, `stringtoslicerune` between the woven and the unwoven runtime (the `string.go` lines inside these functions, sorted). Normalization (the `decisions` function of `.github/runtime-escape-compare.sh`): remove the column (Orchestrion `//line` directives have no column), the `flow:` and `from ...` explanation lines of `-m=2`, and the inlining costs, and renumber `autotmp_` names; these differ because the woven bodies are larger and are not escape decisions (step 5). With variant D the result is not renamed, so no `__result__0` replacement is necessary. The escape decisions must be identical. This comparison is a required CI check (9.4): it is the guard of the alias rule. Negative control: the wrapper calls `runtime.<fn>` directly; the comparison must fail (`leaking param: buf`).
- Stack-result test: a non-escaping clean concat stays on the stack (`stringDataOnStack` is true) and is never adopted.
- Stack-growth test: a tainted operand from a stack `tmpBuf`, a deep recursion that forces stack growth during the tainted path (a test-only callback), then `runtime.GC()` twice. No crash, and no store entry points into a stack range.
- Heap-retention test: a tainted concat result, all other references dropped, `runtime.GC()` twice, then lookup of the adopted root: the data is unchanged and the ranges are correct.
- `testing.AllocsPerRun` of `pre` with a filter hit on a clean operand: 0.
- Panic test: a test-only callback panics. The bridge recovers. The guard field is 0 after the call. The next hook call runs normally.

### 3.9 Linkname contract

Facts from `cmd/link/internal/loader/loader.go` (`checkLinkname`, go1.27.1 lines 2515-2589):

- The check runs only when `-checklinkname` is on (default on since Go 1.23).
- A name in `blockedLinknames` is refused, except from the listed packages.
- A reference to a symbol that is **not** defined in a standard-library package is permitted (`if !r.Std() { return }`).
- A reference to a std symbol is permitted when the definition has a push `//go:linkname` (`osym.IsLinkname()`).

Contract for this plan:

1. Every bridge symbol (`__dd_iast_rt.gate`, `__dd_iast_rt.concat_pre`, ...) is **defined** in `runtimebridge` (not std) with a push `//go:linkname`. The woven `runtime` only **pulls** them with bodyless declarations. Both rules above permit this.
2. No name is in `blockedLinknames`. A check in the step 6 CI job greps the list of each supported toolchain for the `__dd_iast_rt` prefix.
3. The symbol prefix `__dd_iast_rt.` has no package path. It cannot collide with a real package.
4. Test for each toolchain: `go tool orchestrion go build -ldflags=-checklinkname=1` of `cmd/bootstrap` and of the `cmd/nohook` fixture. Both must link and run.
5. **Self-linkname aliases (variant D).** Inside `runtime`, `//go:linkname __dd_iast_orig_<fn> runtime.<fn>` pulls a std symbol that has no push `//go:linkname`. The check permits it because the reference and the definition are in the same package: `if r.unit.Lib.Pkg == pkg { return }` (go1.27.1 line 2551, go1.26.6 line 2530; the code comment says "assembly reference from same package", but the test compares only the package). This test runs before the push-linkname test. The 6 names `runtime.concatstrings`, `runtime.concatbytes`, `runtime.slicebytetostring`, `runtime.stringtoslicebyte`, `runtime.slicerunetostring`, `runtime.stringtoslicerune` are not in `blockedLinknames` of go1.26.6 or go1.27.1 (0 matches in `loader.go`). The step 2 D cells passed `-ldflags=-checklinkname=1` on go1.26.6 and go1.27.1 (default, `-race`, `-N -l`). The item 2 grep also checks these 6 names.
6. **Signature assertions (in the step 2 artifact since critic round 9).** The alias has no body, so the compiler does not compare its signature with `runtime.<fn>`. A different signature (for example a new argument in a later Go release) gives an ABI mismatch when the gate is on: memory corruption. Rule: the shared declarations contain, for each hooked function, 3 assignments of the original, the alias and the wrapper to **one** func type (the signature of `<fn>` in the supported releases):

   ```go
   var _ func(*tmpBuf, []string) string = concatstrings
   var _ func(*tmpBuf, []string) string = __dd_iast_orig_concatstrings
   var _ func(*tmpBuf, []string) string = __dd_iast_concatstrings
   ```

   (the same for the other 5, with their types; `stringtoslicerune` uses `func(*[tmpStringBufSize]rune, string) []rune`). Then a signature change or a rename of `<fn>`, and an alias or a wrapper that does not repeat the signature exactly, are compile errors of the woven runtime (loud, R3). Step 2 (critic round 9): the escape comparison stays identical (67 / 67 / 58 lines) and all 6 darwin/arm64 cells pass with the assertions. Negative control: an alias of `slicebytetostring` with one more `int` argument (and the wrapper call changed to match) fails to compile with the assertions (`cannot use __dd_iast_orig_slicebytetostring (value of type func(buf *tmpBuf, ptr *byte, n int, extra int) string) as func(*tmpBuf, *byte, int) string value`); without the alias assertion the same build compiles silently (the ABI mismatch that the rule prevents).

### 3.10 Supported Go versions (Q3)

Supported: go1.26.x and go1.27.x only. The `go 1.26.6` line of `go.mod` already refuses older toolchains. CI tests go1.26.6 and the latest go1.27.x (section 9.4).

For a newer toolchain (go1.28 and later), the file `internal/taint/runtimebridge/unsupported.go` (`//go:build go1.28`) makes `BindRuntimeBridge` return `false` and increments a counter `unsupportedGo`. Then the gates stay 0, and each hook costs one atomic load. Interior lookup (section 5) still works, because it does not use the hooks. Concat and conversion propagation is then off. There is no build-time or startup warning (user decision, section 12, "Go 1.28+"); only the `unsupportedGo` counter records it. If the woven runtime does not compile on the new toolchain (a renamed runtime field, or a changed signature of a hooked function caught by the assertions of 3.9 item 6, R3), the build fails loudly; the build tag cannot prevent this. With the gate at 0, the wrappers are never called, so a signature change on go1.28+ without the assertion would be harmless; the assertion makes it a build failure. This is the chosen trade-off: on a supported toolchain, a silent ABI mismatch is not acceptable.

## 4. Design B: conversion hooks

### 4.1 Inventory of compiler conversion paths

Source: `cmd/compile/internal/walk/convert.go`, `order.go`, `switch.go`, `escape/escape.go`, `ssagen/ssa.go` (go1.27.1; go1.26.6 has the same functions and the same `ZeroCopy` debug flag, default on).

| Go source form | Compiler op | Runtime call | Result memory | Plan |
|---|---|---|---|---|
| `string(b)` | `OBYTES2STR` | `slicebytetostring(buf, ptr, n)` | new copy (heap, or 32-byte stack `tmpBuf` if it does not escape) | **hook** |
| `[]byte(s)` | `OSTR2BYTES` | `stringtoslicebyte(buf, s)` | new copy (heap or stack `tmpBuf`) | **hook** |
| `[]byte(a + b)` | `OSTR2BYTES` of `OADDSTR` | `concatbytes` | new copy | covered by section 3 |
| `m[string(b)]`, `string(b) == "x"`, `"<" + string(b) + ">"`, `switch string(b)` | `OBYTES2STRTMP` | none (SSA `StringMake`), or `slicebytetostringtmp` when `-race`/msan/asan | **alias** of `b` | interior lookup (section 5), no hook |
| `for i, c := range []byte(s)`, `[]byte(s)` never mutated (escape `ZeroCopy`), string switch split | `OSTR2BYTESTMP` | none | **alias** of `s` | interior lookup, no hook |
| `[]byte("literal")` | constant | none | new static copy | never tainted |
| `string(runes)` | `ORUNES2STR` | `slicerunetostring(buf *tmpBuf, a []rune) string` | new (heap `rawstring(size+3)`, or stack `tmpBuf`) | **hook** (Q6, section 4.5) |
| `[]rune(s)` | `OSTR2RUNES` | `stringtoslicerune(buf *[32]rune, s string) []rune` | new `[]rune` (heap `rawruneslice`, or stack `[32]rune`) | **hook** (Q6, section 4.5), behind the Q2 switch |
| `string(r)` (rune) | `ORUNESTR` | `intstring(buf *[4]byte, v int64) string` | new, 1-4 bytes | not covered (see below) |
| `len(string(b))`, `len([]rune(s))` | optimized (`countrunes`) | none | no value | nothing to track |

Signatures checked in `runtime/string.go` and `cmd/compile/internal/walk/convert.go` of go1.26.6 and go1.27.1: the function bodies are identical (`diff`), and `tmpStringBufSize` is 32 in both.

Documented misses:

- `string(r)` (`intstring`): the argument is an `int64` value, not memory. The store tracks memory identity (a data pointer), so no key exists for a rune value. Only caller-side instrumentation could track it, and this plan removes caller-side rewrites (C4). Thus `string(r)`, including `string(runes[i])` and `for _, r := range s { ... string(r) }`, loses taint.
- One-byte results: `slicebytetostring` with `n == 1` returns static memory (section 4.2), and a one-byte result of `slicerunetostring` is below the 2-byte root minimum. Both lose taint.

The alias forms (`...TMP`) are **not** misses after section 5: their data pointer points inside the source root.

### 4.2 `slicebytetostring`

Variant D (section 2.2). Prepended statements:

```yaml
  - id: iast-slicebytetostring
    join-point:
      all-of:
        - import-path: runtime
        - function-body:
            function:
              - name: slicebytetostring
    advice:
      - prepend-statements:
          imports:
            atomic: internal/runtime/atomic
          template: |-
            {{- $buf := .Function.Argument 0 -}}
            {{- $ptr := .Function.Argument 1 -}}
            {{- $n := .Function.Argument 2 -}}
            if atomic.Load(&__dd_iast_rt_gate) != 0 {
              if __dd_iast_gp := getg(); __dd_iast_gp.__dd_iast_bypass != 0 {
                __dd_iast_gp.__dd_iast_bypass = 0
              } else if __dd_iast_ok() {
                return __dd_iast_slicebytetostring({{ $buf }}, {{ $ptr }}, {{ $n }})
              }
            }
```

Alias, signature assertions and wrapper (in `iast-runtime-decls`, section 3.5):

```go
//go:linkname __dd_iast_orig_slicebytetostring runtime.slicebytetostring
//go:noescape
func __dd_iast_orig_slicebytetostring(buf *tmpBuf, ptr *byte, n int) string

var _ func(*tmpBuf, *byte, int) string = slicebytetostring
var _ func(*tmpBuf, *byte, int) string = __dd_iast_orig_slicebytetostring
var _ func(*tmpBuf, *byte, int) string = __dd_iast_slicebytetostring

// Called only after __dd_iast_ok() returned true (no context check here).
//go:noinline
func __dd_iast_slicebytetostring(buf *tmpBuf, ptr *byte, n int) string {
	gp := getg()
	if buf != nil && n > 1 {
		gp.__dd_iast_in_hook = 1
		hit := __dd_iast_rt_bytes_pre(ptr, n)
		gp.__dd_iast_in_hook = 0
		if hit {
			buf = nil
		}
	}
	gp.__dd_iast_bypass = 1
	r := __dd_iast_orig_slicebytetostring(buf, ptr, n)
	gp.__dd_iast_bypass = 0
	if len(r) > 1 && !stringDataOnStack(r) {
		gp.__dd_iast_in_hook = 1
		__dd_iast_rt_from_bytes(r, ptr, n)
		gp.__dd_iast_in_hook = 0
	}
	return r
}
```

Notes:

- `n == 1` returns a pointer into the static table `staticuint64s`. That result is shared by all goroutines. Never adopt it. The `len > 1` check excludes it. One-byte results lose taint (the same as the current `BytesToString`, which requires `len >= 2`).
- `__dd_iast_rt_bytes_pre` obeys section 3.2.1: filter check, then `confirm`. It returns `true` only for a validated live match.
- The bridge gives the result the input's window ranges and adopts it as a string root. Reuse `internal/taint/propagation/conversion.go` (`BytesToString`) without the `len(input) != len(result)` recheck.
- Under `-race`, `slicebytetostring` calls `racereadrangepc` with the caller PC. With the gate on, that caller is the wrapper (step 2, appendix H). A race report then names the wrapper. This occurs only with the gate on.

### 4.3 `stringtoslicebyte`

Same shape as 4.2. The prepended statements check the Q2 switch (section 4.4) in a nested `if` directly inside the gate check: `if atomic.Load(&__dd_iast_rt_gate) != 0 { if atomic.Load(&__dd_iast_rt_s2s_gate) != 0 { ... } }`. With the switch off, the wrapper is not called. Use the nested `if`, not `gate != 0 && s2s != 0`: with the context check before the wrapper (2.2), the `&&` form makes the compiler keep the condition as a bool (`CSET` + `TBZ`), so the gate-off path gets 2 more instructions and one more taken branch; `s2r-stack` measured approx. +1.1 ns more in its fast mode (step 2, critic round 9, appendix H.6). The nested form gives the gate-off path `LDARW` + `CBZW` only, as for the other 4 functions. The wrapper `__dd_iast_stringtoslicebyte(buf *tmpBuf, s string) []byte` sets `buf = nil` when `buf != nil`, `len(s) > 1` and `__dd_iast_rt_str_pre(s)` returns `true`. After the inner call, it calls `__dd_iast_rt_to_bytes(r, s)` when `len(r) > 1` and `!stringDataOnStack(unsafe.String(unsafe.SliceData(r), 1))` (a 1-byte string view of the slice data, as for `concatbytes`).

`rawbyteslice(len(s))` returns `cap = roundupsize(len)`. `AdoptBytes` uses `cap` as span and charge. This is correct.

### 4.4 Model for the new mutable `[]byte` root

Today string-to-`[]byte` propagation does not exist. Phase 6 section 10 removed it because "the mutable result can retain stale provenance after direct assignment". This plan adds it back with an explicit model:

1. The fresh `[]byte` is a new bytes root. Ranges cover `[0, len)`. Span is `cap`.
2. Writes that dd-iast-go sees (`bytes.Buffer` writer invalidation, `writerbridge`) use the existing root-generation invalidation.
3. Direct writes (`b[i] = x`, `copy(b, y)`, `append` in capacity) are not seen. The old ranges stay. This can over-report (false positive).
4. Source byte roots (`TaintSourceBytes`, `AdoptSourceBytes`) already have the same property. This change makes the property more frequent, not new.
5. The same model applies to the `[]rune` roots of section 4.5.

**Decision (Q2):** on by default, with a switch to turn it off.

- Environment variable `DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED` (boolean, default `true`). It follows the existing names (`DD_IAST_DEDUPLICATION_ENABLED`, `DD_IAST_STACK_TRACE_ENABLED`).
- `internal/config/config.go`: constant `EnvVarStringToSlicePropagationEnabled`, variable `StringToSlicePropagationEnabled bool`, read in `load` with `loader.BoolFromEnv(observer, EnvVarStringToSlicePropagationEnabled, true)`. `internal/config/init.go` loads it at package `init`, before any request.
- The bridge cannot import `config` (rule 1 of 3.2). `request.defaultManager` passes the value: `manager.store.BindRuntimeBridge(runtimebridge.Options{StringToSlice: config.StringToSlicePropagationEnabled})`. `BindRuntimeBridge` stores 1 in `s2sGate` when the value is true (3.2 rule 6). Zero (the BSS value) means off.
- The switch gates the `stringtoslicebyte` and `stringtoslicerune` hooks (both results are mutable). It does not gate `[]byte(a + b)` (`concatbytes`): that result is also mutable, but it is concat propagation, which exists today.
- Cost when off: one more atomic load in the woven runtime, after the main gate. No wrapper call, no bridge call, no `buf = nil`. Step 2 measured +0.0 to +0.5 ns for this case with variant D (appendix H; `s2r-heap` is noise-limited).
- The value is read once. A change needs a process restart, the same as the other `DD_IAST_*` settings.
- Tests: with the switch off, `[]byte(tainted)` and `[]rune(tainted)` are not tainted, a short result stays on the stack (0 extra allocations), and `hookEntries` does not change; `string(b)` and concat still propagate.

### 4.5 Rune conversions (Q6)

Two more aspects in `iast/runtime/orchestrion.yml`, with the variant D shape of section 4.2 (prepended gate check, alias `__dd_iast_orig_<fn>`, wrapper `__dd_iast_<fn>`). `stringtoslicerune` has the Q2 switch in a nested `if`, as in 4.3. The alias of `stringtoslicerune` is `func __dd_iast_orig_stringtoslicerune(buf *[tmpStringBufSize]rune, s string) []rune`.

| Function | Pre-check input (in the wrapper) | Stack case | Result-hook condition (in the wrapper, after the inner call) | Callback |
|---|---|---|---|---|
| `stringtoslicerune(buf *[32]rune, s string) []rune` | `__dd_iast_rt_str_pre(s)` when `buf != nil` and `len(s) != 0`; the wrapper runs only when `s2sGate != 0` | `buf != nil` and at most 32 runes | `len(r) != 0` and the rune array is not on the stack (`stringDataOnStack` of a 1-byte string view of `&r[0]`) | `toRunes(r, s)` |
| `slicerunetostring(buf *tmpBuf, a []rune) string` | `__dd_iast_rt_runes_pre(a)` (bytes `(&a[0], 4*len(a))`) when `buf != nil` and `len(a) != 0` | `buf != nil` and the encoded size + 3 <= 32 | `len(result) > 1` and `!stringDataOnStack(result)` | `fromRunes(result, a)`; the charge uses `len(a)`, not `len(result)` (next list) |

Store model:

- New `KindRunes`. A `[]rune` root uses **byte** coordinates of the rune array: rune `i` is bytes `[4i, 4i+4)`. Thus `rs[i:j]` has data pointer `base + 4i` and length `4(j-i)`, and the interior lookup (section 5) finds it with no special case.
- `Owner.AdoptRunes(value []rune, set)`: span and charge are `4*cap(value)`. It must be <= `MaxRootBytes` (at most 16 384 runes); a larger result is a `bytes` drop. The anchor is `bytesAnchor = unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(value))), 4*cap(value))`. Both types are pointer-free, so this pointer keeps the allocation live, and `rootRecord` needs no new field.
- `slicerunetostring` allocates `rawstringtmp(buf, size1+3)` from a first pass over `a`, and returns `s[:size2]` from a second pass (go1.26.6 and go1.27.1 `runtime/string.go`, identical bodies). If another goroutine changes the runes of `a` between the two passes, `size2` can be much smaller than `size1`. Thus `len(result) + 3` is **not** a bound on the allocation, and a charge from `len(result)` can be too small without limit (critic round 5, finding 3).
- The advice cannot read `size1`: the wrapper sees only the arguments and the returned result of `slicerunetostring`, not its locals. `b` (the `rawstring` slice with the full length) has the same problem.
- Decision: the charge comes from a value that cannot change during the call. `len(a)` is a copy of the slice header in the argument, and the runtime body does not assign `a`. `encoderune` writes at most 4 bytes (3 for an invalid rune or a surrogate), so `size1 <= 4*len(a)` for all rune values, before or after a change. Thus the allocation is at most `sizeClass(4*len(a) + 3)`.
- Add `Owner.AdoptStringAlloc(value string, allocBound int, set)`: span `len(value)`, charge `sizeClass(allocBound)`. It refuses (`bytes` drop) when `allocBound > MaxRootBytes` or `allocBound < len(value) + 3`. The `fromRunes` callback passes `allocBound = 4*len(input) + 3`, where `input` is the `a` argument that the wrapper passes to the callback. The bridge signature `fromRunes(result string, input []rune)` (3.2) does not change.
- Cost of this bound: the charge can be up to approx. 4 x the real allocation (1 000 ASCII runes: charge 4 096 B, real 1 024 B). This uses the request byte quota faster; it never under-charges. The largest adopted `[]rune` input becomes 16 383 runes (`4*16 383 + 3 = 65 535 <= MaxRootBytes`).
- Rejected alternative: read the real object size with `spanOfHeap(p).elemsize` in the woven runtime. It is exact, but it adds one more internal runtime symbol and field (R3). Keep it as an option if step 7 shows that the over-charge refuses roots.

Range mapping (UTF-8 byte offsets are not rune indexes, so the mapping is not a shift). Both directions are exact on rune boundaries and walk the value once. No allocation: the input ranges (<= `MaxRanges`) and the output ranges use stack `[MaxRanges]ranges.Range` arrays, and `ranges.Canonicalize` builds the result set with the root limit.

- **string to `[]rune`:** decode `s` as `for range s` does (an invalid byte is one `RuneError` of width 1). Merge-walk the sorted input ranges with the decode. A range `[a, e)` maps to `[4*rune(a), 4*(rune(e-1)+1))`, where `rune(x)` is the index of the rune that contains byte `x`. A range that starts or ends inside a multi-byte rune (possible after byte slicing) covers the whole rune. This can over-taint by less than one rune at each end. It never loses taint.
- **`[]rune` to string:** the input window ranges are in rune-array bytes. A range `[a, e)` covers runes `[a/4, ceil(e/4))`. Walk the runes and add the encoded width of each (`utf8.RuneLen`, and 3 for an invalid rune or a surrogate, as `encoderune` does) to get output offsets. Output range: `[off(a/4), off(ceil(e/4)))`, clipped to `len(result)`.
- Cost: O(runes + ranges), at most 16 384 runes (root limit). This runs only on the tainted path.
- The functions live in `internal/taint/propagation/runes.go` (the callbacks may import `unicode/utf8`; the bridge does not).

Charge tests (critic round 5, finding 3): a direct callback call with a result shorter than the encoded size of `input` (simulates `size2 < size1`): the charge is `sizeClass(4*len(input)+3)`; `allocBound < len(value)+3` and `allocBound > MaxRootBytes` are refused; a woven forced-change test (build tag `!race`, because the data race is intentional): one goroutine flips the runes of a 1 000-rune slice between `'a'` and U+10000 while another runs `string(rs)` 10 000 times; every adopted root has charge `sizeClass(4 003)`, and `ProcessCharged()` returns to 0 after `Finish`.

Tests (step 4 direct calls, step 5 woven): ASCII round trip `string([]rune(s))` keeps exact ranges; multi-byte text (`"héllo 世界"`) with a taint on one word; a range that starts inside a multi-byte rune (`s[2:]` of `"é..."`); invalid UTF-8 (`"\xff"`: 1 byte in, 3 bytes out); surrogate runes in `[]rune`; `string(rs[2:5])` (interior window); 32 and 33 runes (stack boundary); 16 384 and 16 385 runes (root limit); `string(r)` stays untainted (documented miss); switch off for `[]rune(s)` (section 4.4); `-race` builds, where `slicerunetostring` calls `racereadrangepc` first.

## 5. Design C: interior-pointer lookup (slicing without instrumentation)

### 5.1 Goal

A value `v` (string or `[]byte`) is tainted when its data pointer `p` and length `n` satisfy `base <= p` and `p + n <= base + span` for a live root. Its ranges are the root ranges sliced to `[p - base, p - base + n)`.

Then `s[i:j]`, `b[i:j:k]`, `strings.Cut` results, `OBYTES2STRTMP` and `OSTR2BYTESTMP` aliases are all found without any hook and without `Derive`.

### 5.2 Data structure: granule root index

Add a fixed table that **replaces** the value table (Q4, section 5.4), in a new file `internal/taint/store/interior.go`.

#### 5.2.1 Two tiers of granules

Problem (critic finding 4): with one 4 KiB granule size, all roots in one granule have the same key and the same probe start. Many small roots (for example short query parameters that `strings.Clone` packs into the tiny allocator's 16-byte blocks) can be in one granule. A probe limit of 32 then loses roots after the 32nd.

Decision: two tiers. The tier depends only on the root span. A lookup checks both tiers.

| Tier | Root span | Granule | Granules for each root | Max disjoint roots that overlap one granule |
|---|---|---|---|---|
| S | 2 to 256 B | 64 B (`shift 6`) | <= 5 | 64 / 2 + 1 = 33 (roots have `len >= 2`: `AdoptString`, `AdoptBytes` and `TaintString` refuse shorter values, `root.go:28,233,243`) |
| L | 257 B to 64 KiB | 4 KiB (`shift 12`) | <= 17 | 4096 / 257 + 2 = 17 |

Shared allocations (critic round 2, finding B): one allocation can be the root of **several owners**. `publishStringCopy` (`propagation.go:175-191`) and the bytes helpers (`bytes_exact.go`) adopt one clone for each contributing owner, and `stale_owner_internal_test.go:52-59` adopts one string for two owners. One owner can also adopt the same allocation twice. Thus "one entry for each root" has no density bound (41 owners that adopt one 2-byte allocation fill a 40-entry window).

Decision: one index entry for each **(granule key, allocation base)**. The entry holds up to `MaxSnapshotOwners` (4) owner references (`refs`), and **at most one ref for each owner** (critic round 5, finding 2). A second adoption of the same allocation by the same owner does not add a ref and does not make a second root: it **extends** the earlier root in place (its span and ranges become a union of both, 5.2.2 "Extension", critic round 7). A ref of a fifth **distinct owner** is refused (counter `fanout`), and that root admission fails (section 5.2.2). This matches Q7 (4 owners, not 4 adoptions) and the snapshot limit: `Lookup` returns at most 4 owners, with one contribution for each owner. Correction (critic round 6, finding 2): the old `putWindow` moved a slot to the latest root only for the same **exact** key: pointer, length, kind and owner (`value.go:172`). Two adoptions of one allocation at different lengths kept two slots, and both values stayed tainted. The extension keeps that coverage: every value that the earlier root covered stays covered.

Density proof: adoption requires that the value starts at its allocation base (section 1.3), and a root span is at most the allocation size (`len` or `cap`). Two live allocations never overlap, and two allocations never have the same base. Thus the entries of one key belong to distinct, non-overlapping allocations of >= 2 bytes, and the last column is a hard bound on **entries** for one key. The probe window (40 entries, below) is larger than both bounds. A root is refused only when the probe window is full of entries of **other** keys (load, not density), or when the allocation already has 4 references. The counters `indexFull` and `fanout` record this. If a caller breaks the adoption contract (an interior base), the bound can fail; the result is an `indexFull` refusal, not a wrong match (validation checks `base` and `span`, 5.2.3).

```go
const (
	ShiftS, ShiftL       = 6, 12
	MaxSpanS             = 256
	IndexShards          = 256
	IndexBucketsPerShard = 16
	IndexBucketSize      = 8       // 256 * 16 * 8 = 32 768 entries
	IndexBucketProbe     = 5       // home bucket + 4: 40 entries
	FilterBuckets        = 1 << 15 // 32 768 counters, 128 KiB
)

type ownerRef struct {
	ownerGen uint32 // low 32 bits of the owner generation (defense; Finish removes refs first)
	rootID   uint16 // one ref for each owner in an entry; never changes (5.2.2, Extension)
	ownerIdx uint8
	kind     Kind
} // 8 bytes

type indexEntry struct {
	key  uintptr // tier bit | (address >> shift) + 1; 0 = empty
	base uintptr // allocation base
	span uint32  // max span of the refs; prefilter only, validation reads root.span
	n    uint8   // refs in use, 1..MaxSnapshotOwners
	refs [MaxSnapshotOwners]ownerRef
} // 56 bytes (measured, arm64 and amd64). No root generation: see 5.2.3.

type indexShard struct {
	mu      sync.RWMutex // 24 bytes
	buckets [IndexBucketsPerShard][IndexBucketSize]indexEntry
} // 7 192 bytes (measured)

// In Store:
//   index  [IndexShards]indexShard     // 256 * 7 192 B = 1 841 152 B (1.76 MiB), incl. 256 mutexes
//   filter [FilterBuckets]atomic.Uint32 // 131 072 B
// In rootRecord (guarded by rootsMu):
//   indexed bool   // true only after all refs of this root are published
// In owner (guarded by rootsMu):
//   extending bool // an extension of a root of this owner is in progress (5.2.2, Extension)
```

Memory (computed estimate). Method: `unsafe.Sizeof` of mirror structs with the step 3 layout (value table and `valueQuota` removed, `indexed` added, 3 new drop counters), compiled in the real package through `go test -overlay`, go1.27.1, darwin/arm64; the amd64 test binary compiles with the same layout. Step 3 adds `TestStoreFootprint`, which measures the real types and replaces these numbers.

| Item | Before | After step 3 |
|---|---|---|
| value `shard` x 256 (4 152 B each) | 1 062 912 B | deleted |
| `rootRecord` | 320 B | 312 B: `valueQuota` (8 B) deleted; `indexed` at offset 64, `inline` at 72 |
| `owner` (512 roots, drop counters) | 187 440 B | 183 368 B (-4 096 B roots, +24 B counters) |
| `Store.compactions`, `Store.compactAborts` | 16 B (offset 13 391 432, the last fields) | deleted |
| `Store.values` | 4 B | replaced by `indexedRoots` (4 B, same place) |
| `indexShard` x 256 | - | 1 841 152 B |
| filter | - | 131 072 B |
| `Store` total | 13 391 448 B | 14 040 136 B (**+648 688 B, +0.62 MiB**) |

Arithmetic (critic round 5 asked for a recheck): 13 391 448 - 1 062 912 (value shards) - 64 x 4 072 (owners: 260 608) - 16 (compaction counters) + 1 841 152 + 131 072 = **14 040 136 B**. The "before" values are measured on the current code (`unsafe.Sizeof` through `go test -overlay`, go1.27.1, darwin/arm64: `Store` 13 391 448, `owner` 187 440, `shard` 4 152, `rootRecord` 320, `compactions` at offset 13 391 432). The critic value 14 040 152 B is the same sum without the 16 B of `compactions` and `compactAborts`; section 5.4 deletes them. The index and the filter cost +1 972 224 B (+1.88 MiB, accepted in Q5). The removal of the value table saves 1 323 536 B (1 062 912 + 260 608 + 16; 1.26 MiB). The net change is +0.62 MiB. The round-7 field `owner.extending` uses padding (round 7 deletes the round-5 fields `rootRecord.next` and `owner.replacing`): step 3 `TestStoreFootprint` confirms that `rootRecord` stays 312 B and `owner` stays 183 368 B, or the commit message explains the difference. Step 5 deletes `operatorActive` (8 B) and updates `TestStoreFootprint`.

`TestStoreFootprint` asserts the `Store` size for each 64-bit `GOARCH` in CI, so a later field change that adds padding fails loudly. 32-bit platforms are not supported by this plan.

The shard is `hash(key) % IndexShards`. The home bucket is `(hash(key) >> 8) % IndexBucketsPerShard`. The probe visits the home bucket and the next 4 buckets of the same shard (wrap-around). Delete clears an entry (`key = 0`). A lookup always scans all 5 buckets, so there are no tombstones.

#### 5.2.2 Publication: all or nothing

Problem (critic finding 2): if insertion stops at granule k, the entries for granules 0..k-1 stay in the table.

Problem (critic round 2, finding A): if a root can be live without index entries, a filter miss does not prove "clean". Then `pre` treats a tainted operand as clean, the result stays on the stack, and the taint is lost.

**Admission rule:** index publication is a condition of root admission. A root is visible to lookup only when `root.indexed == true`. If index publication fails, the root admission fails (`rollbackRoot`, the same path as a failed `putWindow` before step 3) and the operation records `indexFull`, `fanout` or `contention`. Thus there is no live root outside the index, and a zero filter bucket is a proof that no visible root covers the granule.

Where: in `Owner.adopt` (also used by `AdoptRunes` and `AdoptStringAlloc`, section 4.5), `AdoptSourceBytes`, and the four `Taint*` functions (`root.go`). Index publication takes the place of the `putWindow` call. This code runs inside `beginWrite` / `endWrite`, so `Finish` cannot run at the same time (it waits on `lifecycleMu.Lock`).

**One root for each owner and allocation (critic round 7).** For one owner and one allocation base, there is at most one root record. A later adoption of the same allocation by the same owner does not make a second root: it **extends** the first root in place ("Extension", below). Thus one generation (`root.generation`) covers every range that this owner has for this allocation. Rounds 5 and 6 made a new root and moved the refs to it (`prev.next`, `owner.replacing`, a one-hop redirect). Round 7 deletes that design: a mutation that claimed `prev` without `rootsMu` could not invalidate the ranges that the merge had copied into the new root (Appendix F, finding 1).

Step 0 (all adoption paths). Every root has a ref in the key of its base granule, in its tier. For the base key of each tier, **tier S first, then tier L** (the reader order, below): `shard.mu.TryRLock()` (failure: `contention`, fail the admission), find the entry with this `base`, copy the ref of this owner (`ownerIdx`, `ownerGen`, `rootID`) if there is one, unlock. No ref: a **first adoption** (steps 1-6). A ref: an **extension** of root `R = roots[ref.rootID]` (steps E1-E5). Step 0 runs before `reserveRootSlot`, so an extension never uses a root slot. The `Taint*` functions clone into a new allocation, so step 0 finds no ref for them; they run it only to keep one code path.

First adoption:

1. `reserveRootSlot` and `publishRoot` as today (`indexed == false`, so no reader uses the root). Compute the list of granule keys (<= 17) of `[base, base+span)` in the tier of `span`, in a stack array.
2. For each key: `shard.mu.TryLock()`. Look for an entry with this `key` and `base` in the 5 buckets. Then:
   - the entry has a ref of **this owner** (same `ownerIdx` and `ownerGen`): another adoption of this owner on this allocation runs at the same time. Unlock and fail with `contention`;
   - else, the entry has `n < 4`: add the ref, and set `span = max(span, root.span)` (a wider prefilter is always safe, so rollback does not restore it);
   - else (`n == 4`, four other owners): fail with `fanout`;
   - no entry: write a new entry in the first empty place.
   Unlock. Record `(shard, bucket, index)` in a stack array `inserted [17]pos`.
3. If step 2 fails for any key (contention, no empty place, or `fanout`): **roll back** (step 6), record the counter, fail the admission. Stop.
4. All keys done: `indexedRoots.Add(1)` (the gate is now on, section 3.2 rule 3), then `filter[bucket(key)].Add(1)` for each key.
5. `rootsMu.TryLock()`. Checks: (a) the root generation is still the published one; (b) owner re-check: for the base key of each tier, `shard.mu.TryRLock()` (a try, never a wait), check that every ref of this owner with this `base` has the `rootID` of this root, unlock. Check (b) stops two concurrent first adoptions of one owner in **different** tiers (for example 100 B and 300 B views of one allocation, with different base keys): commits of one owner are serialized by `rootsMu`, and each publication inserts its refs before its commit, so the second commit always sees the refs of the first one and fails. If all checks pass: `root.indexed = true`. Unlock. Done: the root is now visible. If a check fails, or if `TryLock` fails: unlock if locked, decrement the filter counters of step 4, roll back (step 6), then `indexedRoots.Add(-1)`, record `contention`, fail the admission.
6. Rollback: for each recorded `pos`, `shard.mu.Lock()` (blocking; see the lock order below), remove this root's ref (`ownerIdx`, `ownerGen`, `rootID`); if `n` becomes 0, clear the entry (`key = 0`); unlock. Then `rollbackRoot`.

**Extension (critic rounds 5, 6 and 7).** Rule: after an extension, root `R` covers every value that an earlier adoption of this owner on this allocation covered, and every value of the new adoption. An owner never has more than one ref in an entry. Terms: `old = R.span` (read in E1), `U = max(old, span)`. Same base, so `[base, base+U)` contains every value of both adoptions.

- E1. `rootsMu.TryLock()` (failure: `contention`, fail). Checks: `R.indexed == true`, `R.base == base`, `owner.extending == false`, and every ref of step 0 has the `rootID` of `R`. If a check fails: unlock, fail with `contention`. Else: `owner.extending = true`, read `old`, unlock. Then reserve the charge of the new adoption on the owner and the store (`reserveInt64` against `RequestRootBytes` and `ProcessRootBytes`, as `reserveRootSlot` does; failure: `bytes`). The charge stays until `Finish`, the same as the charge of a second root today, so the sum of the charges is at least the retained memory. On any failure after E1: release the charge if it is reserved, then clear `extending` (`rootsMu.Lock()`, no other lock held).
- E2. If `U == old`: no index change, go to E4. Else compute the keys of `[base, base+U)` in the tier of `U`. A key that is already a key of `R` (same tier as `old`, granule inside `[base, base+old)`) needs only `span = max(span, U)` on its entry (`shard.mu.TryLock()`). For each **new** key: `shard.mu.TryLock()`, find the entry `(key, base)`; a ref of this owner in it: fail with `contention`; else `n < 4`: add a ref to `R`; `n == 4`: `fanout`; no entry: new entry. Unlock. Record the added positions.
- E3. On failure in E2 or E4: remove the added refs (the loop of step 6, without `rollbackRoot`), record the counter, fail the admission. `R` does not change: it keeps its refs, its span, its ranges and `indexed == true`.
- E4. `filter[bucket(key)].Add(1)` for each added ref. `rootsMu.TryLock()`. Check: `R.indexed == true` and `R.setGen == R.generation.Load()` (the ranges of `R` are valid now). If the check fails (a mutation claimed `R` and did not publish yet, or its publication failed), or if `TryLock` fails: unlock if locked, decrement the filter counters of the added refs, E3, `contention`. Else commit: merged ranges (union rule, below), stored with the `publishRangesLocked` logic **without** a change of `R.generation` or `R.setGen`; `R.span = U`; each anchor field (`stringAnchor`, `bytesAnchor`) takes the new anchor when the field is empty or holds a shorter anchor. Record `g = R.generation.Load()`. Unlock. Free the old overflow block after the unlock.
- E5. Clean-up (still inside `beginWrite` / `endWrite`, so `Finish` cannot run): if `old` is in tier S and `U` is in tier L, for each tier S key of `R`: `shard.mu.Lock()` (blocking, no other lock held), remove the ref of `R` (clear the entry at `n == 0`), unlock, then `filter[bucket(key)].Add(-1)`. Then `rootsMu.Lock()`, `owner.extending = false`, unlock. Return `RootRef{R.ID, g}`. `indexedRoots` does not change.

Union rule (critic round 7, finding 2). One rule for **all** kinds (`KindString`, `KindBytes`, `KindRunes`, and mixed kinds):

- Merged ranges = `ranges.Canonicalize(&dst, R.limit, newRanges ++ Rranges, U)`. A range set holds one provenance for each byte. On bytes that both sets describe, the new ranges win (input-order precedence, `canonical.go:9-14`); on all other bytes, each range of both sets is kept. Thus a byte that is tainted in one of the two sets stays tainted. Example: a 64-cap bytes allocation adopted with X on `[0,8)`, then a 32-cap view adopted with Y on `[16,24)` and no tracked write between them: `R` has X on `[0,8)` and Y on `[16,24)`.
- Only a tracked mutation (`PublishBytesMutation`, 5.2.3) replaces earlier ranges. A re-adoption never removes taint. If the application wrote bytes of a bytes root without a tracked mutation, the old provenance of those bytes can stay (over-taint). This is the accepted trade-off of Q2 and R13 (section 4.4). Rounds 5 and 6 had a "mutable rule" (the new adoption wins on `[0, span)`); it is deleted: it removed taint without a tracked mutation, and the old table kept that taint in the exact slot of the earlier adoption.
- Cap: the input is at most 2 x 64 = 128 ranges (`MaxCanonicalInput` is 192). The output is at most `R.limit` (<= `HardLimit`, 64) ranges; `Canonicalize` drops the tail beyond the limit (`Truncated`), and the `publishRangesLocked` logic keeps `GuaranteedRanges` when no overflow block is free. Each drop increments `drops.ranges`, the same counter as today. Cost: `Canonicalize` is O(n^2) for n <= 128, on the stack, only on this writer path.
- Kind: `R` keeps the kind of its first adoption (`Entry.Kind`). The interior match ignores `Key.Kind` (5.2.4).

**Mutation and extension (critic round 7, finding 1).** `claimMutation` is a lock-free `CompareAndSwap` on `R.generation` (`mutation.go:83-89`). Invariant: **every range of `R`, including the ranges that an extension added, is valid only while `R.setGen == R.generation`.** An extension never writes `generation` or `setGen`. A claim changes `generation` with one CAS. Thus a claim at any time (before E4, between the E4 check and the commit, or after the commit) makes every range of `R` invalid in one step, with or without `rootsMu`. If the mutation then fails, `R` stays a miss for all its views until `Finish`. No record keeps stale pre-mutation ranges, because there is no second record. A later extension of `R` sees `setGen != generation` in E4 and fails with `contention`: that re-adoption is refused (R19).

Race test for finding 1: owner A adopts a bytes allocation (cap 64) with X on `[0,8)`, then starts an extension with a 32-cap view and Y on `[16,24)`. A test-only hook pauses the extension inside E4, after the validity check and before the commit (under `rootsMu`). Another goroutine calls `PublishBytesMutation` with the first `RootRef`: the claim CAS succeeds (no lock), and a test-only hook forces its `rootsMu.TryLock` to fail. Then the test resumes the extension. Assert: `PublishBytesMutation` returned `false`; the extension committed; `Lookup` of `(base, 64)`, `(base, 32)`, `(base, 8)` and `(base+16, 8)` is a miss (no X, no Y). The same test with the claim before E4 (the extension fails with `contention`, lookups are a miss) and after the commit (lookups are a miss). Negative control: make the commit set `R.setGen = R.generation.Load()`; the test must fail (X is visible after the failed mutation).

**Reader order (critic round 7).** A ref never changes its `rootID`: writers only add refs and remove refs, under `shard.mu.Lock()`. Thus a reader copies the matched refs under `shard.mu.TryRLock()`, unlocks, and then validates the copies (5.2.3): the root of a copied ref is the same record, and validation reads its current state (a root that became not admitted gives a miss, which is then correct). The round 6 reader rule (validation under the shard read lock) is not necessary any more, and it is deleted with the `next` hop. One order rule is necessary: an extension from tier S to tier L adds and counts its tier L refs (E2, E4) **before** it removes and uncounts its tier S refs (E5). A reader completes tier S (filter load and shard probe) **before** it loads the tier L filter bucket (5.2.4 step 2); it never loads the tier L bucket early (critic round 8). With sequentially consistent atomics and the shard locks, a reader that sees the tier S ref removed reads tier L after that removal, thus after the tier L insert. Thus a value of `R` is never a miss during the move. Test: an S to L extension (200 B, then 300 B) and its `Finish` run in a loop while readers look up `(base+150, 10)` between the adoption and `Finish`; no miss. Negative control: read tier L first, with a test-only hook between the two tier reads; the test must fail. Second negative control (critic round 8): load both filter buckets before the probes, with a test-only hook after the loads that runs a full S->L extension including E5; the test must fail.

Invariants:

- A reader can see refs of a root whose `indexed` is false. Validation (5.2.3) requires `indexed == true`, so the reader gets a miss. Partial state is never visible as a match.
- Gate order: `indexedRoots` >= the number of roots with `indexed == true`, at every instant. The increment is before `indexed = true`; the decrement is after `indexed = false`. Go `sync/atomic` operations are sequentially consistent, and the `rootsMu` unlock / `TryRLock` pair orders the reader after the increment.
- For each filter bucket `b`: `filter[b]` == the number of `(ref, key)` pairs published (from step 4 or E4 to removal) where `bucket(key) == b`. `indexed == true` implies that all pairs of the root are counted. A test checks this sum after every operation of a randomized sequence.
- One owner has at most one root record and at most one ref in an entry for one allocation. That root covers the span of every earlier adoption of this owner on this allocation, and every byte that one of those adoptions tainted stays tainted until a tracked mutation. The randomized sequence test checks this with repeated adoptions by one owner, at random spans and with random ranges.
- Rollback never leaves a ref. Test with failure injection (a test-only hook that fails the insert of granule k) for every k in 0..16 of a 64 KiB root, and for every k in 0..4 of a tier S root, for a first adoption and for an extension. After each case: the admission returned `false`; all filter buckets are at their earlier value; for a first adoption, 0 refs and `Lookup` of the value is a miss; for an extension, `R` has its earlier refs, span and ranges, and `Lookup` returns them. Concurrent readers during the test never see a match for a partial root.

Remove (in `Owner.Finish`, under `rootsMu.Lock()`, before the anchors are cleared): for each root with `indexed == true`, set `indexed = false`, recompute its keys, `shard.mu.Lock()`, remove its ref (the ref of this owner with this `rootID`; clear an entry at `n == 0`), unlock, decrement the filter counter only for a ref that was removed, then `indexedRoots.Add(-1)` (last). `Finish` also sets `owner.extending = false`. `rollbackRoot` needs nothing more: if it runs, index publication failed and step 6 already removed every ref.

Lock order: `rootsMu` then `shard.mu`. `Finish` holds `rootsMu` and waits on `shard.mu`. The publication path never holds a shard lock while it waits: it takes shard locks only when it holds no `rootsMu` (except check (b) of step 5, a `TryRLock`), and it takes `rootsMu` with `TryLock`, or with `Lock` (E1 failure, E5) only when it holds no shard lock. `Finish` cannot hold `rootsMu` at that time (it waits on `lifecycleMu.Lock`, and the writer holds `beginWrite`). Readers take `shard.mu.TryRLock`, unlock it, then take `lifecycleMu.TryRLock` and `rootsMu.TryRLock`, and never wait. Thus no cycle of blocking waits exists. `checklocks` annotations record this.

#### 5.2.3 Generation rule (byte mutation)

Problem (critic finding 3): `Owner.PublishBytesMutation` (`mutation.go:21-78`) changes the root generation (`claimMutation`) and then `setGen`, but it does not call `publishRoot`. An index entry that stores the generation at publication becomes stale after the first mutation, and subslices of the mutated root lose taint.

Step 3 changes `mutation.go` for the removal of the value table (5.4): `claimMutation` only does the generation `CompareAndSwap` (the `valueQuota` swap and the value-counter subtraction at `mutation.go:91-96` are deleted), and `PublishBytesMutation` returns success after it stores the new ranges and `setGen` under `rootsMu` (the final `putWindow` at `mutation.go:73` is deleted). Thus a mutation has only two failure points after the claim: the `rootsMu.TryLock` fails, or the identity check (`mutation.go:50`) fails. Step 3 also changes the identity check for extended roots ("Mutation of an extended root", below).

Decision: an index ref stores the **identity** of the root, not its generation: `ownerIdx`, `ownerGen`, `rootID`, and the entry `base`. Validation of one ref reads the **current** generation:

1. Owner: `uint32(owner.generation) == ref.ownerGen` and state is active (the same check as `Lookup`).
2. Under `rootsMu.TryRLock()` (after the shard unlock; a ref never changes its `rootID`, 5.2.2 reader order): `root.indexed`, `root.base == entry.base`, `p+n <= base+root.span`, `g := root.generation.Load()`, `g != 0`, `root.setGen == g`, `root.count != 0`.
3. Slice the ranges with `ranges.Slice(&w, root.limit, &canonical, root.span, p-base, p-base+n)`. Check `root.generation.Load() == g` again after the copy (the same as `Lookup` line 182). Return an `Entry` with root generation `g`.

Why this is correct:

- `PublishBytesMutation` requires `root.base == key.Pointer` and `cap(value) <= root.span` (step 3 form; today `root.span == cap(value)`, `mutation.go:50`). A mutation never changes `base` or `span`, so the index needs no update.
- After a successful mutation, `setGen == generation`, and the lookup returns the new ranges. The root stays indexed, and `indexedRoots` does not change, so the gate stays on (3.2 rule 3).
- Between `claimMutation` and publication, and after a failed publication, `setGen != generation`. The lookup is a miss. This is the same rule as the method comment: "Returning false never restores stale pre-mutation provenance." The root stays indexed until `Finish`, so the gate can stay on for a root that has no valid ranges. This costs time (filter hits that `confirm` rejects), never taint and never an allocation.
- Root slot reuse inside one owner: `Finish` removes entries; a new root in the same slot has a new `indexed` publication. If the new root has the same `base` and `span`, it is the same memory with its own current ranges, so a match is correct.
- Owner slot reuse: `Finish` removes every ref before the slot can be reused. `ownerGen` is a second protection (32 bits are enough: a wrap needs 2^32 reuses of one slot during one reader's probe).

**Mutation of an extended root (critic rounds 6 and 7).** An extension (5.2.2) can give a bytes root a span `U` larger than `cap(value)` of a later mutation. Every adoption of this owner on this allocation returns a `RootRef` with the same `R.ID`, so there is only one generation to claim. Step 3 rules:

- Identity check: `root.bytesAnchor != nil`, `root.base == key.Pointer`, `cap(value) <= root.span`. When `cap(value) == root.span`, the behavior is the same as today. When `cap(value) < root.span`: the mutation ranges replace the ranges on `[0, cap(value))`. The ranges of `R` on `[cap(value), root.span)` stay only if `root.setGen == ref.Generation` (they were valid just before the claim, and the mutation did not write those bytes); else they are dropped (a miss beyond `cap(value)`, counted in `drops.ranges`). This uses `ranges.Clear` + `Canonicalize`, with the same cap and the same `drops.ranges` counter as the union rule.
- No redirect: `claimMutation(ref)` claims the generation of `ref.ID` as today. It is the only generation that covers these ranges (5.2.2, "Mutation and extension"). Rounds 5 and 6 had a redirect through `prev.next`; it is deleted.
- Failure after the claim (contention or a failed identity check): return `false`. The claimed generation stays invalid, so every view of `R` is a miss. This loses taint (counted) and never restores stale pre-mutation provenance.

Tests: taint a bytes root, mutate it with `PublishBytesMutation`, look up an interior subslice (new ranges); a failed mutation, then an interior lookup (miss); a mutation during concurrent interior lookups under `-race`. Extended roots: adopt `b` (cap 64) with X on `[40,48)`, re-adopt `b[:32:32]` (same owner: an extension, same `R.ID`); mutate through the first `RootRef` with value `b`: only the mutation ranges; mutate through the `b[:32:32]` ref: the mutation ranges on `[0,32)`, and X on `[40,48)` stays; the same mutation with a test-only hook that forces `setGen != ref.Generation`: the tail is dropped and `drops.ranges` is +1; the race test of 5.2.2 ("Mutation and extension").

Gate tests (the root is the **only** root of the process store): (a) after a successful mutation, `gate != 0` and an interior `Lookup` finds the new ranges; (b) with a forced `rootsMu.TryLock` failure after the claim (test-only hook), `PublishBytesMutation` returns `false`, `gate != 0`, an interior `Lookup` is a miss (no stale provenance), and `Finish` then sets `gate == 0`; (c) concurrent publish / mutate / finish / lookup under `-race`, with a test-only hook inside ref validation (under `rootsMu.TryRLock`, `indexed == true`) that asserts `gate != 0`; (d) after `Finish` of the last root, `gate == 0`. Negative control: make `claimMutation` decrement `indexedRoots` (the shape of the old value-counter subtraction); test (a) must fail.

#### 5.2.4 Lookup of value `(p, n)`

1. Two keys: `kS = S | (p >> 6) + 1` and `kL = L | (p >> 12) + 1`. Only the granule of the **start** pointer is needed: a root that contains `p` is registered in every granule it covers.
2. Tier S **completely first**: load `filter[bucket(kS)]`; if it is non-zero, probe the tier S shard (step 3). Only **after** that, tier L: load `filter[bucket(kL)]`; if it is non-zero, probe the tier L shard (step 3). Both loads are 0 -> miss. This is the hot path: two hashes, two atomic loads, no lock. It is a correct "clean" answer because every visible root is indexed (5.2.2), and a root is the only place where taint is stored. Do **not** load both filter buckets before the probes (critic round 8): a reader could load the L bucket before an S->L extension, probe S after E5 removed the S ref, and skip L on the old L value. `confirm` uses the same order.
3. Probe of one tier: `shard.mu.TryRLock()` (contention = miss for sinks, `unknown` for `confirm`, counted), scan the 5 buckets for `entry.key == k` and `base <= p && p+n <= base+span`. Copy the matched refs and the entry `base`, then `shard.mu.RUnlock()` (5.2.2, reader order).
4. Validate each ref (5.2.3). Skip a ref when the sliced range set is empty (a clean part of a sparse root). **One contribution for each owner** (critic round 5, finding 2): an entry has at most one ref for each owner, but during an extension from tier S to tier L one owner can have a valid ref in both tiers for a short time (both have the same `rootID`, so both give the same ranges). Keep the first valid ref of an `ownerIdx` and skip the next ones (counter `dupOwner`, expected 0 outside an extension). Thus a `Snapshot` has at most `MaxSnapshotOwners` distinct owners.

`MayContain(key)` becomes steps 1-2 only. `Lookup(key)` becomes steps 1-4. There is no other table (5.4). For a value that had an exact slot before step 3, the interior match gives the same ranges (`rootOff == p - base`). Behavior changes: `Kind` (next paragraph); every window of a live root is found, not only the windows that some hook recorded with `Derive`; windows no longer use a value quota (`RequestValueLimit`, `MaxValuesPerRoot`). `confirm` (section 3.2.1) is steps 1-4 with a range-overlap scan instead of the range copy of 5.2.3 step 3.

Kind: the interior match ignores `Key.Kind`. A string view of a bytes root reads the same bytes (the `...TMP` aliases need this). `Entry` keeps the root kind for callers that need it.

### 5.3 Analysis

| Topic | Result |
|---|---|
| **Hot-path cost of `MayContain`** | Filter miss: two multiply-shift hashes plus two `atomic.Uint32.Load`, no lock, no exact probe (target <= 3 ns). Filter hit on a clean value: `TryRLock` + <= 40 entries (target <= 45 ns). Expected cost = miss cost + (hit rate x hit cost). The hit rate depends on the load (next row), so the benchmarks run under sparse, typical and full load (section 9.2). |
| **Filter false positives** | A bucket is non-zero when any published ref covers a granule with the same hash. For `d` distinct keys in 32 768 buckets, a random clean pointer hits at least one of its 2 buckets with probability approx. `1 - e^(-2d/32768)`. Sparse (`d` = 100): < 1 %. Typical (`d` = 2 500): approx. 14 %. Full index (`d` = 32 768): approx. 86 %; then almost every check pays the probe (approx. 40 ns expected). Clean pointers in the same granule as a live root always hit. A false positive costs one `confirm` or one probe, never an allocation (section 3.2.1). `FilterBuckets` stays 32 768 (Q5 accepted this size). |
| **Address reuse after GC** | Not possible while the root is live: `stringAnchor` / `bytesAnchor` hold the allocation, and adopted roots start at their allocation base (section 1.3). After `Finish`, `root.generation == 0`, so a stale entry fails validation even before removal. Validation runs under `rootsMu.TryRLock`, and `Finish` takes `rootsMu.Lock`, so a reader never validates a root while `Finish` clears it. |
| **Bytes in the size-class tail** | An allocation can be larger than `span` (size-class rounding). Those bytes belong to the same object and cannot be reused while it is live. The index uses `span`, so a view outside `span` is a miss. That is correct. |
| **Zero-length values** | `validKey` requires `Length > 0`. Empty strings and empty slices stay untainted. `p` of an empty slice at the end of a root (`b[len(b):]`) is never looked up. |
| **One-byte values** | A one-byte window of a live root is found (the same as `Derive` before step 3). One-byte conversion results are not in any root (section 4.1). |
| **Roots larger than a granule** | Registered in every covered granule (tier S <= 5, tier L <= 17). Entries for all live allocations: at most 5 x (tier S count) + 17 x (tier L count). The table (32 768 entries) holds 6 553 tier S allocations in the worst case; the practical load is < 2 500 entries. Overflow refuses the root admission (next row). |
| **Memory bound** | Fixed: `Store` 13 391 448 B -> 14 040 136 B (+648 688 B net: index +1 972 224 B, value table -1 323 536 B; computed estimate, 5.2.1), allocated in `store.New()`. No growth. When the probe window is full, the root is refused (admission rule, 5.2.2; counter `indexFull`): the value is not tainted. |
| **Admission loss, old vs new** | Old: a source root (`TaintString`, `TaintBytes`, `TaintSourceString`, `TaintSourceBytes`, `AdoptSourceBytes`) is refused by the root quotas or by `putWindow` (one value slot: at most 16 384 in the process, shared with derived windows, 64-probe window). New: no value slot; it is refused when an index shard `TryLock` fails, when a 40-entry window is full, or at `fanout`. Capacity against the old limit of 16 384 roots: 256 B roots (<= 5 tier S entries): at most 6 553 (approx. 40 %); roots of <= 64 B (<= 2 tier S entries) and 257 B roots (<= 2 tier L entries): approx. 16 384 (approx. 100 %). One request (<= 512 roots) uses at most 8 704 entries. Typical requests (< 2 500 entries) are far below these limits. Step 3 measures the real loss (9.2) against the budget of Q9. |
| **Many small roots in one granule** | Tier S bounds one key to 33 entries; tier L to 17. Both are < 40 (probe window). Tests: 128 roots of 8 B allocated one after the other (they share one 4 KiB region and some 64 B granules); 33 roots of 2 B in one 64 B granule. Every root must be found by an interior lookup. Step 3 also measures a 1 000-parameter request. |
| **Shared allocations** | One entry for each allocation, <= 4 refs, one ref for each owner, one root for each owner and allocation (5.2.1, 5.2.2 Extension). Tests: 4 owners adopt one 2-byte allocation (all found); 41 owners try to adopt one allocation (4 succeed, 37 refused with `fanout`, no other root in the granule is lost); 33 distinct 2-byte allocations in one 64 B granule, each shared by 4 owners (all 132 roots found). Repeated adoption (critic rounds 5, 6 and 7): one owner adopts one string allocation 5 times with disjoint ranges at the same span: 1 root, 1 ref, the same `R.ID` in the 5 `RootRef` values, `Lookup` returns the union of the 5 range sets, one `Snapshot` contribution, filter sum and `indexedRoots` the same as after the 1st adoption; owner A adopts one allocation 4 times, then owners B, C and D adopt it: all 4 owners are found, no `fanout`; a 5th distinct owner gets `fanout`. **Longer then shorter** (round 6, string, tier S): owner A adopts 200 B with ranges X on `[0,10)` and `[150,160)`, then 100 B (same allocation) with ranges Y on `[20,30)`. After the extension: `Lookup(base, 200)` returns X `[0,10)`, Y `[20,30)`, X `[150,160)`; `Lookup(base, 100)` returns X `[0,10)`, Y `[20,30)`; `Lookup(base+150, 10)` is tainted with X. The same test with overlapping ranges (Y wins on the shared bytes), cross tier (300 B then 100 B: `U == old`, no index change; 100 B then 300 B: tier L refs added and counted, then the tier S refs are removed and counted down, one contribution), and shorter then longer (new keys added and counted). Union rule for bytes (round 7, finding 2; one rule for all kinds): a 64-cap allocation adopted with X on `[0,8)`, then a 32-cap view `b[:32:32]` adopted with Y on `[16,24)` (no write): `Lookup(base, 64)` returns X `[0,8)` and Y `[16,24)`; the same cap re-adopted with Y on `[4,12)`: X `[0,4)` and Y `[4,12)` (Y wins on the shared bytes, no taint removed); `KindRunes` and a string view of a bytes root: the same union. Only a tracked mutation removes X (5.2.3 tests). Range cap: 40 + 40 disjoint ranges with limit 64: 64 ranges kept, `drops.ranges` +1. Extension failure: failure injection at each new key of E2, a forced `TryLock` failure in E1 and E4, and a forced E4 validity failure: `R` keeps all its refs, its span, its ranges and `indexed == true`, the charge is released, and `extending == false`. Concurrency under `-race`: readers during an extension never miss a value of `R` and never see two contributions of one owner; two concurrent re-adoptions of one owner on an existing root: one succeeds, one fails with `contention` (`extending`); two concurrent first adoptions of one owner (same tier, and 100 B / 300 B in different tiers): one succeeds, one fails with `contention`, never two roots. The race test and the reader order test of 5.2.2. |
| **Contention** | Sink readers: `TryRLock`, failure = miss + `contention` counter (the same rule as today). Readers hold the shard read lock only while they scan and copy refs (5.2.2, reader order); a writer `TryLock` on that shard can fail for that time; the stressed admission benchmark measures it (9.2). `confirm`: failure = `unknown`, so `pre` forces the heap (3.2.1): no taint loss, one allocation. Writers: `TryLock` on insert; a failure refuses the root admission (5.2.2). Blocking `Lock` only in rollback and `Finish` (lock order in 5.2.2). |
| **Mutable bytes roots** | Entries store identity, not generation (5.2.3). A mutation keeps interior lookups working with the new ranges. |

### 5.4 What this removes (Q4: in this change, step 3)

After step 3, every tainted value is a root or a window of a root, and the lookup path reads only the interior index. Thus step 3 deletes the exact value table and everything that exists only for it (checked in `internal/taint/store` and its callers):

| Place | Delete |
|---|---|
| `store.go` | `valueSlot`, `shard`, `Store.shards`, `Store.values`, `owner.values`, `rootRecord.valueQuota`, `Store.compactions` / `compactAborts`, `ActiveValues()` (replaced by `IndexedRoots() *atomic.Int32`), `ProcessValues()`; `Stats` loses the tombstone and probe fields and gets index fields (entries in use, maximum probe) |
| `value.go` | `putWindow`, `insertWindow`, `stale`, `reclaim`, `compact`, `recordProbe`, `reserveRootValue`, `releaseRootValue`, `initialSlot`, `forceCollision`. Keep `keyHash` only if the index uses it, and keep `validKey`, `inWindow`, `reserveInt64` |
| `limits.go` | `Shards`, `SlotsPerShard`, `ProbeLimit`, `ProcessValueLimit`, `RequestValueLimit`, `MaxValuesPerRoot`, `compactionThreshold`, `tombstone` |
| `root.go` | every `putWindow` call (six places; index publication replaces it, 5.2.2), `Owner.Derive`, the `valueQuota` stores in `publishRoot` and `rollbackRoot` |
| `mutation.go` | the `valueQuota` swap and counter subtraction in `claimMutation`, the final `putWindow` (5.2.3) |
| `owner.go` | `Owner.Values()`, the `values` swap and subtraction in `Finish`, the `valueQuota` store |
| `lookup.go` | the exact probe in `MayContain` and `Lookup` (replaced by 5.2.4), `lookupWindow` |
| `internal/taint/propagation` | `deriveStringWindow`, `deriveBytesWindow` and their 12 production calls (`propagation.go` 10, `string_coarse.go` 1, `bytes_exact.go` 1) and 3 test calls (`stale_owner_internal_test.go`). `StringWindow`, `StringWindows`, `ByteWindow`, `ByteWindows` (`propagation.go:196-535`) become empty: delete them and their 2 internal calls (`string_exact.go:38,118`) |
| `iast/propagation` (named wrappers) | Delete the 39 window-helper **calls** (`strings.go` 20, `bytes.go` 19). After that, 41 wrappers only call the stdlib function and return its result; delete each of them **together with its `replace-function` aspect** in `iast/propagation/orchestrion.yml`, in the same commit (list below). Keep every wrapper that calls another helper. The 10 calls in `operators.go` stay until step 5 (the AST operator aspects stay until step 5) |
| `iast/propagation/telemetry.go` | `instrumentedPropagationPoints` 125 -> 84 (41 aspects deleted). `TestInstrumentedPropagationTelemetry` counts the `- id:` lines of the YAML and checks this constant |
| `request/scope.go` | `jsonbridge.BindActiveValues(store.ActiveValues())` becomes `BindActiveValues(store.IndexedRoots())` (3.2 rule 3) |

Named wrappers to delete in step 3 with their YAML aspect (checked in the code: after the window call is removed, each one is `return stdlib(args)`):

- `strings.go` (23, aspect ids `strings.<Name>`): `Cut`, `CutPrefix`, `CutSuffix`, `Split`, `SplitN`, `SplitAfter`, `SplitAfterN`, `SplitSeq`, `SplitAfterSeq`, `Lines`, `Fields`, `FieldsFunc`, `FieldsSeq`, `FieldsFuncSeq`, `Trim`, `TrimSpace`, `TrimLeft`, `TrimRight`, `TrimPrefix`, `TrimSuffix`, `TrimFunc`, `TrimLeftFunc`, `TrimRightFunc` (as `StringsCut` ... `StringsTrimRightFunc`), and the helper `stringWindowSeq`.
- `bytes.go` (18, aspect ids `bytes.<Name>`): `Cut`, `CutPrefix`, `CutSuffix`, `Split`, `SplitN`, `SplitAfter`, `SplitAfterN`, `Fields`, `FieldsFunc`, `Trim`, `TrimSpace`, `TrimLeft`, `TrimRight`, `TrimPrefix`, `TrimSuffix`, `TrimFunc`, `TrimLeftFunc`, `TrimRightFunc` (as `BytesCut` ... `BytesTrimRightFunc`).
- Kept (they call other helpers): `StringsClone`, `StringsJoin`, `StringsRepeat`, `StringsReplace`, `StringsReplaceAll`, `ReplacerReplace`, `BytesClone`, `BytesJoin`, `BytesRepeat`, `BytesReplace`, `BytesReplaceAll`, `BytesToLower`, `BytesToUpper`, `BytesToTitle`, `BytesMap`, `BytesToValidUTF8`. These are all the other wrappers of the two files.
- No Go code calls a deleted wrapper directly. The tests call the stdlib functions through the woven `iast/internal/propagationtest` package (`testapp.BytesCut`, `testapp.Cut`, ...). Those tests (`iast/propagation/strings_test.go`, `bytes_test.go`, `strings_provenance_test.go`, `bytes_provenance_test.go`) stay and must pass: the results are windows of the input root, and the interior lookup finds them. `benchmarks/overhead` names (`BenchmarkStringsSplit`, ...) also call the stdlib and stay.

Direct callers of the window helpers and `Derive` in tests (`rg 'StringWindows?\(|ByteWindows?\(|\.Derive\('`): `internal/taint/propagation/propagation_test.go` (14), `range_behavior_test.go` (6), `path_native_test.go` (5), `path_entry_test.go` (3), `sequence_operations_test.go` (2), `stale_owner_internal_test.go` (2), `path_lifecycle_test.go` (1), `internal/taint/evidence/collection_behavior_test.go` (1), and `internal/taint/store` `admission_behavior_test.go` (15), `handle_test.go` (2), `generation_test.go`, `memory_test.go`, `mutation_test.go`, `race_test.go`, `saturation_test.go`, `store_test.go` (1 each). Each call is deleted; the test then checks that the window is found by interior lookup (or that it is a miss, for the clean-window and finished-owner cases).

Tests to rewrite (19 files use `ProcessValues`, `Values`, `Derive`, `forceCollision`, `Tombstones`, `ProbeLimit` or the value limits): `ProcessValues() == 0` becomes `IndexedRoots().Load() == 0` and a zero filter sum; `path_native_test.go` "one root plus sixteen sparse windows" becomes "one root, sixteen windows found by interior lookup"; `compaction_test.go` is deleted; the saturation tests use the index limits.

Also removed by this plan (step 5): the slice aspects and the `StringSlice*` / `BytesSlice*` wrappers (section 6.2).

## 6. Design D: remove the unmerged Orchestrion pin

### 6.1 YAML

Delete from `iast/propagation/orchestrion.yml`:

- `operator string concat 2` ... `operator string concat 16`;
- `operator bytes to string conversion`;
- `operator string slice`;
- `operator byte slice`.

Add a new package `iast/runtime` (`orchestrion.yml` with the runtime aspects from sections 3 and 4). Import it from `orchestrion.tool.go` at the root, the same as the other `iast/*` packages. The `links:` list names `github.com/DataDog/dd-iast-go/internal/taint/runtimebridge` and `github.com/DataDog/dd-iast-go/internal/taint/propagation` (3.2 rule 6, link rule).

After the change, this command must print nothing:

```sh
grep -rn 'string-concat\|type-conversion\|slice-expression' --include='*.yml' .
```

### 6.2 Go code to delete

| File | Delete |
|---|---|
| `iast/propagation/operators.go` | the complete file (`Concat2..16`, `concatNResult`, `BytesToString`, `StringSlice*`, `BytesSlice*`, `integer`) |
| `iast/propagation/operators_concat_test.go` | complete file; the woven tests move to `iast/runtime` |
| `iast/propagation/operators_slices_test.go` | complete file; replace with store interior tests |
| `iast/propagation/operators_contexts_test.go` | complete file; keep `TestUnsupportedNativeOperatorContextsDoNotInventProvenance` cases as runtime-hook tests |
| `iast/propagation/operators_test.go` | complete file; `TestOperatorEvaluationAndPanicSemantics` becomes the C4 regression (section 8.2) |
| `internal/taint/propagation/operator_concat.go` | complete file |
| `internal/taint/operatorbridge/` | complete package, after the gate moves to `runtimebridge` |

Keep `internal/taint/propagation/conversion.go` (`BytesToString`); the runtime bridge calls it.

### 6.3 `go.mod` files

Replace `github.com/DataDog/orchestrion v1.12.2-0.20260828141217-23afa71d6dcb` with the released version in all five modules:

- `go.mod`
- `benchmarks/overhead/go.mod`
- `iast/database/sql/testapp/go.mod`
- `iast/integration/testapp/go.mod`
- `iast/os/exec/testapp/go.mod`

Commands (in each module directory):

```sh
go get github.com/DataDog/orchestrion@v1.13.1
go mod tidy
go list -m github.com/DataDog/orchestrion   # must print the released version
```

Version selection, from facts (recorded on 2026-09-24 in the root module):

- `go mod graph | grep ' github.com/DataDog/orchestrion@'` prints only `github.com/DataDog/dd-iast-go github.com/DataDog/orchestrion@v1.12.2-0.20260828141217-23afa71d6dcb`. No other module requires Orchestrion.
- `dd-trace-go/v2@v2.11.0-rc.1/go.mod` has no Orchestrion requirement (0 matches).
- `go list -m -versions github.com/DataDog/orchestrion` ends with `v1.12.1 v1.12.2 v1.13.0 v1.13.1`.
- v1.13.0 and v1.13.1 both require `dd-trace-go/v2 v2.10.1`. That is lower than our `v2.11.0-rc.1`, so MVS does not change dd-trace-go.

Decision: v1.13.1, the highest released version. It is also the version of the prototype. Our requirement is a **minimum** for customers: MVS selects the highest version in their graph. Step 6 adds one CI job that builds the woven tests with the latest released Orchestrion (`@latest`) so that a later release that breaks the aspects is detected.

### 6.4 Other files to check

- `LICENSE-3rdparty.csv:22`: the Orchestrion line has no version. Check that `go mod tidy` does not add or remove other dependencies. Update the file if it does.
- `orchestrion.tool.go`: add `_ "github.com/DataDog/dd-iast-go/iast/runtime"`. Run `go generate` (`orchestrion pin -generate`) and check the diff.
- `.github/workflows/ci.yml` lines 124-149: the `go tool orchestrion go test` step uses the pinned tool, on `ubuntu-latest` only, from `go-version-file`, without `-race` for woven tests. Section 9.4 gives the new matrix.
- `.github/workflows/system-tests.yml` lines 59-67: it reads the Orchestrion version from `go.mod`. No change is necessary; it then pins a released version. Confirm that system-tests pass.

## 7. How the findings are resolved

| Finding | Resolution | Remaining |
|---|---|---|
| **C2** | No aspect uses `string-concat`, `type-conversion` or `slice-expression`. All modules use a released Orchestrion. | None for operators. |
| **C4** (concat, conversion, slice) | No source expression is rewritten. `len([N]T{a + b})` stays constant, and Go does not evaluate it. The runtime hooks run only when Go already calls the runtime function. | Check that the remaining `wrap-expression` aspects (50 in `iast/propagation`, 1 in `iast/net/http`, 1 in `iast/os/exec`) wrap only call expressions. A call is already non-constant, so a wrapper call does not change evaluation. Step 5 adds a test for each. |
| **H27** | The wrappers are deleted. Gate off: 0 extra allocations (prototype). | Other named wrappers are out of scope for this plan. |

Still open after this plan:

- `string(r)` for a rune value, and one-byte conversion results (section 4.1).
- `append` and `copy` (Phase 6 section 5, unchanged).
- Direct writes into tainted `[]byte` (section 4.4).
- Short non-escaping results with **clean** operands stay on the stack. That is correct: they have no taint.

## 8. Risks and trade-offs

| # | Risk | Mitigation |
|---|---|---|
| R1 | **Process-wide overhead.** Every non-constant concat and every `string(b)` / `[]byte(s)` in the process runs the hook: stdlib, dd-trace-go and dd-iast-go code too. | Gate off (variant D, darwin/arm64, step 2): <= +0.54 ns resolved median, 0 allocations (appendix H); amd64 is measured in step 7. Gate on only while an indexed root exists (section 3.2 rule 3). Numeric gates in section 9.3. |
| R2 | **No caller filter.** A runtime hook cannot exclude `dd-iast-go/internal/**` or dd-trace-go. | Recursion guard (section 3.4). Tracer strings are clean unless they contain tainted data, and then taint is correct. |
| R3 | **Runtime internal symbols.** `concatstrings`, `concatbytes`, `slicebytetostring`, `stringtoslicebyte`, `slicerunetostring`, `stringtoslicerune` are compiler-coupled entry points and stable. `stringDataOnStack`, `getg`, `m.curg`, `m.locks`, `tmpBuf`, `tmpStringBufSize` are less stable. Variant D also repeats the signature of each entry point in a body-less alias `//go:linkname __dd_iast_orig_<fn> runtime.<fn>` + `//go:noescape` (section 2.2). | A rename of a helper or field: the runtime does not compile (loud). A rename or a signature change of an entry point: the signature assertions (3.9 item 6) make it a compile error (loud); without them, a rename would silently match nothing and a signature change would be an ABI mismatch. **Alias rule:** the wrapper calls the original function only through the alias, never directly (a direct call changes the escape tags to `leaking param: buf`, 3.8); the alias and the wrapper have no other call site. The escape comparison is a required CI check (9.4). CI woven test for each supported Go version asserts that each hook fires (section 9.1 item 1). |
| R4 | **Linkname policy.** The design depends on two linker rules: references to non-std definitions are not checked, and push-linknamed definitions are permitted (section 3.9). | Explicit `-ldflags=-checklinkname=1` link test for each toolchain (section 9.4). A Go change breaks it loudly at link time. |
| R5 | **`buf = nil` trick.** Correct because every runtime caller accepts `buf == nil` (the compiler passes nil for escaping results). | A test for each Go version checks that the tainted stack case gives 1 allocation and correct taint (prototype `TestAllocsTaintedStack`). |
| R6 | **Whole-cache rebuild.** Weaving `runtime` invalidates the build cache for the full graph. | The GLS aspect already does this. No new cost for dd-trace-go users. |
| R7 | **Interaction with the GLS aspect.** Both add a field to `runtime.g` and inject declarations into `runtime`. | Done in step 2: one binary with dd-trace-go GLS and our aspects; both fields are in the woven `runtime.g`; `TestGLSCoexists` passes (appendix H). Names use the `__dd_iast_` prefix. |
| R8 | **amd64 only partly tested.** Step 2 passed all functional cells on linux/amd64 (under Rosetta emulation) with the `defer` template. Variant D was run only on darwin/arm64 (functional and performance). The D gate-off path on amd64 is `MOVL gate(SB)` + `TESTL` + `JNE`; the same cost is expected, but not measured. | Step 5 runs the D woven tests on linux/amd64 before the commit. Step 6 CI runs all cells on native linux/amd64 (and can report a gate-off benchmark, optional). Step 7 measures the 9.3 gate-off row on native amd64. |
| R9 | **`-gcflags=all=-N -l`.** No inlining: `concatstring2..5` are real calls, and the wrapper is a real call in all builds. Escape analysis can differ. | Step 2 passed `-N -l` with the `defer` template (4 platform x Go pairs) and with variant D (darwin/arm64, 2 Go versions); escape lines identical (58 lines). The step 6 CI job runs the woven tests with `-N -l`. Only correctness is required there, not overhead. |
| R10 | **`-race`.** The runtime is not race-instrumented. `slicebytetostringtmp` is called only in instrumented builds. | The gate uses `internal/runtime/atomic` (no formal data race). `-race` woven tests run in CI. |
| R11 | **Panic in the hook.** | Every bridge function that runs store code (`confirmSlow`, tainted-path callbacks) recovers, with the guard set (3.2 rule 5, 3.4). `__dd_iast_ok` excludes the states where `gopanic` throws (3.3). The filter-only path has no operation that can panic (loops only over `a`, masked array index). |
| R12 | **More allocations with taint.** Each tainted short non-escaping concat or conversion adds one allocation (<= 32 B). | Only on the tainted path. Accepted. |
| R13 | **Bytes and rune over-taint** (sections 4.4, 4.5). | Accepted (Q2): on by default; `DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED=false` turns it off at the cost of one atomic load. |
| R14 | **Source taint loss that the old table did not have.** The admission rule (5.2.2) turns index contention, a full 40-entry window, or `fanout` into a root refusal. Worst case (dense 256 B roots): the index holds approx. 40 % of the 16 384 roots that the old value table permits (5.3); for roots of <= 64 B or > 256 B, approx. 100 %. This is a real regression under high load, not only a new counter. It is permitted by the drop-on-load rule, but it is a trade-off: in exchange, slicing and aliases need no hook and no `Derive`. | Two tiers bound density (5.2.1). Counters `indexFull`, `fanout`, `contention`. Step 3 benchmarks old vs new admission at sparse, stressed and saturated load (9.2). Options if the loss is too high: more index entries, or a bounded `TryLock` retry (at most 4 tries, no blocking). Gate (Q9): sparse 0 points, stressed <= 1 point, saturated reported only (9.3). Stop condition in section 11. |
| R15 | **Clean operand near a live root.** A clean string in the same granule as a tainted root always hits the filter. Under a full index, most clean pointers hit (5.3). | `confirm` validates the root and the range overlap before `buf = nil` (3.2.1): cost only, no allocation. Measured under sparse, typical and full load (9.2). |
| R16 | **Coverage gap between commits.** | Removed: the swap from AST aspects to runtime hooks is one commit (step 5). No commit loses concat or conversion propagation. |
| R17 | **Every sink lookup pays the interior path** (critic round 5). Before step 3, a sink check was one exact probe. After step 3, `MayContain` computes two hashes and loads two filter buckets; on a filter hit, `Lookup` takes up to two `TryRLock` and scans up to two 40-entry windows (one for each tier), then validates the refs under `rootsMu.TryRLock`. Under a full index most clean pointers hit the filter (5.3), so most sink checks pay the probes. | Measured by the sink check benchmark of 9.2 (`request/lookup.go` path, before step 3 vs after, sparse / typical / full load, clean and tainted values). Gates: the `MayContain` rows of 9.3 and the HTTP overhead gate. If the full-load cost fails a gate, stop (section 11); options: a larger filter or a per-tier filter. |
| R18 | **Rune conversion over-charge** (4.5). `string(rs)` charges `sizeClass(4*len(rs)+3)`, up to approx. 4 x the real allocation. | Never an under-charge. Only on the tainted path. Step 7 reports the charged bytes; `spanOfHeap` is the fallback option. |
| R19 | **Re-adoption by one owner** (5.2.2 Extension; corrected in critic rounds 6 and 7). The old table kept one slot for each exact (owner, pointer, length, kind) key, so adoptions at different lengths kept both values tainted. The round 5 rule ("latest root wins") and the round 6 "mutable rule" (the new bytes adoption wins on `[0, cap)`) removed taint without a tracked mutation; both are withdrawn. Now a re-adoption extends the one root of this owner and allocation with the union rule, for all kinds. Remaining trade-offs: (1) on bytes that both adoptions describe, the new ranges win, so the provenance can change (taint is never lost); (2) bytes that the application rewrote without a tracked mutation keep their old taint (over-taint, accepted with Q2 and R13); (3) the merged set can reach the range cap, and the tail is dropped (`drops.ranges`); (4) a concurrent re-adoption fails with `contention` (root refused); (5) after a failed mutation, the root is a miss until `Finish`, and a re-adoption of it by the same owner is refused (`contention`). The old table gave that re-adoption a new slot; this loss occurs only after a failed mutation (itself a counted loss). | Extension in place with the union rule; one generation for all ranges of the root (5.2.2 "Mutation and extension"). Tests in 5.3 (longer then shorter, cap, union for bytes, concurrent), the race test and reader order test of 5.2.2, and negative controls (9.1 item 5). |
| R20 | **Bypass token** (variant D, 3.4.2). A stale token makes one hooked call on a `g` skip the wrapper. This occurs only when the gate changes to 0 between the outer entry and the inner entry, and then the original body panics or runs a hooked function after the gate changes back. | One missed propagation for each such event, not counted. No crash and no wrong taint. The wrapper clears the token after every inner call (3.4.2 rule 3). Gate-change test and negative control (3.4.2, 9.1 items 5 and 14). |
| R21 | **Inexact `//go:noescape` on the aliases** (3.8). `buf` flows to the result, but the alias says "no escape". | Safe only with the alias rule (R3): the alias has one call site (the wrapper) and the wrapper has one caller (the prepended code of the same function). The escape comparison (woven vs unwoven, identical lines) is a required CI check in every cell (9.4). Negative control: a direct call changes the comparison (9.1 item 5). |
| R22 | **Gate-on cost of variant D.** Two more frames (wrapper and inner call) and a second gate read on each gate-on call. Step 2 (stub bridge): heap concat with clean operands is +0.4 to +1.4 ns slower than the `defer` template; stack concat and `string(b)` are equal; `r2s-stack` is approx. 3 ns faster. Stack traces and profiles with the gate on show the wrapper frame. | The 9.3 gate-on rows stay; step 7 measures them with the real bridge. |

## 9. Validation gates

### 9.1 Tests

Section 9.4 gives the matrix for the woven tests.

1. **Hooks fire:** for each runtime function (`concatstrings`, `concatbytes`, `slicebytetostring`, `stringtoslicebyte`, `slicerunetostring`, `stringtoslicerune`), a test taints a value, runs the operation, and asserts the exact ranges. An unwoven run `t.Skip`s with a detected reason, **except** when `DD_IAST_REQUIRE_WOVEN=1`: then it fails. Every woven CI job sets this variable. `TestMain` also reads a bridge counter `hookEntries` and fails if it is 0 at the end. Thus an unwoven build cannot pass a woven job. `hookEntries` is opt-in: the bridge counts entries only after `runtimebridge.CountEntries(true)`, because a shared atomic counter on every hooked operation costs too much on a busy process (step 4). `TestMain` and every test that reads `hookEntries` turn it on first.
2. **Concat cases:** `a+b`, `a+b+c`, 6 operands, 17 operands with only operand 17 tainted, 40 operands with only operand 40 tainted, more than 16 interleaved operands of two owners (the ranges of each owner cover only its operands), more than 16 operands with one shared operand where owner A taints the two ends and owner B the middle (the ranges of A do not cover the bytes of B), more ranges than the range limit (exact and coarse: one `ranges` drop), `s += b`, generic `T ~string`, defined string types, `[]byte(a+b)`, `quote("x" + tainted)` (the v1 failure), identity (`"" + t`).
3. **Conversion cases:** each row of section 4.1, including the alias rows, and the one-byte case (not tainted, no crash). The rune mapping tests of section 4.5. The switch-off tests of section 4.4.
4. **Slice cases (store only, no hook):** `s[i:j]`, `s[i:]`, `s[:j]`, `b[i:j:k]`, one-byte windows, empty windows, a window that crosses a granule (both tiers), a 256 B and a 257 B root (tier boundary), a 64 KiB root, a window of a finished owner (must miss), the density and shared-allocation tests of 5.3 (including the extension and union tests), the rollback tests, the mutation-extension race test and the reader order test of 5.2.2, the mutation tests of 5.2.3 (including extended roots), and `TestStoreFootprint` (5.2.1).
4b. **No false negative in the pre-check** (woven build, short non-escaping concat, `string(b)`, `[]byte(s)`, `string(rs)` and `[]rune(s)` with a tainted operand):
   - forced `indexFull` and forced `fanout` (test-only hooks): the root admission fails, the source value is **not** tainted, and no lookup reports it. Thus no live root is invisible to the filter. (Step 5: the woven test forces `indexFull` with `store.ForceIndexFullForTest`, a seam on the existing store test hook, so it adds no production cost.)
   - forced shard contention in `confirm` (failed `TryRLock`): `confirm` returns `confirmUnknown`, `pre` returns `true`, the result is on the heap, and the result hook adopts it (1 allocation, taint kept). Step 4 checks `pre` and `confirm` with direct calls only (`TestRuntimePreConfirm`); the woven tests of step 5 must check the three effects: the heap is forced, the result hook adopts the result, and the result has the correct taint.
   - an allocation that already has `MaxSnapshotOwners` owners (forced fanout): `pre` and `confirm` see the taint of the admitted owners, the taint of the refused owner is not visible, and no lookup reports the refused owner (step 4: `TestRuntimePreWithFullFanout`).
   - a clean subwindow of a sparse tainted root (taint on bytes 0-3 of a 64-byte root, operand `root[10:20]`): `pre` returns `false`, 0 allocations, the result stays on the stack.
   - a tainted subwindow of the same root (`root[2:6]`): `pre` returns `true`, the result has the correct ranges.
5. **Negative controls** (each must make a test fail, then be restored): remove `stringDataOnStack`; in the wrappers, replace `buf = nil` with `_ = buf` (step 2 on variant D: 9 tests fail: forced-heap, runes, panic, unknown, recursion, stack growth, allocs); remove the `__dd_iast_in_hook` check from `__dd_iast_ok` (step 2 on variant D: `TestRecursionGuard` fails); remove the `s2sGate` check (the nested `if`) from the string-to-slice aspects (step 2 on variant D: `TestS2SGateOff` fails); make the wrappers call `runtime.<fn>` directly in place of the alias `__dd_iast_orig_<fn>` (step 2, first D build: the escape comparison fails in all 6 cells with `leaking param: buf`); remove the clear of the bypass token after the inner call (the gate-change test of 3.4.2 must fail); move the `__dd_iast_ok()` check from the prepended code back into the wrapper (the first variant D; step 2, critic round 9: the gate-on child of the system-stack test, item 15, crashes with "fatal: morestack on g0" in `__dd_iast_concatstrings`); in one alias, add an argument and remove the alias signature assertion (step 2: the build then compiles silently; with the assertion it is a compile error, 3.9 item 6); remove the filter decrement in `Finish` (filter test must detect the leak); remove `confirm` from `pre` (the clean-filter-hit allocation test must fail); remove the range-overlap scan from `confirm` (the sparse-root test of 4b must fail); make admission ignore an index failure (the forced `indexFull` test of 4b must fail); remove the rollback loop (the failure-injection test must fail); make `claimMutation` decrement `indexedRoots` (gate test (a) of 5.2.3 must fail); make the extension commit set `R.setGen = R.generation.Load()` (the mutation-extension race test of 5.2.2 must fail); read tier L before tier S (the reader order test of 5.2.2 must fail); replace the union with "latest adoption wins" (the longer-then-shorter test and the bytes union test of 5.3 must fail); remove check (b) of 5.2.2 step 5 (the concurrent cross-tier first adoption test must fail).
6b. **Independent stores:** two stores from `store.New()` plus the process store, used concurrently under `-race`. Taint in a non-process store never changes `gate`, never changes the bridge filter, and is never seen by a hook. After the process store is bound, `BindRuntimeBridge()` on a second store returns `false`, and the bridge still uses the gate, filter, `confirm` and callbacks of the first store (a tainted value of the second store is not seen by a hook; a tainted value of the first store still is). The check includes a result callback: after the refused second binding, a concat result and a `[]byte(s)` result of a first-store value are adopted in the first store, and results of a second-store value are adopted in no store (step 4: `TestRuntimeResultAfterRefusedSecondBind`).
6c. **Escape and GC** (section 3.8): all listed checks.
6. **Address reuse:** taint, finish the owner, force GC, allocate many same-size strings, assert that none is tainted.
7. **C4 regression fixtures** (woven build):
   - `len([2]string{a + b, c})` with a function-call-free `a`, `b`, `c`: no hook call, no side effect, constant result.
   - `cap([4][]byte{b[1:3]})` with `b` nil: no panic (Go does not evaluate it; today the wrapper panics).
   - `range [2]string{a + b}` with only the index used.
8. **No recursion:** a hook-entry counter stays 0 while the hook runs.
9. **Bridge dependencies:** `go list -deps ./internal/taint/runtimebridge` contains only allowed packages.
10. **Link without import:** a binary that does not import `runtimebridge` links and runs (prototype `cmd/nohook`).
11. **Link check:** section 3.9 item 4.
12. **Callback panic:** section 3.8 panic test, in the woven build.
13. **`confirm` panic and nesting:** the tests of section 3.4.1 (a panic in `confirm`; a concat and a conversion inside `confirm`).
14. **Bypass token:** the tests of section 3.4.2 (gate change for each of the 6 functions, stale-token bound, 1 000-operation sequence, nesting).
15. **System stack, `g0` (critic round 9, step 2 prototype `g0test/g0_test.go`):** user code cannot reach `g0` or `gsignal` (`os/signal` handlers run on a normal goroutine: `signal.Notify` sends on a channel; no public API runs a user function on the system stack). The test thus pulls `runtime.systemstack` with a test-only `//go:linkname` (its own package, `-ldflags=-checklinkname=0`, 9.4 item 3b). It runs itself again as a subprocess (environment variable) on a thread that is not `m0` (the main goroutine is locked to `m0` in `init`; all other threads have the same `g0` layout):
    1. Control, depth 0, gate on: the 6 hooked operations (concat, `[]byte(a+b)`, `string(b)`, `[]byte(s)`, `string(rs)`, `[]rune(s)`, all with a stack `tmpBuf`) on `g0` give 0 bridge entries; the same operations on the goroutine give 6 (woven, gate on).
    2. Calibration, gate off: binary search of the largest recursion depth `D` on `g0` (32 B frames; 48 B with `-N -l`) before the operations, where the child exits 0; `D + 1` must crash with "morestack on g0". Both sides are run again once (stable edge). Thus at `D` the free `g0` stack is less than one frame.
    3. Gate on at depth `D`: the child must exit 0, with 0 bridge entries on `g0` and 6 on the goroutine. This proves that the gate-on path adds no frame with a stack check on `g0`.
    Step 2 result: pass in all 6 darwin/arm64 cells (`D` = 16 306 default, 16 281 `-race`, 10 867 `-N -l`, the same on go1.26.6 and go1.27.1). Negative control: item 5. `gsignal` is not tested: no test-only path runs a hooked operation on it without a runtime change; `__dd_iast_ok()` rejects it with the same `gp == gp.m.curg` check. Step 5 moves this test into the real module.

### 9.2 Benchmarks

Median of 8 runs, `-benchmem`, `benchstat`, go1.26.6 and go1.27.x:

- concat n = 2, 4, 6, 16 and stack case: gate off, gate on clean, gate on tainted;
- `string(b)` and `[]byte(s)`, heap and stack, the same three modes; `[]byte(s)` also with the Q2 switch off;
- `[]rune(s)` and `string(rs)`, 8 and 1 000 runes, ASCII and multi-byte, the same three modes;
- `MayContain` and `confirm`: filter miss, filter hit clean, tainted hit, before and after the store change, each under three index loads: **sparse** (100 entries), **typical** (2 500 entries), **full** (every place of the index used, 32 768 entries). Report the measured filter hit rate next to each result;
- concat pre-check with 2 and 6 clean stack operands under the same three loads;
- sink check (`request/lookup.go` path) before step 3 (parent commit) and after, sparse, typical and full load, clean and tainted values; report the filter hit rate and the probe count (R17);
- **source-root admission, old vs new** (same workload on the old store, which is the parent commit of step 3, and on the new store): the percentage of admitted roots for `TaintString`, `TaintBytes`, `TaintSourceString`, `TaintSourceBytes` and `AdoptSourceBytes`, with refusals split by counter (`full`, `indexFull`, `fanout`, `contention`). Loads: **sparse** (100 roots), **stressed** (2 500 index entries plus 8 goroutines that publish and finish at the same time), **saturated** (roots until the quotas stop). Workloads: 1 000 short parameters; dense 256 B roots (5 tier S entries each); 257 B roots; roots whose granule keys collide in one shard (chosen addresses); retention (after 10 000 publish / finish cycles, the admitted rate does not drop). Report both rates in one table in `REPORT.md`;
- a zero-allocation check in the style of `log/slog` `TestTextHandlerAlloc`: `testing.AllocsPerRun` on a woven stdlib path with the gate on and clean data must be 0;
- `benchmarks/overhead` HTTP benchmark: control and IAST.

### 9.3 Numeric gates

| Case | Gate |
|---|---|
| Gate off, any concat or conversion | 0 extra allocations; <= +2 ns as the pooled median of hook - nohook (woven) builds over >= 8 code placements (user decision after step 5); the worst single placement is reported, not gated (variant D, darwin/arm64, step 2: <= +0.54 ns resolved median; amd64 in step 7) |
| Gate on, clean, escaping (`buf == nil`) | 0 extra allocations; <= +3 ns + 1.5 ns for each operand (user decision after step 5; was <= +3 ns) |
| Gate on, clean, stack buffer, filter miss | 0 extra allocations; <= +3 ns + 1.5 ns for each operand (user decision after step 5; was <= +8 ns) |
| Gate on, clean, stack buffer, filter hit | 0 extra allocations; <= +50 ns for each operand that hits |
| Gate on, clean, 2-operand stack concat, full index | 0 extra allocations; <= +100 ns (both operands can hit) |
| Gate on, tainted, stack buffer | exactly +1 allocation of the exact result size (<= 32 B for strings and bytes; 4 B for each rune for `[]rune`); <= +1 us (user decision after step 5; was <= +60 ns and <= 32 B) |
| `MayContain` filter hit, clean | <= 45 ns, 0 allocations |
| `MayContain` clean, mean over random pointers, sparse / typical / full | <= 4 ns / <= 10 ns / <= 45 ns, 0 allocations |
| Gate on, clean, rune conversion (`[]rune(s)`, `string(runes)`), escaping or stack | 0 extra allocations; <= +6 ns (user decision after step 5: `s2r-heap` measured +5.49 ns pooled, noisy) |
| Gate on, `[]byte(s)` / `[]rune(s)` with the Q2 switch off | 0 extra allocations; <= +2 ns (one more load) |
| Gate on, tainted rune conversion | +1 allocation only in the stack case, of the exact result size; <= +1 us (user decision after step 5; was <= +60 ns + 2 ns for each rune) |
| `MayContain` filter miss (any load) | <= 3 ns, 0 allocations |
| HTTP overhead benchmark | not worse than the Phase 6 result (+2.70 %) by more than 1 point |
| Source-root admission loss (Q9), old admitted % - new admitted %, every workload of 9.2 | sparse: 0 points; stressed: <= 1 point; saturated: no gate, reported in `REPORT.md` |

A failed gate stops the plan for user review (section 11).

**Step 5 measurement and user decision.** On darwin/arm64 (20 interleaved rounds, GOGC=off), the gate-on clean path cost +5 to +19 ns for a concat (about +1.2 ns for each operand: one filter check for each operand) and +4 to +5 ns for a conversion; the tainted stack path cost +450 to +930 ns (store adoption is about 170 ns; GOGC=off adds `madvise` time). The gate is on whenever any request of the process has taint, so under load this cost applies to every concat and conversion of the process, also in the standard library and the tracer. Romain accepted these measured costs and the three new gates above.

**Gates for each platform (user decision after CI run 36992589970).** The gates in the table above are the **local** profile (darwin/arm64, Apple M5 Pro). The GitHub runners (`ubuntu-latest`, linux/amd64, AMD EPYC 7763; `ubuntu-24.04-arm`, linux/arm64) are slower and have more noise. Romain accepted the native CI numbers. `.github/runtime-bench.py` has one table of gates (`PROFILES`) with the two profiles; `RUNTIME_BENCH_PROFILE` selects one (default `local`; the workflow sets `ci`). The report title gives the profile, and the gate column gives the limits of that profile. The CI limits are the worst value of the two runners in run 36992589970, plus a margin. The allocation rules are the same in the two profiles (0 extra allocations for clean and gate off; +1 allocation of the exact size for tainted). The admission gate stays optional on CI (no old store). The CI measure jobs are **report-only**: the job summary and the artifact have the full table and the verdict, and a FAIL or INCOMPLETE verdict gives a warning, not a failed job (`RUNTIME_BENCH_REPORT_ONLY=1`). An error of the scripts still fails the job.

| Key | Local (darwin/arm64) | CI (GitHub runners) | CI worst, run 36992589970 |
|---|---|---|---|
| off | <= +2 ns | <= +8 ns; rune rows (`r2s`, `s2r`): <= +25 ns (noisy) | +6.87 ns (`concat16-stack`, arm64); rune +21.85 ns (`r2s-heap`, amd64) |
| clean-heap, clean-stack | <= +3 ns + 1.5 ns for each operand | <= +4 ns + 2 ns for each operand (concat 2 / 4 / 6 / 16: 8 / 12 / 16 / 36 ns; conversions 6 ns) | `concat16-stack` +29.59 ns (amd64); `s2b-stack` +4.06 ns (amd64) |
| rune-clean | <= +6 ns | <= +25 ns | +20.85 ns (`r2s-heap`, amd64) |
| hit | <= +50 ns for each operand that hits | <= +100 ns for each operand that hits | 89.21 ns (arm64) |
| full2 | <= +100 ns | <= +200 ns | 175.89 ns (arm64) |
| tainted | <= +1 us | <= +1.5 us | +1167.55 ns (`concat2-stack`, amd64) |
| tainted-rune | <= +1 us | <= +1.75 us | +1438.09 ns (`s2r-stack`, arm64) |
| maycontain-hit | <= 45 ns | <= 45 ns | 4.37 ns (amd64) |
| maycontain-random | <= 4 / 10 / 45 ns | <= 5 / 10 / 45 ns | 4.13 / 4.12 / 4.17 ns (amd64) |
| maycontain-miss | <= 3 ns | <= 5 ns | 4.15 ns (amd64) |
| s2s-off | <= +2 ns | <= +5 ns | +4.08 ns (`s2r-heap`, arm64) |
| http | <= +3.70 % | <= +6.00 % | +5.17 % (arm64) |
| admission | sparse 0, stressed <= 1 point | the same, optional (no old store) | not measured |
| allocs | 0 | 0 | 8 PASS on each runner |

CI evidence (workflow `runtime-bench.yml`, local gates, verdict FAIL in the three runs):

1. Run 36834964455 (revision `b3096104`, before the gate-on optimization of section 13.4): clean `concat16-heap` +43.34 ns (amd64) / +40.50 ns (arm64); `hit` 79.44 / 88.30 ns (estimate); HTTP +8.24 % / +10.57 %.
2. Run 36910820603 (revision `0dd7db22`, after the gate-on optimization): clean `concat16-heap` +27.47 / +26.45 ns; `hit` 56.21 / 89.95 ns (woven); HTTP +9.96 % / +10.89 %, IAST +9 allocations for each request.
3. Run 36992589970 (revision `4def661f`, after the HTTP allocation fix: no allocation for each request that IAST does not analyze): HTTP +5.01 % / +5.17 %, IAST +5 allocations for each request. With the `ci` profile, the two runners PASS (section 13.2).

### 9.4 CI matrix for woven tests

New job `woven-runtime` in `.github/workflows/ci.yml`, root module only. Packages: `./iast/runtime/...`, `./internal/taint/runtimebridge/...`, `./internal/taint/store/...`, `./internal/taint/propagation/...`. Every cell sets `DD_IAST_REQUIRE_WOVEN=1`.

| Axis | Values |
|---|---|
| Go | `1.26.6` (from `go.mod`), `1.27.x` |
| Runner | `ubuntu-latest` (linux/amd64), `ubuntu-24.04-arm` (linux/arm64) |
| Mode | default; `-race`; `-gcflags=all=-N -l` |

2 x 2 x 3 = 12 cells. One more cell: Go `1.27.x`, linux/amd64, default mode, with `go tool orchestrion` replaced by `go run github.com/DataDog/orchestrion@latest` (section 6.3). Total: **13 cells**.

Each cell also runs these required checks (a failure fails the cell):

1. **Escape comparison** (section 3.8): `-gcflags=runtime=-m` and `-m=2` output of the woven and the unwoven runtime, for the `string.go` lines inside the 6 hooked functions, `concatstring2..5` and `concatbyte2..5`, sorted. The script (`.github/runtime-escape-compare.sh`, `decisions`) removes the column, the `flow:` and `from ...` explanation lines of `-m=2`, and the inlining costs, and it renumbers `autotmp_` names (step 5, deviation 3: these differ because the woven function bodies are larger; they are not escape decisions). All escape decisions (escape tags, `leaking param`, `does not escape`, `moved to heap`, derefs) must be identical. This is the guard of the alias rule (R3, R21). Step 2 reference counts for `-m`: 67 lines (default and `-race`), 58 lines (`-N -l`).
2. **Link check** (section 3.9 item 4) with `-ldflags=-checklinkname=1`. It also covers the self-linkname aliases (3.9 item 5).
3. **`blockedLinknames` grep** of the toolchain `loader.go`: no `__dd_iast` name and none of the 6 `runtime.<fn>` names of the aliases (3.9 items 2 and 5).
3b. **System-stack test** (9.1 item 15): its own test package (for example `iast/runtime/internal/g0test`), run with `-ldflags=-checklinkname=0` because of its test-only pull of `runtime.systemstack`. The other packages keep the default link check. Step 2 time: under 1 s in each darwin/arm64 cell (approx. 40 subprocess runs).
4. Optional (not a gate): on linux/amd64, default mode, the gate-off benchmark of 9.2 (unwoven vs woven, interleaved), reported in the job summary. CI runners are noisy, so step 7 keeps the gate measurement.

Budget (measured in step 2, `REPORT.md` "Timings"): the largest cold cell is 264 s (linux/amd64 under Rosetta, go1.27.1, `-race`); warm cells are 53 to 70 s; darwin/arm64 warm cells are 26 to 45 s. Most of the cold time is the woven build of the test binary (approx. 110 s) and the `withhook` link (approx. 70 s). Step 6 sets `timeout-minutes: 9` (2 x 264 s, rounded up), plus the module download time if the CI module cache is empty. Native CI runners can differ from the Rosetta times; step 6 adjusts the value to 2 x the first measured CI time. The user accepted all 13 cells (Q8). If the `ubuntu-24.04-arm` runner is not available for this repository, step 6 stops for user review (section 11); it does not remove the row.

The existing `Unit Tests` step (lines 124-149) adds `-race` to the woven `go tool orchestrion go test` run of the root module.

## 10. Implementation steps

Each step ends with `gofmt`, `go vet`, the repository linters, and all tests green. Each step is one `jj` commit. Estimates are for one engineer with an agent.

Order rule: the runtime hooks are built and tested only with the **released** Orchestrion. The released version cannot load the AST operator aspects (it has no `string-concat`, `type-conversion` or `slice-expression` join point). Thus the removal of those aspects, the repin, and the addition of **all** runtime hooks (concat, bytes conversions and rune conversions) are **one** commit (step 5). Before step 5, the AST aspects stay and work. After step 5, the runtime hooks work. No commit loses concat or conversion propagation. Step 4 prepares all code that does not need weaving, so the step 5 commit is as small as possible.

### Step 1 (done): release version

Done during critic round 1. Result: v1.13.1 (section 6.3).

### Step 2 (done): harden the prototype (early gate, no commit in this repository)

Result: **gate passed** ([`/tmp/concathook-gate/REPORT.md`](/tmp/concathook-gate/REPORT.md); summary in appendix H). One binary (Orchestrion v1.13.1, dd-trace-go v2.11.0-rc.1 GLS, declarations on `runtime.g`, guard field, full `__dd_iast_ok`, binding with a stub `confirm`, all 6 hooked functions, `s2sGate`) passed all 12 combinations (darwin/arm64 and linux/amd64 under Rosetta, go1.26.6 and go1.27.1, default / `-race` / `-N -l`): 14 woven tests, unwoven build, `-checklinkname=1` link of `withhook` and `nohook`, `blockedLinknames` grep, identical escape lines, 3 negative controls fail as expected. No stop condition of section 11 occurred. The gate-off time of the `defer` template was above the 9.3 limit of +2 ns for some conversions on arm64 (up to +4.4 ns). The performance investigation found the cause (the `defer`: closure build, indirect call to a closure with its own frame and stack check, approx. 80 B more frame) and selected **variant D** (no `defer`, wrapper with a bypass token, section 2.2): gate off <= +0.54 ns resolved median, 0 extra allocations, 6/6 correctness cells on darwin/arm64 (go1.26.6 and go1.27.1, default / `-race` / `-N -l`) with identical escape output. Critic round 9 (appendix H.6): the context check now runs before the wrapper call (a wrapper on `g0` could hit a fatal `morestack`), with 3 signature assertions for each function and a nested `s2sGate` `if`; 6/6 darwin/arm64 cells pass with the new system-stack test, and the gate-off cost stays <= +0.46 ns resolved median on go1.26.6 and go1.27.1. Not done in step 2: variant D on linux/amd64 (functional and performance), `-m=2` comparison. Steps 5, 6 and 7 do them. Measured cell times are in 9.4.

### Step 3 (5.5 days): interior-pointer index replaces the value table (one commit)

- Before any change: run the source-root admission benchmark (9.2) on the current store and keep the result as the "old" baseline.
- Add `internal/taint/store/interior.go` (section 5.2): two tiers, shared entries with <= 4 refs, all-or-nothing publication, the admission rule (a failed publication fails the root), identity-based validation. Publish after `publishRoot` in `adopt` and the five `Taint*` / `AdoptSourceBytes` functions, in place of `putWindow`; remove in `Finish`. Add `indexedRoots` with the publication order of 5.2.2, bind `operatorbridge` and `jsonbridge` to it (3.2 rule 3).
- Delete the value table and everything in the table of section 5.4 (Q4), including `Owner.Derive` and the derive helpers. Change `mutation.go` as in 5.2.3. Rewrite the 19 test files of 5.4.
- Delete `StringWindow`, `StringWindows`, `ByteWindow`, `ByteWindows`, their 39 calls in `iast/propagation/strings.go` and `bytes.go`, and the 2 internal calls. In the same commit, delete the 41 wrappers that then only call the stdlib, **with their 41 `replace-function` aspects** in `iast/propagation/orchestrion.yml`, and set `instrumentedPropagationPoints` to 84 (section 5.4 lists them). Do not delete a wrapper that calls another helper. Do not change the AST operator aspects or `operators.go` (step 5). Remove the direct calls in the test files that section 5.4 lists.
- Add `KindRunes`, `Owner.AdoptRunes` and `Owner.AdoptStringAlloc` (section 4.5); they use the same `adopt` path.
- Change `MayContain` to the filter check only, and `Lookup` to the interior path (5.2.4). Add `confirm` with the range-overlap scan. Add counters `indexFull`, `preContention`, `preStale`, `dupOwner` to `dropCounters` and `Counters` (`fanout` exists). Add the extension protocol with the union rule and the reader order (5.2.2), the relaxed mutation identity check (5.2.3), and `owner.extending`.
- Tests: section 9.1 items 4, 5 (filter, rollback, overlap, admission, mutation gate), 6. `TestStoreFootprint` (it replaces the computed estimate of 5.2.1). Race tests. `checklocks`. The existing AST operator tests and slice-wrapper tests still pass: interior lookup finds every window without `Derive`.
- **Exit:** store tests and fuzz campaigns pass; `MayContain` gates pass under the three loads; the admission loss gate of 9.3 passes (Q9: sparse 0 points, stressed <= 1 point; saturated reported only); `TestStoreFootprint` reports `Store` <= 14 040 136 B + 1 % on arm64 and amd64, or the difference is explained in the commit message.

### Step 4 (1.5 days): runtime bridge without weaving (one commit)

- Add `internal/taint/runtimebridge` (gate, binding, `concatPre`, `confirmSlow`, the conversion pre-checks, the callback entry points, counters), `Store.BindRuntimeBridge()`, and the binding call in `request.defaultManager`. Keep `operatorbridge`: the AST aspects still use it. Both gates follow the same `indexedRoots` counter (3.2 rule 3).
- Register the callbacks from `internal/taint/propagation` (adopt the result, section 3.6, including `coarseConcatHit`; `BytesToString` for `string(b)`; the bytes root of section 4.4 for `[]byte(s)`; the rune callbacks and range mapping of section 4.5 in `internal/taint/propagation/runes.go`).
- Add the Q2 switch (section 4.4): `EnvVarStringToSlicePropagationEnabled` and `StringToSlicePropagationEnabled` in `internal/config/config.go`, `runtimebridge.Options`, and `s2sGate`.
- Unit tests call the bridge functions directly (no weaving): items 2 and 3 of 9.1 as direct calls (with the rune mapping tests of 4.5), 6b, 9, the `confirm` tests of 4b, the callback panic test, and config tests for the switch (default `true`, `false` parsed, invalid value falls back to the default like the other `BoolFromEnv` settings).
- Report selection: a callback result can be shared by more than one request owner. The step 4 direct-call tests and the step 5 woven callback tests must make a shared result, send it to a sink, and check that the report has the ranges, sources, and evidence of one owner only, also when the sink context has an unowned span (a span annotation that no request scope bound).
- **Exit:** all tests pass; `go list -deps` check passes; no change in woven behavior (the AST aspects still run).

### Step 5 (3 days): swap AST aspects for runtime hooks (one commit)

Work in local stages; commit only when every stage passes. No stage is committed alone.

- 5a. Delete the YAML aspects (section 6.1), the Go code (section 6.2) and `operatorbridge`. Apply section 6.3 to all five modules and section 6.4 (except the CI matrix).
- 5b. Add `iast/runtime/orchestrion.yml` from the variant D artifact (`/tmp/concathook-gate/artifacts/perf/yaml/D-atomic.orchestrion.yml`, section 2.2): the shared declarations aspect `iast-runtime-decls` (two `runtime.g` fields, bridge declarations, `__dd_iast_ok`, the 6 aliases and wrappers) and the concat aspects. Change `links:` to `github.com/DataDog/dd-iast-go/internal/taint/runtimebridge` and `github.com/DataDog/dd-iast-go/internal/taint/propagation` (3.2 rule 6, link rule). Add a **runtime-only link fixture**: a test binary whose source imports nothing from dd-iast-go (all dd-iast-go code comes from weaving, with only the runtime aspect and one source aspect that does not import `propagation`, for example `iast/net/http`). The test checks that the 6 callbacks are registered, and that a tainted concat result is tainted (not only forced to the heap). Keep the context check before the wrapper call (2.2, 3.3) and the 3 signature assertions for each function (3.9 item 6); both are in the artifact since critic round 9. Move the system-stack test (9.1 item 15) into the module.
- 5c. Add the `slicebytetostring`, `stringtoslicebyte`, `slicerunetostring` and `stringtoslicerune` aspects (sections 4.2, 4.3, 4.5), with the `s2sGate` check in a nested `if` of the two string-to-slice aspects (4.3).
- 5d. Move the woven operator tests to `iast/runtime` (section 6.2). Add the C4 fixtures (section 9.1 item 7), the `wrap-expression` audit test (section 7), the woven rune and switch-off tests (sections 4.4, 4.5), and the bypass token tests (3.4.2, 9.1 item 14). Add the woven report selection test of step 4 (a shared callback result, one owner in the report, also with an unowned context span), and the woven variants of the coarse (> 16 operands) two-owner report tests of step 4 (`TestReportCoarseRuntimeResultMasksForeignOperands`, `TestReportCoarseRuntimeResultMasksForeignBytesInSharedOperand`). Add `DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED` (default `true`, section 4.4) to the configuration table of `README.md`: the switch has an effect only after step 5, so step 4 does not document it. Delete `operatorActive` and update `TestStoreFootprint` (5.2.1).
- 5e. Run the escape comparison with `-m` and `-m=2` (3.8), the link checks (3.9), and the negative controls of variant D (9.1 item 5: `_ = buf`, guard check, `s2sGate`, direct call in place of the alias, token clear after the inner call). Run the woven tests of variant D on linux/amd64 (container or CI branch run), default and `-race` (R8).
- **Exit:** the `grep` in section 6.1 prints nothing; `go list -m github.com/DataDog/orchestrion` prints `v1.13.1` in all five modules; section 9.1 items 1-4b, 6b, 6c, 7-14 pass on go1.26.6 and go1.27.1, default and `-race`, on darwin/arm64 and linux/amd64; the escape lines are identical; concat and conversion benchmark gates pass on darwin/arm64.

### Step 6 (1 day): CI matrix (one commit)

- Build cache (found in step 5): Orchestrion v1.13.1 adds dependency archives (for example `iobridge` for std `io`) that the Go action ID of the dependent package does not include, and its tool ID does not include the build flags. Two woven runs that differ only in coverage flags or in per-package `-gcflags` must not share one GOCACHE: give each woven mode its own GOCACHE (`$RUNNER_TEMP/gocache-<mode>`) or put the mode in the cache key. Also pass `-gcflags` only once: Orchestrion keeps only the last `-gcflags` value (`internal/goflags/flags.go`), so a second flag gives a fingerprint mismatch.

- Add the `woven-runtime` job (section 9.4, all 13 cells) with the timeouts measured in step 2 (`timeout-minutes: 9`, then 2 x the first CI time) and the required checks of 9.4 (escape comparison, link check, `blockedLinknames` grep). Optional: the gate-off benchmark report on linux/amd64 (9.4 item 4). Check that `ubuntu-24.04-arm` is available for this repository; if not, stop (section 11).
- **Exit:** CI is green on the branch; system-tests pass.

### Step 7 (0.75 day): measure and report

- Run section 9.2 on darwin/arm64 and on native linux/amd64 (not Rosetta). The gate-off rows of variant D on amd64 are measured here for the first time (R8). Use the method of `_docs/plans/runtime-operator-hooks-step5-results.md` (step 5): compare woven builds with and without the hooks (hook - nohook, not woven - unwoven, because the woven binary also links the tracer and its GC cost is not a hook cost), >= 8 code placements, interleaved runs, pooled median against the gate, worst single placement reported. Report the woven - unwoven difference too, as a separate customer-visible cost.
- Fill the result table in a new "Implementation result" section of this plan.
- **Exit:** every gate in section 9.3 passes, or the plan stops for review.

Total remaining: approx. 11.75 working days (steps 3 to 7: 5.5 + 1.5 + 3 + 1 + 0.75). Step 2 (1.75 days) is done. Step 2 changes: step 5 +0.25 day (variant D template, bypass token tests, signature assertions, amd64 run), step 7 +0.25 day (native amd64 measurement). Before step 2, the total was approx. 13 working days (1.75 + 5.5 + 1.5 + 2.75 + 1 + 0.5). Compared with the earlier 10 days: +1 day for the value-table removal (Q4), +0.75 day for the rune hooks (Q6), +0.25 day for the Q2 switch, +0.25 day for the window-helper removal, +0.5 day for the replace protocol and the removal of 41 wrappers with their aspects (critic round 5), +0.25 day for the merge rule and its tests (critic round 6). Critic round 7 replaces the round 6 merge with a simpler in-place extension (no `next`, no redirect, no reader rule) and adds two race tests; the estimate does not change.

## 11. Stop conditions

Stop for user review if any of these occur:

- a hook adds an allocation or a new escape with the gate off;
- the woven runtime fails to build on a supported Go version or architecture;
- the GLS aspect and these aspects conflict;
- the recursion guard or the bypass token rules (3.4) cannot be proven;
- a numeric gate in section 9.3 fails;
- the source-root admission loss (old vs new, 9.2) is more than the Q9 gate (sparse 0 points, stressed 1 point; 9.3);
- the `ubuntu-24.04-arm` runner is not available (Q8 requires all 13 cells);
- a woven combination of variant D fails (step 5 on linux/amd64, or a step 6 CI cell), or the escape comparison of variant D is not identical;
- the gate-off cost of variant D on native amd64 (step 7) is above +2 ns (9.3);
- Orchestrion v1.13.1 cannot carry `imports:` in `runtime`, or two `struct-definition: runtime.g` aspects (GLS and ours) in one build (both proven in step 2, appendix H);
- `confirm` cannot meet 0 allocations, or the rollback protocol (5.2.2) cannot be proven free of leaks under `-race`;
- any test of section 9.1 item 4b shows a tainted operand that `pre` reports as clean.

## 12. User decisions

Q1 (Orchestrion target) is closed: dd-trace-go v2.11.0-rc.1 has no Orchestrion requirement, so the target is v1.13.1 (section 6.3). The earlier Q7 (coverage gap between commits) is closed: the swap is one commit (section 10, step 5).

- **Q2.** `[]byte(s)` propagation is on by default; `DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED=false` turns it off (and `[]rune(s)`). Applied: 3.2 rule 6, 4.3, 4.4, 4.5, R13, 9.1, 9.2, 9.3, steps 2, 4, 5.
- **Q3.** Supported: go1.26.x and go1.27.x only; newer toolchains keep the hooks off. Applied: Status, 3.10, 9.4.
- **Q4.** Remove the exact value table in this change (step 3); every lookup uses the interior index. Applied: 1.4, 3.2 rule 3, 5.2.1-5.2.4, 5.3, 5.4, R14, step 3.
- **Q5.** +1.88 MiB for the index and filter is accepted; the net change with Q4 is +0.62 MiB (computed, `TestStoreFootprint` measures it). Applied: 5.2.1, 5.3, step 3 exit.
- **Q6.** Add `slicerunetostring` and `stringtoslicerune` hooks with exact rune-boundary range mapping; `string(r)` and one-byte results stay documented misses. Applied: 3.2.1 sketch, 3.8, 4.1, 4.5, 7, R3, 9.1-9.3, steps 2-5.
- **Q7.** The 4-owner limit for one allocation (`fanout`) is accepted. The limit counts distinct owners; repeated adoptions by one owner use one ref (critic round 5), and they extend one root in place (critic round 7). Applied: 5.2.1, 5.2.2 (Extension).
- **Q8.** The full 13-cell CI matrix is required; a missing arm64 runner stops the plan. Applied: 9.4, step 6, section 11.
- **Go 1.28+.** On an unsupported newer toolchain the hooks stay off silently: no build error, no warning, only the `unsupportedGo` counter. Applied: 3.10.
- **Window helpers.** Delete the 4 empty window helpers and their 39 call sites in this change (step 3). Applied: 5.4, 7, step 3.
- **Signature assertions.** Accepted: the woven runtime asserts the signature of each hooked function at compile time. A signature change then fails the build, also on go1.28+ (this is the one exception to "Go 1.28+: hooks off silently"). Applied: 3.9 item 6, 3.10, R3, step 5.
- **Q9.** Loss budget is a gate: sparse 0 points, stressed <= 1 point, saturated reported only. Applied: R14, 9.3, step 3 exit, section 11.

## 13. Implementation result

Step 7. The measurement is automatic: `.github/runtime-bench.sh` (build, run, report) and `.github/runtime-bench.py` (pooled medians, bootstrap intervals, the 9.3 gates, verdict). The CI workflow `.github/workflows/runtime-bench.yml` runs the same script on linux. The method is the method of step 5 ([runtime-operator-hooks-step5-results.md](./runtime-operator-hooks-step5-results.md)):

- hook - nohook: two woven test binaries of `./iast/runtime`; nohook has no prepend-statements aspect (the `runtime.g` declarations stay);
- 8 code placements: a padding function with k = 0, 1, 3, 5, 7, 9, 11, 13 stores in the injected runtime declarations (k = 0 is the repository code), one GOCACHE for each build;
- interleaved rounds: each round runs the 16 woven binaries and the unwoven binary once, and the order rotates each round;
- gate value: the pooled median of hook - nohook over all the placements, with a 95 % bootstrap interval; the worst single placement is reported, not gated;
- woven - unwoven (pooled hook - plain) is reported in a separate column: it is the cost that a customer sees (it also has the GC cost of the linked tracer), not a gate.

In the step 7 run (sections 13.1 to 13.3), two gates (`hit`, `full2`) are **estimates**, because no woven benchmark had a clean filter hit. Section 13.4 replaces these estimates with the woven case `BenchmarkRuntimeCleanHit`. `BenchmarkRuntimePre` (`internal/taint/store/runtime_bridge_bench_test.go`, new in step 7) calls the bridge pre-check directly on the bound store (filter check, `Confirm`, panic guard). The gate value is this time plus the hook entry (the clean `b2s-stack` or `concat2-stack` hook - nohook, which also has one filter-miss pre-check). This sum is not a woven measurement of the filter-hit path. `concat2-clean-hit` uses the same clean neighbor for the two operands (one pointer, one shard). `BenchmarkMayContain` has a new `clean-miss` case (only keys that the filter rejects) at the three loads.

The report is PASS only when every gate has complete data: the 41 runtime cases (43 after section 13.4) in 8 placements with the same number of hook and nohook runs (>= 8), >= 8 runs of each store row that a gate uses and of each admission row, and >= 10 HTTP runs for each side. Missing data gives INCOMPLETE, unless the gate key is in `RUNTIME_BENCH_OPTIONAL`.

### 13.1 darwin/arm64

Apple M5 Pro (18 cores), go1.26.6, Orchestrion v1.13.1, revision `7b2a6d48` (plus the step 7 files). Raw data and `report.md`: `/tmp/perf7` (builds and run 1), `/tmp/perf7-heap` (re-measure), `/tmp/perf7-http20`, `/tmp/perf7-run2` (run 2).

Commands (repository root):

```console
export GOTOOLCHAIN=go1.26.6 GOCACHE=/tmp/perf7-gocache-plain RUNTIME_BENCH_OUT=/tmp/perf7
.github/runtime-bench.sh build                    # 16 woven builds, 4 at a time: 11 min
.github/runtime-bench.sh plain
.github/runtime-bench.sh run                      # 10 rounds x 17 binaries, 300ms: 42 to 48 min
RUNTIME_BENCH_OLD_TREE=/tmp/step3-base .github/runtime-bench.sh store   # 8 rounds, old and new store: 2 min
RUNTIME_BENCH_HTTP_COUNT=20 .github/runtime-bench.sh http   # sampled out: 1 min
.github/runtime-bench.sh report
```

`/tmp/step3-base` is the old store of step 3 (the parent commit of step 3 with the benchmark files, `/tmp/step3-report.md`).

Three measurements:

1. **Run 1** (18:41 to 19:30): other builds ran on the machine (load average 5 to 81). Result: 3 heap conversion rows and the HTTP row (n=10) failed, with wide intervals: gate off `r2s-heap` +2.95 ns [-0.21, +6.82]; clean `s2b-heap` +4.88 ns [+4.49, +5.52] (gate +4.5); clean `s2r-heap` +6.24 ns [+3.47, +7.53] (gate +6); HTTP +7.12 % (benchstat ±97 % / ±771 %, p=0.315).
2. **Re-measure** of the 8 heap conversion rows (20 rounds, 160 runs for each side, same load): all pass; clean `s2b-heap` +4.36 ns [+4.03, +4.65]. HTTP n=20: +0.60 % (±87 %).
3. **Run 2** (20:26 to 21:09, the same 17 binaries, quiet machine: load average 2 to 5): new runtime rounds (with `TestAllocs`) and a new HTTP run (n=20). The store, bridge pre-check and admission benchmarks are not measured again in run 2: the report uses their run of 20:22 to 20:24 (after the new store benchmarks were added; load average 4). With these inputs, **all gates pass**. This combined result is the step 7 result on darwin/arm64. The table below uses it.

| Key | Case (9.3) | Gate | Run 2 | Result |
|---|---|---|---|---|
| off | Gate off, any concat or conversion | 0 extra allocations; <= +2 ns pooled | 0 extra allocations; worst `concat2-stack` +0.43 ns; `concat16-stack` +0.13 ns (worst placement +2.96 ns, k=0) | PASS |
| clean-heap | Gate on, clean, escaping (`buf == nil`) | 0 extra allocations; <= +3 ns + 1.5 ns for each operand | worst margin `s2b-heap` +4.22 ns [+4.16, +4.33] (gate +4.5); concat 2 / 4 / 6 / 16: +5.31 / +6.43 / +8.09 / +14.66 ns | PASS |
| clean-stack | Gate on, clean, stack buffer, filter miss | 0 extra allocations; <= +3 ns + 1.5 ns for each operand | worst margin `s2b-stack` +3.99 ns; concat 2 / 4 / 6 / 16: +4.85 / +5.90 / +7.21 / +15.13 ns | PASS |
| hit | Gate on, clean, stack buffer, filter hit | 0 extra allocations; <= +50 ns for each operand that hits | estimate: `RuntimePre/full/one-clean-hit` 41.51 ns + hook entry 3.61 ns = 45.12 ns (sparse 25.35 ns, typical 24.73 ns) | PASS (estimate) |
| full2 | Gate on, clean, 2-operand stack concat, full index | 0 extra allocations; <= +100 ns | estimate: `RuntimePre/full/concat2-clean-hit` (both operands hit) 79.57 ns + hook entry 4.85 ns = 84.42 ns | PASS (estimate) |
| tainted | Gate on, tainted, stack buffer | +1 allocation of the exact result size; <= +1 us | +1 allocation, 16 B; concat2 +620.06 ns, `b2s` +415.44 ns, `s2b` +418.40 ns | PASS |
| maycontain-hit | `MayContain` filter hit, clean | <= 45 ns, 0 allocations | worst 1.65 ns | PASS |
| maycontain-random | `MayContain` clean, random pointers, sparse / typical / full | <= 4 / 10 / 45 ns, 0 allocations | 1.69 / 1.72 / 1.92 ns (filter hit rate 0.5 / 11.1 / 92.3 %) | PASS |
| rune-clean | Gate on, clean, rune conversion, escaping or stack | 0 extra allocations; <= +6 ns | worst `s2r-stack` +3.37 ns; `s2r-heap` +3.37 ns [+0.70, +5.10] | PASS |
| s2s-off | Gate on, `[]byte(s)` / `[]rune(s)`, Q2 switch off | 0 extra allocations; <= +2 ns | worst `s2b-stack` +0.23 ns | PASS |
| tainted-rune | Gate on, tainted rune conversion | +1 allocation of the exact result size; <= +1 us | `r2s` +815.34 ns, 16 B; `s2r` +833.12 ns, 48 B (11 runes x 4 B = 44 B, size class 48 B) | PASS |
| maycontain-miss | `MayContain` filter miss (any load) | <= 3 ns, 0 allocations | `clean-miss` sparse / typical / full: 1.68 / 1.69 / 1.66 ns | PASS |
| http | HTTP overhead benchmark (sampled out) | <= +3.70 % (Phase 6 +2.70 % + 1 point) | n=20: control 54.38 us, IAST 55.95 us, +2.89 % (±1 %, p=0.000) | PASS |
| admission | Source-root admission loss (Q9), old - new | sparse: 0 points; stressed: <= 1 point | sparse: 0.00 points in all 17 rows; stressed: worst +0.10 points (`dense256/stressed/TaintBytes`), best -1.15; saturated (reported): -46.36 to +87.20 points, as in step 3 (`collide/saturated` 12.80 %: the index refuses colliding granules) | PASS |
| allocs | Zero allocations (`TestAllocs`, woven stdlib path, gate on, clean) | 0 | PASS in all 8 hook binaries | PASS |

The smallest margins: clean `s2b-heap` (0.28 ns; step 5: +4.45 ns), `hit` (4.9 ns), clean `concat2-heap` (0.69 ns), tainted `s2r-stack` (167 ns). A loaded machine moves the heap rows over their gates (run 1).

Run 2, all runtime cases (hook - nohook, ns; "Allocs" and "B" are the median extra allocations and bytes):

| Case | Pooled [95 % CI] | Worst placement (k) | Range | Allocs | B | Woven - unwoven | Gate | Result |
|---|---:|---:|---:|---:|---:|---:|---|---|
| RuntimeOff/concat2-heap | **+0.38** [+0.19, +0.59] | +0.98 (11) | +0.25..+0.98 | +0 | +0 | +2.30 | <= +2 ns | PASS |
| RuntimeOff/concat4-heap | **+0.30** [+0.17, +0.46] | +1.03 (0) | +0.05..+1.03 | +0 | +0 | +1.70 | <= +2 ns | PASS |
| RuntimeOff/concat6-heap | **+0.35** [+0.11, +0.50] | +1.27 (0) | -0.09..+1.27 | +0 | +0 | +1.64 | <= +2 ns | PASS |
| RuntimeOff/concat16-heap | **-1.42** [-1.85, -1.04] | +2.61 (0) | -2.54..+2.61 | +0 | +0 | -0.36 | <= +2 ns | PASS |
| RuntimeOff/concat2-stack | **+0.43** [+0.31, +0.51] | +0.91 (11) | +0.19..+0.91 | +0 | +0 | +0.29 | <= +2 ns | PASS |
| RuntimeOff/concat4-stack | **+0.31** [+0.24, +0.47] | +1.27 (0) | +0.15..+1.27 | +0 | +0 | +0.41 | <= +2 ns | PASS |
| RuntimeOff/concat6-stack | **+0.42** [+0.31, +0.59] | +1.79 (0) | +0.11..+1.79 | +0 | +0 | +0.39 | <= +2 ns | PASS |
| RuntimeOff/concat16-stack | **+0.13** [-0.54, +0.51] | +2.96 (0) | -2.03..+2.96 | +0 | +0 | -0.23 | <= +2 ns | PASS |
| RuntimeOff/b2s-heap | **+0.10** [+0.05, +0.17] | +0.26 (0) | +0.02..+0.26 | +0 | +0 | +2.00 | <= +2 ns | PASS |
| RuntimeOff/b2s-stack | **+0.18** [+0.15, +0.21] | +0.22 (13) | +0.11..+0.22 | +0 | +0 | +0.19 | <= +2 ns | PASS |
| RuntimeOff/s2b-heap | **+0.08** [+0.00, +0.15] | +0.20 (11) | -0.01..+0.20 | +0 | +0 | +1.93 | <= +2 ns | PASS |
| RuntimeOff/s2b-stack | **+0.24** [+0.23, +0.24] | +0.24 (11) | +0.21..+0.24 | +0 | +0 | +0.24 | <= +2 ns | PASS |
| RuntimeOff/r2s-heap | **-1.70** [-2.07, -1.07] | +0.12 (0) | -2.70..+0.12 | +0 | +0 | +0.01 | <= +2 ns | PASS |
| RuntimeOff/r2s-stack | **-0.49** [-0.73, -0.08] | +0.25 (13) | -1.11..+0.25 | +0 | +0 | +0.10 | <= +2 ns | PASS |
| RuntimeOff/s2r-heap | **-0.37** [-1.72, +0.63] | +0.00 (11) | -2.09..+0.00 | +0 | +0 | +4.23 | <= +2 ns | PASS |
| RuntimeOff/s2r-stack | **-0.43** [-0.94, +0.23] | +0.33 (5) | -0.90..+0.33 | +0 | +0 | -0.22 | <= +2 ns | PASS |
| RuntimeClean/concat2-heap | **+5.31** [+5.10, +5.48] | +5.62 (11) | +4.95..+5.62 | +0 | +0 | +5.34 | <= +6 ns | PASS |
| RuntimeClean/concat4-heap | **+6.43** [+6.27, +6.68] | +7.64 (0) | +6.02..+7.64 | +0 | +0 | +6.54 | <= +9 ns | PASS |
| RuntimeClean/concat6-heap | **+8.09** [+7.77, +8.33] | +9.23 (0) | +7.49..+9.23 | +0 | +0 | +8.21 | <= +12 ns | PASS |
| RuntimeClean/concat16-heap | **+14.66** [+14.34, +15.03] | +17.84 (0) | +13.53..+17.84 | +0 | +0 | +14.30 | <= +27 ns | PASS |
| RuntimeClean/concat2-stack | **+4.85** [+4.71, +4.99] | +5.19 (0) | +4.49..+5.19 | +0 | +0 | +4.83 | <= +6 ns | PASS |
| RuntimeClean/concat4-stack | **+5.90** [+5.80, +6.08] | +6.82 (0) | +5.64..+6.82 | +0 | +0 | +5.91 | <= +9 ns | PASS |
| RuntimeClean/concat6-stack | **+7.21** [+7.06, +7.39] | +8.39 (0) | +6.60..+8.39 | +0 | +0 | +7.31 | <= +12 ns | PASS |
| RuntimeClean/concat16-stack | **+15.13** [+14.73, +15.76] | +18.78 (0) | +13.98..+18.78 | +0 | +0 | +15.49 | <= +27 ns | PASS |
| RuntimeClean/b2s-heap | **+3.82** [+3.74, +3.90] | +4.28 (1) | +3.65..+4.28 | +0 | +0 | +3.91 | <= +4.5 ns | PASS |
| RuntimeClean/b2s-stack | **+3.61** [+3.58, +3.62] | +3.67 (7) | +3.56..+3.67 | +0 | +0 | +3.60 | <= +4.5 ns | PASS |
| RuntimeClean/s2b-heap | **+4.22** [+4.16, +4.33] | +4.51 (11) | +4.04..+4.51 | +0 | +0 | +4.44 | <= +4.5 ns | PASS |
| RuntimeClean/s2b-stack | **+3.99** [+3.98, +4.02] | +4.04 (9) | +3.96..+4.04 | +0 | +0 | +3.99 | <= +4.5 ns | PASS |
| RuntimeClean/r2s-heap | **+1.92** [+1.61, +2.41] | +4.12 (0) | +0.83..+4.12 | +0 | +0 | +2.97 | <= +6 ns | PASS |
| RuntimeClean/r2s-stack | **+2.79** [+2.54, +3.26] | +3.40 (13) | +2.33..+3.40 | +0 | +0 | +3.41 | <= +6 ns | PASS |
| RuntimeClean/s2r-heap | **+3.37** [+0.70, +5.10] | +5.66 (13) | -0.18..+5.66 | +0 | +0 | +1.82 | <= +6 ns | PASS |
| RuntimeClean/s2r-stack | **+3.37** [+2.85, +3.89] | +4.08 (7) | +2.78..+4.08 | +0 | +0 | +3.31 | <= +6 ns | PASS |
| RuntimeS2SOff/s2b-heap | **+0.12** [+0.08, +0.18] | +0.23 (11) | -0.04..+0.23 | +0 | +0 | +0.20 | <= +2 ns | PASS |
| RuntimeS2SOff/s2b-stack | **+0.23** [+0.23, +0.24] | +0.24 (7) | +0.22..+0.24 | +0 | +0 | +0.24 | <= +2 ns | PASS |
| RuntimeS2SOff/s2r-heap | **-2.92** [-4.44, -0.68] | +1.36 (1) | -4.53..+1.36 | +0 | +0 | -1.88 | <= +2 ns | PASS |
| RuntimeS2SOff/s2r-stack | **-0.38** [-0.88, +0.14] | +0.15 (5) | -1.62..+0.15 | +0 | +0 | -0.64 | <= +2 ns | PASS |
| RuntimeTainted/concat2-stack | **+620.06** [+618.26, +624.93] | +625.90 (11) | +614.24..+625.90 | +1 | +16 | +619.98 | <= +1 us, +1 alloc | PASS |
| RuntimeTainted/b2s-stack | **+415.44** [+411.86, +417.27] | +419.98 (1) | +408.34..+419.98 | +1 | +16 | +415.43 | <= +1 us, +1 alloc | PASS |
| RuntimeTainted/s2b-stack | **+418.40** [+415.85, +420.45] | +422.15 (3) | +414.50..+422.15 | +1 | +16 | +418.40 | <= +1 us, +1 alloc | PASS |
| RuntimeTainted/r2s-stack | **+815.34** [+812.52, +821.35] | +829.35 (13) | +811.00..+829.35 | +1 | +16 | +815.84 | <= +1 us, +1 alloc | PASS |
| RuntimeTainted/s2r-stack | **+833.12** [+828.72, +834.88] | +838.00 (5) | +827.01..+838.00 | +1 | +48 | +833.17 | <= +1 us, +1 alloc | PASS |

### 13.2 linux/amd64 (CI)

Filled in after CI run 36992589970: see 13.2.1 (also linux/arm64). Workflow `.github/workflows/runtime-bench.yml` ("Runtime benchmarks"). Trigger: push a branch that matches `bench/**` (the step 7 commit has the bookmark `bench/runtime-hooks-step7`). A manual start (`workflow_dispatch`) is possible only after the workflow file is on the default branch. The job summary of "Measure (ubuntu-latest)" has the 9.3 table, and the artifact `runtime-bench-results-ubuntu-latest` has the raw files and the benchstat output. The same run also gives linux/arm64 ("Measure (ubuntu-24.04-arm)").

Differences from the darwin/arm64 run, so that the measure job fits in 60 minutes (measured locally: one run of all the runtime benchmarks is 8.4 s at 100ms, 21 s at 300ms):

- `-test.benchtime=100ms` in place of 300ms. The 8 placements and the 10 rounds do not change (80 runs for each side and case). Budget: 17 binaries x 10 rounds x approx. 9 s = approx. 26 min, plus approx. 1 min for the store benchmarks. The budgets come from local times: check them after the first CI run (a runner can have 2 vCPUs).
- The 16 woven builds of one runner run in 8 parallel build jobs (one for each placement); the measure job downloads the 16 binaries and runs all the rounds on one machine.
- The HTTP benchmark runs in its own job, on another runner with the same label.
- No old store: the source-root admission gate is optional (`RUNTIME_BENCH_OPTIONAL=admission`). It is a property of the store algorithm, measured on darwin/arm64 above and in step 3. The new-store admitted percentages are reported. All the other gates must have data.
- Only the Go version of `go.mod` (go1.26.6).

#### 13.2.1 CI results, run 36992589970

Revision `4def661f`, go1.26.6, 8 placements, 10 rounds, 100ms (80 runs for each side and case). Runners: `ubuntu-latest` (linux/amd64, AMD EPYC 7763) and `ubuntu-24.04-arm` (linux/arm64). With the local gates, the verdict is FAIL on the two runners. With the `ci` gates (section 9.3, user decision), the verdict is **PASS** on the two runners (the same artifacts, report again with `RUNTIME_BENCH_PROFILE=ci`). The key rows (pooled hook - nohook, ns; store rows: median ns):

| Key | Row | linux/amd64 | linux/arm64 | CI gate |
|---|---|---:|---:|---|
| off | worst non-rune row | -0.62 (`concat16-stack`); +0.62 (`s2b-stack`) | +6.87 (`concat16-stack`) | <= +8 |
| off | worst rune row | +21.85 (`r2s-heap`, CI [-5.35, +27.55]) | +3.50 (`s2r-heap`) | <= +25 |
| clean-heap | `concat16-heap` | +26.85 | +25.75 | <= +36 |
| clean-stack | `concat16-stack` | +29.59 | +27.91 | <= +36 |
| clean-stack | `s2b-stack` | +4.06 | +1.74 | <= +6 |
| rune-clean | worst | +20.85 (`r2s-heap`) | +8.55 (`s2r-heap`) | <= +25 |
| s2s-off | `s2r-heap` | +0.54 | +4.08 | <= +5 |
| hit | woven `CleanHit/s2b-stack` + load | 60.07 + 11.84 = 71.91 | 73.23 + 15.98 = 89.21 | <= 100 |
| full2 | woven `CleanHit/concat2-stack` + load | 132.40 + 28.11 = 160.51 | 144.45 + 31.44 = 175.89 | <= 200 |
| tainted | `concat2-stack` | +1167.55 (+1, 16 B) | +1115.90 (+1, 16 B) | <= +1.5 us |
| tainted-rune | `s2r-stack` | +1347.12 (+1, 48 B) | +1438.09 (+1, 48 B) | <= +1.75 us |
| maycontain-hit | worst `clean-neighbor` | 4.37 | 3.88 | <= 45 |
| maycontain-random | sparse / typical / full | 4.13 / 4.12 / 4.17 | 4.02 / 4.03 / 4.14 | <= 5 / 10 / 45 |
| maycontain-miss | worst | 4.15 | 4.06 | <= 5 |
| http | sampled out, n=10 | +5.01 % (145.15 / 152.43 us) | +5.17 % (91.73 / 96.47 us) | <= +6.00 % |
| allocs | `TestAllocs` | 8 PASS | 8 PASS | 0 |

The rune rows (`r2s`, `s2r`) have the most noise on CI: the placement range of `RuntimeOff/r2s-heap` on amd64 is -8.90 to +30.35 ns, and on arm64 the same row is -8.90 ns pooled. The gate-off instructions do not change (section 13.4).

**Step 7: done**, with the gates of section 9.3 for each platform: darwin/arm64 PASS with the local gates (section 13.1, and 13.4 after the gate-on optimization); linux/amd64 and linux/arm64 PASS with the ci gates (run 36992589970). The CI measure jobs are report-only (section 9.3).

### 13.3 Not measured, and corrections

- go1.27.x (section 9.2 asks for go1.26.6 and go1.27.x): not measured in step 7. Step 5 measured the gate-off rows on go1.27.1 (pooled, all pass).
- Section 9.2 cases that `iast/runtime/bench_test.go` does not have: tainted concat with 4, 6 and 16 operands, and a tainted heap concat; rune conversions with 8 and 1 000 runes, and multi-byte text (the benchmarks use 11 and 40 ASCII runes). The 9.3 gates above are proven only for the measured cases. To add them: new cases in `bench_test.go`, then a new build and run (approx. 1 hour).
- In step 7, no woven benchmark had a clean filter hit, thus the `hit` and `full2` gates are estimates (see above; `hit` is 4.9 ns below its gate). Done in section 13.4. To measure them: woven one-hit and two-hit stack cases at the full load in `bench_test.go` (with two neighbors in different granules), then a new build and run.
- Section 9.2 says "median of 8 runs". After step 5, the gate rows use the pooled method above (80 runs for each side); section 9.2 is not changed.
- Correction outside the plan: the comment of `BenchmarkRuntimeTainted` (`iast/runtime/bench_test.go`) gave the old gate (<= +60 ns); it now gives <= +1 us (user decision after step 5). No factual error was found in the other sections of this plan.

### 13.4 Gate-on optimization (after step 7)

Cause: the first CI run of the step 7 workflow (run 36834964455, linux/amd64) gave gate-on clean costs of approx. 2 times the gates (for example `concat2` +10 ns, gate +6 ns; `b2s` / `s2b` +7 to +9 ns, gate +4.5 ns; filter-hit pre-check 79 to 88 ns, gate 50 ns). The gate-off rows passed. This change makes the gate-on path less expensive. The gate-off path does not change: the same 4 instructions after the prologue, and the same prologue and frame as the nohook build (disassembly of the 6 functions; the escape comparison is identical in the 3 modes).

Changes:

1. **Filter check before the wrapper.** After `__dd_iast_ok()`, the prepended code calls a bridge filter check (`__dd_iast_rt.concat_hit`, `bytes_hit`, `str_hit`, `str_hit_runes`; `internal/taint/runtimebridge/hooks.go`). It reads the interior filter of each input. When no input can be tainted (the clean path), the original body runs directly: no wrapper, no pre-check, no bypass token, no inner entry and no result hook. The pre-check and the result hook read the same filter, so they could do nothing for these inputs. The filter check returns its arguments unchanged, and the prepended code stores them in the arguments: thus no argument is live across the call, and the compiler adds no spill at the entry (the gate-off path). In an optimized build, each filter check is a leaf function (no frame, no lock, no allocation). Exception: in `slicerunetostring`, the call in the prepended code makes the frame larger than the small-frame limit, so the wrapper calls `__dd_iast_rt.runes_hit` first, and calls the result hook only after a hit. Woven tests: each tainted operation now enters the bridge 3 times (filter check, pre-check, result hook).
2. **Less expensive filter hash** (`filter.go`, `filterHit`): one multiply-add for each tier (`k*m + m` in place of `(k+1)*m`), the multiplier in a register for a loop of operands, the two bucket loads with one branch (the tier S load stays first in the program order, section 5.2.4). On a 64-bit platform, the tier L key does not set `TierLBit` (bit 63 does not change bits 37 to 51 of the hash); on a 32-bit platform, it sets it (`tierLHashBit`).
3. **Slot tags in the index** (`internal/taint/store/interior.go`): one tag byte for each slot (hash bits 29 to 36, never 0; 0 is an empty slot), in one word for each bucket (32 KiB for the store). Only a writer that holds the shard write lock changes a tag, together with the entry. `probe` reads only the slots whose tag can match (a SWAR compare of 8 tags). `Confirm` of a clean filter hit is approx. 2 times faster (`RuntimePre/sparse/one-clean-hit` 24.66 to 13.29 ns; `full` 39.78 to 18.01 ns).
4. **Measured clean filter hit**: the new woven benchmark `BenchmarkRuntimeCleanHit` (`iast/runtime/bench_test.go`) replaces the estimates of the `hit` and `full2` gates (section 13). Each operand is in the granule of a different root, so it is a filter hit, and `Confirm` gives clean. Before the measurement, the benchmark checks that a hooked binary calls `Confirm` once for each operand and that the cases do not allocate. The gate value is the woven case (hook - nohook, sparse load) plus the extra cost of the pre-check at the worst load (`RuntimePre/<load>/... - RuntimePre/sparse/...`). `concat2-clean-hit` of `BenchmarkRuntimePre` now uses two neighbors in different granules (two roots).

Not used, with the reason (not measured separately): one load for both tiers (the tier S and tier L buckets of a pointer are not adjacent, and the reader order of 5.2.4 needs two loads); a filter check that does not return its arguments, in the prepended code (the arguments are then live across the call, and the compiler spills them at the entry, also on the gate-off path); the filter check in the prepended code of `slicerunetostring` (see item 1). In the wrapper of `slicerunetostring`, a first version stored the returned arguments again; the wrapper now ignores them (the compiler keeps `buf` and `a` in their spill slots), and `RuntimeClean/r2s-stack` went from +4.39 to +3.70 ns (two different runs). Not done: a lock-free `Confirm` (the clean filter hit costs mostly the 3 `TryRLock` / `RUnlock` pairs: shard, owner lifecycle, owner roots).

HTTP (sampled out): a CPU profile of the woven benchmark (`DD_IAST_REQUEST_SAMPLING=0`, 5 s) has no sample in a hooked runtime function or in the bridge: no root is live, so the gate is off. The IAST cost of this benchmark is not in the runtime hooks (IAST has +9 allocations and +3.9 KiB for each request).

Measurement (darwin/arm64, Apple M5 Pro, go1.26.6, Orchestrion v1.13.1). "Before" is the parent commit `b3096104` with the new benchmark files (`iast/runtime/bench_test.go`, `internal/taint/store/lookup_bench_test.go`, `runtime_bridge_bench_test.go`). The 16 woven binaries of "before" and the 16 of "after" run in the same interleaved rounds (8 rounds, 34 binaries, 300ms; thus 64 runs for each side and case). Store benchmarks: 8 rounds for each tree, one tree after the other. HTTP: n=20 for each tree, one tree after the other. Raw data and reports: `/tmp/t02` (not kept). Pooled hook - nohook, ns:

| Case | Gate | Before | After |
|---|---|---:|---:|
| `RuntimeClean/concat2-heap` | +6 | +5.17 | **+2.62** |
| `RuntimeClean/concat2-stack` | +6 | +4.80 | **+2.97** |
| `RuntimeClean/concat4-stack` | +9 | +5.84 | **+4.00** |
| `RuntimeClean/concat6-stack` | +12 | +7.07 | **+4.98** |
| `RuntimeClean/concat16-heap` | +27 | +14.42 | **+11.16** |
| `RuntimeClean/concat16-stack` | +27 | +15.34 | **+12.78** |
| `RuntimeClean/b2s-heap` | +4.5 | +3.81 | **+1.14** |
| `RuntimeClean/b2s-stack` | +4.5 | +3.60 | **+1.20** |
| `RuntimeClean/s2b-heap` | +4.5 | +4.30 | **+1.28** |
| `RuntimeClean/s2b-stack` | +4.5 | +4.02 | **+1.40** |
| `RuntimeClean/r2s-heap` | +6 | +1.99 | +1.55 |
| `RuntimeClean/r2s-stack` | +6 | +2.76 | +3.70 |
| `RuntimeClean/s2r-heap` | +6 | +6.04 | **+1.24** |
| `RuntimeClean/s2r-stack` | +6 | +4.52 | **+1.96** |
| `RuntimeCleanHit/s2b-stack` (sparse) | - | +33.61 | **+23.36** |
| `RuntimeCleanHit/concat2-stack` (sparse) | - | +62.77 | **+42.03** |
| gate `hit` (woven + full - sparse) | 50 | 48.73 | **28.08** |
| gate `full2` (woven + full - sparse) | 100 | 94.21 | **50.88** |
| `RuntimeTainted/concat2-stack` | +1 us | +603.90 | +590.30 |
| `RuntimeOff/*` (worst pooled) | +2 | +1.25 (`s2r-heap`) | +2.02 (`s2r-heap`), see below |
| HTTP sampled out | +3.70 % | +2.63 % | +3.47 % |

All other rows pass. The gate-off concat rows are 0.2 to 0.5 ns higher than before (`concat16-stack`: -0.27 to +1.19 ns). Their gate-off instructions do not change; the gate-on block is 2 instructions longer, so the original body starts 8 bytes later (code layout). The gate-off row `RuntimeOff/s2r-heap` is the row with the most noise (placement range -1.51 to +4.60 ns; the gate-off path has the same instructions as before and as the nohook build). It failed by 0.02 ns in the 8 rounds. A re-measure of this row only (20 rounds, 160 runs for each side, the same binaries): before +0.64 ns [-0.31, +1.69], after +0.57 ns [-0.61, +1.70]: PASS. `RuntimeClean/r2s-stack` is 0.9 ns slower than before (the wrapper calls the filter check and then the original function; it is 2.3 ns below its gate). The HTTP rows of the two trees ran one after the other, not interleaved (benchstat ±1 % to ±3 %); the gate is off in this benchmark, so this change cannot change it. With these inputs, all gates pass (the `admission` gate needs the old store of step 3 and is not measured again: this change does not change admission).

Validation: `go vet` (also `./.github`), `gofmt`, `go tool checklocks ./...`, `go test ./internal/taint/... ./.github`; `.github/woven-runtime.sh` in the modes default, race and nol: test, g0, escape (identical), and in default also linknames and link; `GOOS=linux GOARCH=386 go build ./internal/taint/...`.

**CI must run again** (linux/amd64 and linux/arm64, workflow `runtime-bench.yml`): the CI numbers of run 36834964455 are for the code before this change.

## Appendix A. Critic round 1 responses

| # | Finding | Response |
|---|---|---|
| 1 | Clean operand can allocate after a filter hit | Fixed: `confirm` validates before `buf = nil` (3.2.1); new gates (9.3); negative control. |
| 2 | Partial multi-granule insertion not rolled back | Fixed: `indexed` flag, all-or-nothing protocol, blocking rollback, filter only after all inserts (5.2.2); failure injection at each granule. |
| 3 | Byte mutation makes index generations stale | Fixed: entries store identity, validation reads the current generation and `setGen` (5.2.3). Evidence: `PublishBytesMutation` keeps `base` and `span` (`mutation.go:50`). |
| 4 | 32-probe limit loses small roots | Fixed: two tiers (64 B / 4 KiB) with hard density bounds 33 / 17, probe window 40 (5.2.1); 128-root and 33-root tests. |
| 5 | More than 16 operands miss late operands | Fixed: `coarseConcatHit` scans all operands (3.6 step 7). Evidence: `propagation.go:363-378`, `string_exact.go:51-65`. |
| 6 | Step order; pin cannot give `Result 0` | Fact part rejected: `fieldAt` is identical in the pin and in v1.13.1 (`diff` of `dot_function.go`), so the pin **can** name results. The plan text of section 2 (from Phase 0) was wrong and is corrected (now section 2.1; variant D no longer uses result names). Order part accepted. Round 2 changed it again: the AST removal, the repin and all runtime hooks are one commit (step 5), so no commit loses propagation (appendix B, R1#6). |
| 7 | Global filter can point at another store | Fixed: one binding set only by the process manager, `CompareAndSwap` (3.2 rule 6); independent-store test (9.1 item 6b). |
| 8 | Escape and GC safety not proven | Fixed: contract table, proof and checks (3.8). |
| 9 | dd-trace-go has no Orchestrion requirement | Fixed: facts recorded, Q1 closed, v1.13.1 selected (6.3). |
| 10 | Linkname rationale not correct | Fixed: rules from `loader.go` `checkLinkname` (3.9); explicit `-checklinkname=1` link test. |
| 11 | Validation matrix does not match CI | Fixed: `woven-runtime` matrix, `DD_IAST_REQUIRE_WOVEN`, `hookEntries` check, `-race` in woven tests (9.4, 9.1 item 1). |

## Appendix B. Critic round 2 responses

| # | Finding | Response |
|---|---|---|
| R1#1 | `confirm` checks containment, not range overlap | Fixed: `confirm` scans the root ranges (<= 64, no copy) for overlap with the operand window (3.2.1 step 3); interior `Lookup` skips empty sliced sets (5.2.4 step 4). Evidence: `appendWindow` clips each range to `[low, high)` and skips empty results (`ranges/operations.go:358-376`). Tests and negative control in 9.1 items 4b and 5. |
| R1#4 | 33/17 bounds false for shared allocations | Fixed with B. |
| R1#6 | Steps 4-6 lose propagation between commits | Fixed: new step 4 (bridge, no weaving) keeps the AST aspects; step 5 is one commit for AST removal + repin + all runtime hooks (section 10). R16 removed, old Q7 closed. |
| R1#7 | No test that a second bind cannot switch stores | Fixed: 9.1 item 6b checks that gate, filter, `confirm` and callbacks stay those of the first store. |
| R1#8 | Full conversion + GLS build not shown | Fixed: step 2 is an explicit early gate with one binary (GLS, concat, both conversions, guard, `recover`), 12 combinations; steps 3-7 wait for it. |
| R1#11 | Cell count and budget | Fixed: 12 + 1 = 13 cells; budget measured in step 2, not estimated (9.4). |
| A | Index failure makes a live root invisible to the filter | Fixed: admission rule (5.2.2). A root is visible to exact and interior lookups only when `indexed`; a failed index publication fails the admission. Thus a zero filter bucket proves "clean". Contention in `confirm` returns `unknown`, and `pre` forces the heap (3.2.1). Tests in 9.1 item 4b. |
| B | Shared allocations break the per-granule bound | Confirmed: `publishStringCopy` (`propagation.go:175-191`) and `stale_owner_internal_test.go:52-59` adopt one allocation for several owners. Fixed: one entry for each (key, base) with <= 4 refs; a fifth ref is a `fanout` refusal (5.2.1, new Q7). Tests in 5.3. |
| C | `MayContain` must also probe the exact table | Fixed: with the admission rule, the filter covers every exact slot (`putWindow` checks `inWindow`), so `MayContain` is the filter only and `Lookup` does not read the exact table (5.2.4). Hit rate depends on load: numbers per load in 5.3; benchmarks and gates for sparse, typical and full load (9.2, 9.3). |
| D | No guard or `recover` around `confirm` | Fixed: the runtime side sets the guard around every bridge call; `confirmSlow` has `defer` + `recover` and returns `true` on panic; the filter-only path has no `defer` (3.2, 3.4). Also found: `gopanic` throws when `m.mallocing`, `m.preemptoff` or `m.locks` is set (`runtime/panic.go:830-845`), so `__dd_iast_ok` checks all three (3.3). Tests: 9.1 item 13. |
| E | Memory claim incomplete | Fixed: measured with `unsafe.Sizeof` through `go test -overlay` (arm64, and an amd64 test binary): `Store` 13 391 448 B -> 15 363 672 B; `indexShard` 7 192 B including the 24-byte mutex; `rootRecord` stays 320 B because `indexed` uses padding at offset 76. `TestStoreFootprint` asserts it (5.2.1). |

No finding of round 2 is rejected.

## Appendix C. Critic round 3 responses

| # | Finding | Response |
|---|---|---|
| 1 | Indexed taint can be live while the gate is zero | Confirmed: `claimMutation` subtracts all old value slots (`mutation.go:91-96`); `setGen` and the ranges are stored (`mutation.go:58-66`) before `putWindow` (`mutation.go:73`). Fixed: the gate follows `indexedRoots`, not the value counter. Increment before `indexed = true`, decrement after `indexed = false` and ref removal (3.2 rule 3, 5.2.2). Mutation does not change it (5.2.3). Tests (a)-(d) and a negative control in 5.2.3. |
| 2 | Admission loses source taint that the old table kept | Confirmed, and not hidden: worst case approx. 20 % of the old capacity for dense 256 B roots (5.3). Fixed as asked: old vs new admission benchmark at sparse, stressed and saturated load, with dense, colliding and retention workloads (9.2); step 3 exit and section 11 use a user budget; R14 states the regression; new Q9. |
| 3 | Bridge sketch cannot represent `unknown` | Fixed: `confirmResult` enum (`confirmClean`, `confirmTainted`, `confirmUnknown`) in 3.2.1 text and sketch; 9.1 item 4b asserts `confirmUnknown` for a failed `TryRLock`. |

No finding of round 3 is rejected.

## Appendix D. Critic round 5 responses

| # | Finding | Response |
|---|---|---|
| 1 | Step 3 deletes wrappers that YAML aspects still name | Confirmed: `iast/propagation/orchestrion.yml` has `replace-function` aspects for `StringsCut` (line 425), `BytesCut` (line 839) and the others. Fixed: step 3 deletes the 39 window-helper calls; then it deletes the 41 wrappers that only call the stdlib **with** their 41 aspects in the same commit, and sets `instrumentedPropagationPoints` 125 -> 84 (`TestInstrumentedPropagationTelemetry` checks it). The list comes from the code (5.4). The AST operator aspects and `operators.go` stay until step 5. The direct test callers of `StringWindow*`, `ByteWindow*` and `Derive` (from `rg`, including `propagation_test.go` and `evidence/collection_behavior_test.go`) are listed in 5.4. No code calls a deleted wrapper directly; the woven tests use `iast/internal/propagationtest`. |
| 2 | Shared entries do not deduplicate by owner | Confirmed: the old `putWindow` moves one (owner, key) slot to the latest root (`value.go:172-187`). Fixed: at most one ref for each owner in an entry; `fanout` counts distinct owners (Q7). A new "Replace" protocol (5.2.2): the latest root wins; `shared` positions are not changed before the commit; the commit sets `prev.indexed = false` and `prev.next = root` under `rootsMu`, with generation and `owner.replacing` checks; validation follows `next` one hop (5.2.3), so readers never see a partial replace; a clean-up moves or removes the refs of `prev`; rollback of a failed replace leaves `prev` unchanged. Cross-tier `prev` is found through the base key of the other tier; `Lookup` keeps one contribution for each owner (5.2.4). Tests in 5.3; R19. |
| 3 | `slicerunetostring` charge can be too small | Confirmed in go1.26.6 and go1.27.1: allocation `size1+3`, result `size2`, and `size2` can be much smaller after a concurrent change. The advice cannot read `size1` or `b` (declared after the prepended statements). Fixed: charge `sizeClass(4*len(a)+3)`, a bound that no rune change can break (`encoderune` writes <= 4 bytes; `len(a)` is an argument copy). `AdoptStringAlloc` refuses a bound below `len(value)+3` or above `MaxRootBytes`. Over-charge accepted (R18). Direct and forced-change tests in 4.5. |
| - | Store total | Rechecked on the current code (measured sizes in 5.2.1). 14 040 136 B is correct when `compactions` and `compactAborts` (16 B, the last `Store` fields) are deleted, as 5.4 says; 14 040 152 B is the same sum without that deletion. The arithmetic is now written in 5.2.1. |
| - | Sink lookup cost | Added R17: two hashes and two filter loads on each sink check, and up to two 40-entry probes on a hit. Measured by the sink check benchmark of 9.2 at sparse, typical and full load. |

No finding of round 5 is rejected.

## Appendix E. Critic round 6 responses

| # | Finding | Response |
|---|---|---|
| 1 | A merge clean-up can change a copied ref between the copy and the validation, so `confirm` reports clean | Confirmed: in round 5, 5.2.4 released the shard read lock before validation under `rootsMu`, and the clean-up rewrote the ref and cleared `prev.next`. Fixed with one rule (5.2.2, "Reader rule"): a reader validates each ref while it holds the shard read lock where it found it; writers change refs only under `shard.mu.Lock()`. Invariant and proof in 5.2.2: a ref resolves in at most one `next` hop to an indexed root, or to a root that is not admitted. `prev.next` is not cleared any more (only `Finish` clears it); the mutation redirect uses it. Lock order still has no blocking cycle (readers only try). Cost: longer shard read hold, measured by the stressed admission benchmark (Q9 gate). Barrier test with a negative control (5.2.2, 9.1 items 4 and 5). |
| 2 | R19 is wrong: the old table kept one slot for each exact key, so a shorter re-adoption did not lose the longer value | Confirmed: `putWindow` matches `pointer`, `length`, `kind`, `ownerIdx` and `ownerGen` (`value.go:172`). Fixed: "latest root wins" is withdrawn. A re-adoption **merges** (5.2.2 "Merge"): span `U = max`, and ranges `Canonicalize(new ++ prev)` for strings (union of taint; new ranges win on shared bytes), or new ranges on `[0, root.span)` plus the `prev` tail for mutable roots (the mutation rule of 5.2.3). `prev` is found before the keys are computed (new step 0), so the keys cover `U`; refs of `prev` move to the merged root. Cap: <= `root.limit`, tail drop counted in `drops.ranges`. Mutations of a merged root: relaxed identity check (`cap(value) <= root.span`) and a redirect from `prev` to the merged root (5.2.3). R19 rewritten with the remaining trade-offs. Tests in 5.3 (longer then shorter, overlap, cross tier, mutable, cap) and a negative control. |
| - | Found while fixing 2: two concurrent first adoptions of one owner in different tiers could both commit | Two base keys (tier S and tier L) are different entries, so step 2 did not always see the other publication. Fixed: commit check (c) re-reads the base key of each tier under `rootsMu` with `TryRLock` (5.2.2 step 5). Test and negative control in 5.3 and 9.1 item 5. |
| - | Estimate | Step 3: 5.25 -> 5.5 days; total 12.75 -> 13 days. |

No finding of round 6 is rejected.

## Appendix F. Critic round 7 responses

| # | Finding | Response |
|---|---|---|
| 1 | A mutation can claim `prev` between merge check (b) and the commit; if the mutation then fails, the merged root keeps ranges copied from `prev` (stale pre-mutation taint) | Confirmed: `claimMutation` is a generation `CompareAndSwap` without `rootsMu` (`mutation.go:83-89`), and a failed publication (`rootsMu.TryLock`, `mutation.go:43`) leaves only the claimed root invalid. The problem is broader than the window between check (b) and the commit: a claim of `prev` after the commit, then a failure before the redirect, gives the same result. Fixed with the simplest design that removes the cause: **one root record for each owner and allocation**. A re-adoption extends the root in place (5.2.2 "Extension") and never writes `generation` or `setGen`. Invariant: every range of the root, including the ranges from an extension, is valid only while `setGen == generation`; one claim CAS invalidates all of them, with or without `rootsMu`. There is no second record that can keep stale ranges. Deleted: `rootRecord.next`, `owner.replacing`, the one-hop validation, the mutation redirect, the shared-position logic, and the round 6 reader rule (a ref now never changes its `rootID`, so a reader can validate a copied ref; 5.2.2 "Reader order"). Added: `owner.extending` (one extension at a time for each owner), E4 validity check. Race test: claim CAS exactly between the E4 check and the commit, then a forced `rootsMu.TryLock` failure of the mutation; all views are a miss. The same with the claim before E4 and after the commit. Negative control in 9.1 item 5. Trade-off: after a failed mutation, a re-adoption of that root by the same owner is refused (R19 item 5). |
| 2 | The bytes/runes merge discards earlier taint on `[0, root.span)` without a tracked mutation | Confirmed: the round 6 "mutable rule" kept only the new ranges on `[0, root.span)`; the old table kept the exact slot of the earlier adoption (`value.go:172`). Fixed: one **union** rule for all kinds (5.2.2 "Union rule"): `Canonicalize(new ++ old, U)`; the new ranges win only on bytes that both sets describe, and every tainted byte stays tainted. Only a tracked mutation (5.2.3) replaces earlier ranges. Over-taint of bytes that the application rewrote without a tracked mutation is accepted (Q2, R13). The example of the finding (X on `[0,8)` of a 64-cap allocation, then Y on `[16,24)` of a 32-cap view, no write) keeps X and Y (5.3 test). R19 and the 5.3 tests are updated. |
| - | Found while fixing 1: a reader could miss a root during an extension from tier S to tier L | If a reader read tier L before the tier L insert and tier S after the tier S removal, it could miss the root (the round 6 design had the same gap during a cross-tier merge). Fixed: writers add tier L refs before they remove tier S refs, and readers read tier S before tier L, for the filter and the shards (5.2.2 "Reader order", 5.2.4). Test and negative control in 5.2.2 and 9.1 item 5. |
| - | Estimate | No change: the removed parts (redirect, hop, barrier test) balance the two new race tests. Total 13 days. |

No finding of round 7 is rejected.

## Appendix G. Critic round 8 responses

| # | Finding | Response |
|---|---|---|
| 1 | A reader can load the tier L filter bucket before an S->L extension, probe tier S after E5, and skip tier L on the old bucket value | Accepted. The reader completes tier S (filter load and probe) before it loads the tier L bucket; `confirm` uses the same order (5.2.4 step 2, 5.2.2 "Reader order"). Second negative control added. |

## Appendix H. Step 2 results and variant D

Source: [`/tmp/concathook-gate/REPORT.md`](/tmp/concathook-gate/REPORT.md) (sections "Verdict" to "Remaining risks", and "Performance investigation (gate off)"). Artifacts: `/tmp/concathook-gate/artifacts/` and `/tmp/concathook-gate/artifacts/perf/` (YAML of each variant in `yaml/`, generator `gen.py`, woven sources `D-atomic-woven-*.go.txt`, disassembly in `disasm/`, benchmark data in `results/`, cell logs in `cells/`). Module of variant D: `/tmp/concathook-gate-perf/D-atomic`.

### H.1 Step 2 gate (template with `defer`)

- Verdict: **PASS**. 12/12 combinations: darwin/arm64 and linux/amd64 (Rosetta, a real amd64 run under emulation), go1.26.6 and go1.27.1, default / `-race` / `-gcflags=all=-N -l`.
- Each cell: 14 woven tests (a skip is a failure), unwoven build, `-ldflags=-checklinkname=1` link and run of `cmd/withhook` and `cmd/nohook`, `blockedLinknames` grep, escape comparison (67 / 67 / 58 lines identical).
- GLS and our aspects both use `struct-definition: runtime.g` in one build with no conflict. `imports:` works in `runtime`.
- Negative controls fail as expected: `buf = nil` removed (8 tests), guard check removed (`TestRecursionGuard`), `s2s_gate` check removed (`TestS2SGateOff`).
- Two test defects were found and fixed (not hook defects). One of them proved the plan 3.8 case "a stale stack key is only a miss, no crash".
- Early warning: gate-off time above +2 ns in some runs for `r2s-stack` (+4.4 ns), `s2r-stack` (+3.2 ns), `s2b-stack` (+2.9 ns), `concat-heap` (+2.0 ns), darwin/arm64.

### H.2 Cause: the `defer`

Disassembly (go1.27.1, darwin/arm64). The compiler open-codes the `defer`, but the gate check is inside the closure. Thus the gate-off path runs, on every call: the result gets a stack home (zeroed at entry, stored at each `return`, loaded again); the closure slot and the defer bits are zeroed and the closure is built (4 to 6 stores); at exit, an indirect call to `func1`, which has its own stack check and frame, and only then loads the gate. The arguments are spilled before the pre-check branch. The frame grows by 80 B in all 6 functions; `stringtoslicebyte` goes from 64 to 144 B, above `StackSmall` (128), so its stack check gets one more instruction. Inlining is not the cause: none of the 6 functions is inlinable, woven or not.

| Function | Frame bytes: unwoven / `defer` / **D** | Instructions: unwoven / `defer` / **D** |
|---|---|---|
| `concatstrings` | 112 / 192 / **128** | 120 / 192 / **132** |
| `concatbytes` | 112 / 192 / **112** | 100 / 176 / **112** |
| `slicebytetostring` | 48 / 128 / **48** | 64 / 136 / **76** |
| `stringtoslicebyte` | 64 / 144 / **64** | 48 / 124 / **64** |
| `slicerunetostring` | 128 / 208 / **128** | 88 / 152 / **100** |
| `stringtoslicerune` | 80 / 160 / **80** | 100 / 176 / **116** |

### H.3 Variants

| Variant | Shape | Result |
|---|---|---|
| base | the `defer` template of the step 2 gate (Phase 0 v2 shape, with the guard and the full `__dd_iast_ok`) | above +2 ns for `s2b-stack` and `r2s-stack` (95 % CI above 2) |
| A | `if gate != 0 { pre-check; defer ... }` | still open-coded; the defer state and the larger frame stay; +1.1 to +1.4 ns for conversions, little margin |
| B | A with `//go:noinline` helpers | no gain over A (`defer f(&r, x)` is a closure too) |
| C | plain load in place of `atomic.Load` | no measurable difference; keep `atomic.Load` |
| **D** | no `defer`; outer gate check; wrapper with bypass token and alias (section 2.2) | gate-off cost at the noise floor (0.0 to 0.5 ns) |

Two details of D are necessary:

1. **Alias.** The first D build called `runtime.<fn>` directly from the wrapper. The escape comparison failed in all 6 cells (`leaking param: buf` in place of `leaking param: buf to result ~r0 level=0`, for the 6 functions and `concatstring2..5` / `concatbyte2..5`; reproduced in a 30-line package). The body-less `//go:linkname` + `//go:noescape` alias fixes it (identical lines, 6/6 cells). `-checklinkname=1` accepts the same-package pull (3.9 item 5).
2. **One-shot token** `__dd_iast_bypass uint8` (3.4.2). No body copy in the YAML: the wrapper calls the original function again, and the token makes that inner call skip the hook.

### H.4 Gate off, delta vs unwoven, ns

These are the numbers of the first D (context check in the wrapper). H.6 has the numbers after critic round 9 (the template of section 2.2).

Method: `go test -c` binaries (unwoven, `defer` template, D-atomic), one round runs every binary once in a rotating order, 20 rounds x `-benchtime=1s`, darwin/arm64 (Apple M5 Pro). Delta = difference of medians; D with a bootstrap 95 % CI (4 000 resamples). Heap cases store the result in a global; stack cases return only `len` (result <= 32 B). Conversions: 40 elements (heap), 11 or 12 elements (stack). Allocations: identical to unwoven in every cell (1 for heap, 0 for stack).

| Case | go1.27.1 unwoven | go1.27.1 `defer` | go1.27.1 **D** [95 % CI] | go1.26.6 unwoven | go1.26.6 `defer` | go1.26.6 **D** [95 % CI] |
|---|---:|---:|---:|---:|---:|---:|
| concat2-heap | 13.51 | +1.75 | **+0.51** [+0.22, +0.74] | 15.18 | +1.31 | **+0.29** [-0.26, +1.01] |
| concat4-heap | 17.07 | +1.48 | **+0.54** [+0.19, +0.70] | 18.91 | +1.00 | **-0.08** [-0.43, +0.44] |
| concat6-heap | 21.50 | +1.29 | **+0.39** [+0.06, +0.64] | 23.30 | +1.39 | **+0.15** [-0.56, +0.54] |
| concat16-heap | 46.90 | +0.34 | **-0.58** [-1.41, +0.06] | 49.34 | +2.91 | **+0.86** [-0.68, +1.39] |
| concat2-stack | 8.21 | +1.01 | **-0.17** [-0.37, +0.04] | 7.67 | +1.46 | **+0.42** [-0.06, +0.64] |
| concat4-stack | 11.46 | +1.06 | **+0.14** [-0.03, +0.33] | 11.38 | +1.32 | **+0.07** [-0.19, +0.33] |
| concat6-stack | 17.93 | +1.11 | **+0.22** [-0.41, +0.55] | 18.16 | +0.73 | **-0.37** [-0.87, +0.05] |
| concat16-stack | 42.64 | +1.09 | **-1.23** [-2.12, -0.30] | 42.14 | +1.45 | **-0.48** [-1.61, +0.24] |
| b2s-heap | 9.18 | +1.67 | **+0.10** [+0.03, +0.19] | 10.44 | +1.42 | **-0.02** [-0.18, +0.30] |
| b2s-stack | 2.77 | +1.57 | **+0.18** [+0.12, +0.22] | 2.77 | +1.34 | **+0.15** [+0.13, +0.22] |
| s2b-heap | 10.84 | +1.89 | **+0.05** [-0.04, +0.12] | 11.91 | +2.06 | **+0.02** [-0.22, +0.31] |
| s2b-stack | 2.55 | +2.17 | **+0.45** [+0.45, +0.47] | 2.57 | +2.18 | **+0.23** [+0.20, +0.27] |
| r2s-heap | 94.37 | +0.91 | **-0.44** [-0.63, +0.19] | 95.27 | +2.09 | **-1.17** [-5.64, +0.62] |
| r2s-stack | 24.83 | +2.48 | **+0.39** [+0.36, +0.44] | 25.17 | +2.15 | **+0.32** [-0.45, +0.86] |
| s2r-heap | 39.17 | +2.35 | **+1.63** [-0.87, +3.32] | 43.81 | -0.36 | **-1.77** [-4.14, +0.44] |
| s2r-stack | 10.28 | +1.13 | **+0.16** [-0.52, +1.07] | 10.71 | +1.41 | **-0.22** [-0.92, +1.02] |

Reading: the worst resolved D median is +0.54 ns (`concat4-heap`, go1.27.1). `s2r-heap` is noise-limited: the unwoven baseline moves between 37.4 and 44.8 ns in one set; 40 more runs gave D +0.74 [-1.76, +3.17], and with `GOGC=off GOMEMLIMIT=1GiB` +0.60 [-2.52, +2.56]. The D code of `stringtoslicerune` is the same 4 instructions as for the other functions.

Gate on, Q2 switch off (9.3 row "<= +2 ns"), D: go1.27.1 `s2b-heap` +0.11, `s2b-stack` +0.45, `s2r-heap` +1.78 [-0.81, +3.91], `s2r-stack` -0.44; go1.26.6 +0.03 / +0.23 / -3.35 / -0.30. The `defer` template: +1.2 to +2.2.

Gate on, clean operands (stub bridge with 2 test counter atomics for each entry, not a 9.3 measurement): D is +0.4 to +1.4 ns slower than the `defer` template for heap concat, equal for stack concat and `string(b)`, and approx. 3 ns faster for `r2s-stack` (R22).

### H.5 Correctness of D

- First D: `cell.sh` with D-atomic, darwin/arm64, go1.26.6 and go1.27.1, default / `-race` / `-N -l`: **6/6 PASS** (14 woven tests, unwoven build, both links with `-checklinkname=1`, `blockedLinknames` grep, escape lines identical: 67 / 67 / 58).
- Negative controls on D: `buf = nil` -> `_ = buf`: 9 tests fail; `in_hook` check removed from `__dd_iast_ok`: `TestRecursionGuard` fails; `s2s_gate` check removed: `TestS2SGateOff` fails. The first D build (direct call, no alias) is the escape negative control.
- Not done: D on linux/amd64 (step 5 and step 6), D performance on amd64 (step 7), `-m=2` comparison (step 5).
- After critic round 9: H.6.

### H.6 Critic round 9: context check before the wrapper

Source: [`/tmp/concathook-gate/REPORT.md`](/tmp/concathook-gate/REPORT.md), section "Critic round 9". Data: `/tmp/concathook-gate-perf/D-atomic/_perf/` (`cells/`, `results/fix-*`, `results/s2r-*`, `bin/`). Test: `/tmp/concathook-gate-perf/D-atomic/g0test/g0_test.go`.

| # | Finding | Response |
|---|---|---|
| MAJOR | With the gate on, the prepended code called the `//go:noinline` wrapper before `__dd_iast_ok()` checked `g0` / `gsignal`. The wrapper has a stack check at entry, and `morestack` on `g0` or `gsignal` is fatal. | Accepted. The prepended code reads the token, then calls the `//go:nosplit` `__dd_iast_ok()`, and calls the wrapper only when it is true; otherwise the original body runs directly (2.2 items 2-3, 3.3). The wrapper has no context check. Token rules re-checked (3.4.2 rules 1, 2, 6): the token is read before the check, so only the inner call consumes it; only a wrapper sets it, thus never on `g0` / `gsignal`; the wrapper clears it after the inner call. A nested operation in the bridge now runs the original body directly (no extra frames). `__dd_iast_ok()` cannot grow the stack: inlined (default flags) or a leaf with no frame, no stack check and no call (`-N -l`), go1.26.6 and go1.27.1 disassembly. New test 9.1 item 15 and negative control (9.1 item 5). |
| MINOR | The signature assertions checked only `<fn>`, not the alias and the wrapper. | Accepted. 3 assertions for each function, all to one func type (3.9 item 6). Negative control: an alias with one more argument is a compile error; without the alias assertion it compiles silently. |
| - | Found while measuring the fix: `gate != 0 && s2s != 0` in the new shape was compiled as a bool (`CSET` + `MOVD ZR` + `TBZ`) in `stringtoslicebyte` / `stringtoslicerune`: 2 more instructions on the gate-off path; `s2r-stack` fast mode +1.1 ns (minimum 10.3 vs 9.3 ns in 4 sets). | The `s2sGate` check is a nested `if` (4.3). Gate-off path again `LDARW` + `CBZW` in all 6 functions. |

Correctness (darwin/arm64, `cell.sh`, go1.26.6 and go1.27.1, default / `-race` / `-N -l`): **6/6 PASS**. Each cell: 14 woven tests and the system-stack test (15 PASS), unwoven build (also of the system-stack test), `-checklinkname=1` link and run of `withhook` and `nohook`, `blockedLinknames` grep, escape lines identical (67 / 67 / 58). System-stack calibration edge `D`: 16 306 (default), 16 281 (`-race`), 10 867 (`-N -l`), the same on both Go versions. At `D` with the gate on: exit 0, 0 bridge entries on `g0`, 6 on the goroutine.

Negative controls: the first D template (check in the wrapper): the system-stack test fails in go1.27.1 default, `-race`, `-N -l` and go1.26.6 default (child: "fatal: morestack on g0", in `__dd_iast_concatstrings`). On the new template: `buf = nil` -> `_ = buf`: 9 tests fail; `in_hook` check removed: `TestRecursionGuard` fails; `s2s` check removed: `TestS2SGateOff` fails.

Machine code: frame sizes unchanged (128 / 112 / 48 / 64 / 128 / 80 B, table H.2); each function has 12 more instructions than the first D, all in the gate-on branch.

Gate off, delta vs unwoven, median ns [95 % CI], same method as H.4 (20 interleaved rounds x 1 s; `s2r-*` 40 rounds). Allocations identical to unwoven.

| Case | go1.27.1 first D | go1.27.1 **fixed D** | go1.26.6 first D | go1.26.6 **fixed D** |
|---|---:|---:|---:|---:|
| concat2-heap | +0.52 | **+0.31** [+0.10, +0.58] | +0.45 | **+0.22** [+0.02, +0.47] |
| concat4-heap | +0.50 | **+0.25** [+0.07, +0.50] | +0.41 | **+0.46** [+0.22, +0.63] |
| concat6-heap | +0.41 | **+0.11** [-0.17, +0.39] | +0.18 | **+0.29** [-0.09, +0.53] |
| concat16-heap | -0.86 | **-1.24** [-2.16, -0.69] | +0.16 | **-1.42** [-2.04, -0.55] |
| concat2-stack | +0.04 | **-0.03** [-0.24, +0.17] | +0.52 | **+0.30** [+0.10, +0.66] |
| concat4-stack | +0.13 | **+0.28** [+0.13, +0.46] | +0.26 | **+0.35** [+0.20, +0.53] |
| concat6-stack | -0.07 | **+0.34** [-0.01, +0.80] | -0.11 | **+0.04** [-0.21, +0.24] |
| concat16-stack | -1.49 | **-0.15** [-1.68, +0.59] | -0.67 | **-1.27** [-2.38, -0.60] |
| b2s-heap | +0.11 | **+0.13** [+0.03, +0.21] | +0.07 | **+0.19** [+0.05, +0.31] |
| b2s-stack | +0.17 | **+0.10** [+0.06, +0.21] | +0.23 | **+0.18** [+0.13, +0.21] |
| s2b-heap | -0.04 | **-0.05** [-0.12, +0.12] | +0.01 | **+0.10** [-0.01, +0.16] |
| s2b-stack | +0.45 | **+0.23** [+0.23, +0.24] | +0.24 | **+0.24** [+0.23, +0.25] |
| r2s-heap | -0.55 | **+0.69** [-0.35, +6.97] (a) | -0.87 | **+0.25** [-0.26, +0.73] |
| r2s-stack | +0.31 | **+0.38** [+0.20, +0.74] | +0.32 | **+0.34** [+0.29, +0.38] |
| s2r-heap | +0.31 | **-1.41** [-4.12, +1.07] | +0.63 | **-1.80** [-2.89, +0.75] |
| s2r-stack | -0.43 | **-0.26** [-1.14, +0.87] | +0.61 | **-0.09** [-1.20, +0.78] |

(a) 8 of 20 runs at 100 to 121 ns (background load); the other 12 are as unwoven.

Reading: the worst resolved median is +0.46 ns (`concat4-heap`, go1.26.6). All 16 cases stay within the 9.3 gate of +2 ns on both Go versions. Q2 switch off (gate on): go1.27.1 +0.04 / +0.24 / +0.64 / +0.48, go1.26.6 +0.16 / +0.24 / -2.03 / -0.37 (`s2b-heap` / `s2b-stack` / `s2r-heap` / `s2r-stack`). Gate on with clean operands was not measured again.
