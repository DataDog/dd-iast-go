# Phase 6 plan: operator taint propagation

## Status

- **State:** deferred by user at the Orchestrion schema checkpoint
- **Parent:** [taint-tracking-net-http-sqli-cmdi.md](./taint-tracking-net-http-sqli-cmdi.md)
- **Evidence:** [taint-tracking-net-http-sqli-cmdi-phase-0.md](./taint-tracking-net-http-sqli-cmdi-phase-0.md), section 4
- **Toolchain:** Go 1.26.6; Orchestrion 1.12.2 plus the additive APIs below

The user deferred this phase before schema approval. No Orchestrion or operator
implementation is authorized. Phase 7a reporting and sink work can proceed
independently; this plan is retained as the reviewed basis for resuming Phase 6.

This phase targets string concatenation, string and byte slicing,
`string`/`[]byte` conversions, and the built-in `append` and `copy` operations.
Runtime concat and conversion callbacks remain rejected: they cannot observe
unnamed results with the selected Orchestrion version, and the concat input
shape added a disabled-path allocation in the Phase 0 probe.

`append` and `copy` are conditional subphases. Their matchers can land upstream,
but dd-iast-go aspects remain disabled until the allocation and managed-root
mutation proofs in section 5 pass.

## 1. Required user checkpoint: Orchestrion API and schemas

The first release adds four typed join points and one generic advice-proxy
extension:

```yaml
# Resolve the callee through go/types and match only a universe built-in.
builtin-call:
  name: append # enum: append, copy

# Match only the root of one maximal, non-constant string `+` chain.
string-concat:
  min-operands: 2
  max-operands: 16

# Match a SliceExpr by the core type of X.
slice-expression:
  operand: string # enum: string, bytes

# Match an explicit conversion only where Go 1.26.6 proves that wrapping keeps
# the original allocation and alias behavior.
type-conversion:
  from: bytes  # enum: string, bytes
  to: string   # enum: string, bytes; must differ from `from`
  mode: allocation-preserving # the only accepted first-release value
```

A concat chain above `max-operands` is rejected as one complete operation. It is
not partially instrumented. The build emits a bounded diagnostic/count for the
unsupported shape. Sixteen is a proposed first-release coverage bound and is
part of this checkpoint.

Current Orchestrion join points return only a match boolean; they cannot attach
join-point-specific data to advice. The implementation therefore extends the
**generic advice AST proxy**, not `join.Point.Matches`, with read-only typed
helpers available for every applicable AST node:

- `BinaryExpr.FlattenedOperands`: maximal string-add operands in source order;
- `Expr.ResolvedType`: an import-aware syntax node for the exact `go/types.Type`;
- `CallExpr.ResolvedObject` and `CallExpr.BuiltinShape`: resolved callee identity
  and append/copy overload shape;
- existing `SliceExpr.X`, `Low`, `High`, and `Max` fields remain unchanged.

The proxy computes these values from `AdviceContext.ResolveType` plus a new
`ResolveObject` method backed by `types.Info.Uses`. It does not depend on which
join point matched. Proxy generation, import insertion, stable hashing, and
composition under `all-of` are tested explicitly. `ResolvedType` is available
only when the exact type is source-nameable from the injection site. A matcher
that requires it rejects imported unexported or otherwise inaccessible types
with a bounded diagnostic. It must never render a canonical type that changes
identity. A transformation that supports inaccessible types requires a new user
schema review.

## 2. Repository and dependency workflow

The join-point registry, typed context, advice proxy, and embedded schema are
internal to Orchestrion. There is no external join-point plugin API. Changes
live in the sibling `../orchestrion` repository and are submitted upstream.

Development uses a temporary uncommitted `GOWORK` binding to `../orchestrion`;
the module cache is never edited. Orchestrion changes are committed and reviewed
first. dd-iast-go then pins their pseudo-version and regenerates its tool pin. A
local filesystem `replace` is never committed. Before GA, the dependency moves
to the first published Orchestrion release containing these APIs.

Every join point implements stable fingerprint hashing and package/file
pre-filters. Missing schema fields, unstable hashes, stale-cache matches, or
synthetic test-variant cycles are blockers.

## 3. Orchestrion join-point implementation

### 3.1 Typed built-in calls

`AspectContext.ResolveObject` maps a decorated expression to the original AST
and reads `types.Info.Uses`. `builtin-call` matches a `*dst.CallExpr` only when
its callee is the configured `*types.Builtin` from `types.Universe`. Local
functions, variables, package declarations, and lexical shadows named `append`
or `copy` never match.

`BuiltinShape` distinguishes element append, slice append, byte/string append,
slice copy, and byte/string copy from resolved argument types. Advice templates
select a fixed typed wrapper for the shape; they do not reimplement type
resolution.

### 3.2 Maximal string concatenation

`string-concat` matches `token.ADD` `*dst.BinaryExpr` with string core type. It
rejects a node whose matching ancestor belongs to the same compiler concat
chain. Maximal-ancestor detection and flattening cross `ParenExpr` nodes:
parentheses are not compiler concat boundaries. Non-constant string-add trees
are flattened in source order, while a constant-valued subtree is retained as
one atomic operand so compiler folding stays unchanged. The 16-operand bound is
applied after this compiler-equivalent folding. Only the maximal root is
advised. Results whose exact type cannot be named at the injection site are
rejected as a complete chain.

Before schema completion, an Orchestrion golden fixture must prove the exact
generated source IIFE. It must:

1. evaluate operands once and left to right;
2. keep untyped constants in a context where they retain their original type;
3. perform the original maximal `+` expression once;
4. preserve base, imported defined, alias, and constrained type-parameter
   result types;
5. preserve panic order and the original disabled/untainted allocation count.

The generated IIFE uses an import-aware exact, source-nameable return type and
keeps untyped operands in their original contextual expression. Generic
variadic reconstruction is forbidden because it can change compiler concat
lowering. Fixtures include left/right/nested parentheses, folded constant
subtrees, a defined operand on each side, untyped literals, untyped named
constants, imported exported and unnameable hidden result types, aliases, and
type parameters. Golden source, disassembly, and allocation output must agree
with compiler-equivalent flattening.

`+=` remains unsupported because it is an assignment statement, not a
`BinaryExpr`.

### 3.3 Typed slicing

`slice-expression` matches only string or `[]byte` core operands and rejects
arrays, pointers to arrays, and unrelated slices. String aspects support all
four omitted-bound forms. Byte aspects also support full-slice forms with
`Max`.

Advice uses one shape-specific constrained-generic wrapper per bound form, so
an inaccessible inferred operand type does not need to be spelled in generated
source. It evaluates `X`, `Low`, `High`, and `Max` once in Go's original order,
performs the original slice operation before taint work, and uses no sentinel
bound. Panic values and messages therefore come from the original operation.
Compile fixtures cover imported unexported defined strings/byte slices, aliases,
and `~string`/`~[]byte` type parameters before this design is accepted.

### 3.4 Typed conversions and compiler exclusions

`type-conversion` matches a one-argument, non-variadic `CallExpr` only when the
callee resolves as a type and source/destination core types match the schema.
`allocation-preserving` is a conservative allowlist derived from Go 1.26.6
compiler source and disassembly. It excludes at least:

- range expressions;
- `len(string(bytes))` and equivalent optimized built-in contexts;
- conversions participating in optimized string concatenation;
- direct or recursively nested map-key expressions, including struct and array
  literal keys;
- comparisons, switch tags, and case expressions;
- `[]byte(string)` contexts where escape analysis uses a non-mutating zero-copy
  temporary.

The Orchestrion change documents the exact accepted parent contexts. Every
accepted and excluded context has allocation and alias tests. If no useful
allowlist survives, conversion aspects stop for user review; they are not
broadened by default.

Defined destination types are preserved by applying the original destination
conversion syntax around the base helper result. The input expression appears
once. Compile and escape fixtures cover named strings, named byte slices,
aliases, imported types, and constrained type parameters.

## 4. Unconditional dd-iast-go semantics

All enabled aspects apply only to application-root packages. They exclude
`dd-iast-go/internal/**`, `iast/propagation`, `taint`, and `dd-trace-go`.
Generated code first evaluates and performs the host expression once, then
checks the active store and provenance. Nil-store, ineligible-key, and
`MayContain` misses stay inline; tainted work is `//go:noinline`.

### 4.1 Concatenation

For chains of 2 through 16 operands, range sets are shifted by each operand's
byte offset with `ranges.Concat`. A non-aliasing tainted result is cloned once to
exact length and shared across at most four contributing owners. An alias fast
path derives its input root. Empty results stay untainted. Mid-rune and invalid
UTF-8 bytes are preserved exactly.

### 4.2 Slicing

String and byte outputs derive canonical root-relative windows. Empty outputs
remain untainted; a one-byte output can derive from an existing managed root.
A three-index byte slice does not create a new root or charge. Capacity is read
from the live result when a later mutation is evaluated; the current value key
continues to use pointer, length, and kind only.

### 4.3 Conversions

Byte-to-string propagation returns an exact-length managed string on the
tainted path. String-to-byte propagation returns a replacement clone on the
tainted path rather than retaining the compiler's temporary result. The outer
original destination conversion preserves a defined result type. Allocation
and alias parity on disabled, no-active, sampled-out, and active-clean paths is
a prerequisite, not an assumed property.

## 5. Conditional append/copy feasibility and semantics

No append/copy aspect is enabled until this section has a separate critic and
user checkpoint.

### 5.1 Pre-mutation token

Current `Entry` exposes window-relative ranges, while
`Owner.PublishBytesMutation` requires a complete root-base value and complete
root-relative set. Add a bounded pre-mutation capture API that returns an opaque
generation-safe token containing owner identity, `RootRef`, root offset, root
span/base comparison key, destination window, and a snapshot of the complete
canonical root range set. Numeric pointers remain comparison keys and are never
converted back.

Capture precedes the built-in and atomically reserves or dirties the root
generation before mutation. At most one token for one generation can leave
publishable provenance. A competing successful capture conservatively dirties
the root before either host mutation, so publication reordering cannot leave one
valid but incomplete range set. Publication uses checked root-relative offsets:
append writes at `rootOffset + oldLen`; copy writes at `rootOffset` and preserves
root ranges outside that interval. Source ranges are snapshotted before an
overlapping copy.

The token design must also solve capture contention without leaving stale
provenance. A failed bounded capture cannot permit an untracked mutation of a
possibly managed root. The proof may use a lock-free, bounded dirty-generation
marker, but it may not block, scan all roots, or retain an arbitrary pointer. If
this cannot be guaranteed, append/copy remain unsupported.

A zero-count copy does not change generation or ranges. Panic or allocation
failure may conservatively invalidate provenance but cannot publish ranges for
a mutation that did not occur.

### 5.2 Managed and unmanaged destinations

An in-place append or copy into an unmanaged caller allocation cannot be
retained. Source propagation is dropped. A reallocated append result may be
adopted only if escape analysis proves that passing it through the wrapper adds
no disabled/clean allocation and the result is a complete allocation. Append is
never cloned because that changes capacity and aliasing.

Exact value keys are insufficient for zero-length or unregistered interior
aliases into a managed root. The feasibility stage must add a bounded root-
interval identity/invalidation directory that can recognize any pointer/span
inside a live managed byte root without scanning all roots, retaining an
arbitrary pointer, or converting a numeric key back to one. It must cover
zero-length aliases at a known live address. Otherwise append/copy remain
unsupported.

Direct byte index and slice assignment can also mutate a managed root through
an unregistered alias. Before mutable-byte operator propagation is enabled,
Orchestrion must either provide a typed assignment matcher with conservative
root invalidation or prove an equivalent bounded invalidation mechanism. Merely
documenting index assignment as unsupported is not sufficient because stale
ranges would be false provenance.

### 5.3 Exact operation behavior after feasibility passes

Append supports element, `src...`, and `append([]byte, string...)` forms. An
in-place managed append claims a new root generation, preserves existing root
ranges, and shifts source ranges to the root-relative write offset. A proven
reallocation adopts the complete result and charges visible capacity.

Copy supports slice/slice and `copy([]byte, string)` forms. It snapshots source
ranges before the built-in, then overwrites only the actual root-relative
`[offset, offset+n)` interval. Untainted bytes remove overwritten taint; copied
ranges are clipped to `n`; unaffected root ranges survive. Self-copy in both
directions follows Go's pre-copy semantics.

Assignment propagation itself remains out of scope, but assignment-triggered
root invalidation is a prerequisite from section 5.2. If it cannot cover direct
index and slice assignments without changing host semantics or gates, append and
copy stay disabled.

## 6. Bounds and telemetry

The current hard limits remain: 64 owners; 512 roots and 4,096 values per owner;
256 values per root generation; 16,384 process values; 64-KiB individual roots;
2-MiB charged roots per request; 8-MiB process roots; ten guaranteed and 64 hard
ranges; and the approved 24-MiB whole-feature fixed-plus-managed ceiling.
Operator fanout is four owners. All ordinary locks use bounded try operations.

Accepted propagation increments existing debug telemetry after taint is
confirmed. Coarsening, range tails, unsupported concat length, contention,
capacity, and partial fanout use only names accepted by the shared IAST
telemetry specification; otherwise they use bounded debug diagnostics. Soak
tests verify roots, values, stale entries, charges, anchors, and counters return
to baseline.

## 7. Validation matrix

Orchestrion tests cover schemas, invalid fields, stable hashes, pre-filters,
proxy data, generated-source goldens, local homonyms, maximal selection,
constants, parentheses, aliases, imported defined types, generics, every slice
bound, every conversion allow/exclusion context, and stale build-cache behavior.

Woven dd-iast-go fixtures cover concat 2/4/6/16, untyped constants, side effects,
panics, multiple sources/owners, and range clipping; every string/byte slice
shape, empty/one-byte windows, UTF-8 mid-byte boundaries, invalid UTF-8, and
panic identity; conversion round trips, defined types, generic helpers, alias
behavior, and zero wrappers in excluded contexts.

Conditional append/copy fixtures additionally cover single evaluation and panic
order, nil and zero-length destinations, in-place growth, reallocation,
registered and unregistered interior aliases, source-only owners, unmanaged
destinations, capacity boundaries, partial and zero copy, untainted overwrite,
both overlap directions, two concurrent successful captures on disjoint and
overlapping windows, publication reordering, pre-capture contention, panic after
reservation, direct index/slice assignment invalidation, saturation, generation
invalidation, and stack-local escape regressions.

Run ordinary and woven suites, race, vet, checklocks, `GODEBUG=checkptr=2`,
escape analysis, import-cycle checks, retained-memory checks, and dependency
closure audits.

## 8. Performance checkpoint

Use at least twenty one-second idle-machine samples with benchstat intervals and
a paired-bootstrap 95% upper bound. Measure concat 2/4/6/16, defined concat 4,
string slice, byte slice, full byte slice, and both conversions under disabled,
enabled-no-active, sampled-out, active-clean, and sampled-tainted states.
Conditional append/copy get the same matrix for in-place append, reallocating
append, slice append, byte/string append, slice copy, and byte/string copy.

Below 80 ns, estimate and upper bound may add at most 4 ns. At or above 80 ns,
both may add at most 5%. Disabled and active-clean local paths add no
allocations. Maximal concat keeps the baseline allocation count. Repeat
sampled-out HTTP and a concat-heavy handler; use the 2% median gate and present
statistical uncertainty explicitly, as approved for Phase 5.

## 9. Commit boundaries

1. Orchestrion object resolution, typed proxy support, and golden proof API.
2. Orchestrion `builtin-call` and overload-shape tests.
3. Orchestrion bounded maximal concat matcher and generated-IIFE tests.
4. Orchestrion slice and allocation-preserving conversion matchers/tests.
5. dd-iast-go pseudo-version/tool pin, with no operator aspects enabled.
6. concat/slice/conversion primitives and byte-level oracle tests.
7. concat/slice/conversion aspects, woven fixtures, telemetry, and benchmarks.
8. append/copy pre-mutation feasibility plan, proof, critic, and user checkpoint.
9. if approved, append/copy store API, primitives, aspects, and benchmarks.
10. README, Phase 6 exit evidence, and published Orchestrion release pin.

Each repository uses separate clean Jujutsu changesets and its own validation.
The Orchestrion repository documentation is read before modifying it.

## 10. Stop conditions

Stop for user review if typed proxy data cannot reach advice; generated code
evaluates an expression twice; an untyped or defined type changes; a panic or
allocation changes; maximal concat is not one operation; conversion exclusions
are incomplete; any local estimate or upper bound fails; or a published
Orchestrion version cannot carry the APIs. Append/copy additionally stop if a
managed mutation can escape invalidation, an unmanaged allocation would be
retained, zero-length identity is unsound, or stack escape changes. Runtime
hooks are not a fallback.
