# Plan: Taint Tracking — Basic API (Phase 1)

## Status

- **Phase:** 1 of 2 — core data model + minimal propagation API.
- **Explicitly out of scope:** orchestrion aspects, instrumentation wiring,
  sources/sinks for specific vulnerability types, telemetry. These come in a
  later phase that builds on the API defined here.
- **Reference:** the Java implementation in `../dd-trace-java`
  (`dd-java-agent/agent-iast` and `internal-api/.../api/iast`). This document
  adapts that model to Go; it is not a literal port.

## Background

Taint tracking is the backbone of IAST (see `README.md`):

1. Values from untrusted **sources** are **tainted**.
2. Taint is **propagated** as values are combined/transformed.
3. Sanitizers place **marks** that vouch the value is safe for a specific
   operation.
4. A tainted value reaching a dangerous **sink** without the matching mark is
   reported as a **vulnerability**.

This phase delivers steps 1–2 (and the marking primitive for step 3) as a
reusable API in the `taint` package. Sources, sinks and marking call-sites are
wired in Phase 2.

## Operating Constraints (from `AGENTS.md`)

This code runs inside customer hot paths. The design MUST:

- **Never panic** — every public entrypoint recovers/guards and degrades to a
  no-op rather than propagating failures into the host.
- **Never block** — drop data under load instead of waiting on locks/GC.
- **Bound memory** — a hard cap on retained taint metadata that is never
  exceeded; saturation drops data.
- **Gate expensive work behind a cheap check** — every operation begins with
  `CanBeTainted(value)` before touching the store.
- **Preserve provenance** — when data *is* tracked, ranges/sources stay
  accurate so findings are trustworthy.

## The Central Problem: Go Has No String Identity

The Java engine keys taint metadata on `String` **object identity**
(`System.identityHashCode`) and holds objects via `WeakReference`. Go has no
equivalent:

- `string` is an immutable **value** — a `(data *byte, len int)` header copied
  freely. Two equal strings may or may not share a backing array; identical
  content can come from unrelated sources.
- There is no per-object header to attach metadata to, and no stable identity
  hash.

### Decision: identity = `weak.Pointer` (object + offset), bucketed by address

We identify a tainted value by a **`weak.Pointer` made from `unsafe.StringData(s)`**,
and bucket it in the hash table using `(addr, len)` purely as a hash:

- `unsafe.StringData` returns the pointer to the first byte; for a substring
  `s[i:j]` the pointer is advanced, so the *offset* is part of the identity.
  Per the `weak` docs, weak pointers "map to objects and offsets within those
  objects, not plain addresses," so distinct offsets in the same backing array
  are distinct identities — exactly what we want for substrings.
- **The match key is weak-pointer equality, not the raw address.** Within a
  bucket, an entry matches a query iff their `weak.Pointer` values compare equal
  *and* `Value() != nil` (still alive). Raw `(addr, len)` only chooses the
  bucket; collisions there are harmless.
- **GC-reclaim-then-address-reuse is handled by `weak`, not by us.** The docs
  guarantee that a weak pointer created from a *new* object does not compare
  equal to one from a reclaimed object, even at the same address (the runtime
  tracks object generation, not address). So an unrelated allocation that reuses
  the freed backing array of a former tainted string will **not** spuriously
  match — the old entry's `Value()` is already `nil` and its weak pointer is a
  different identity. This removes the pointer-reuse false positive entirely for
  the GC case.
- A freshly allocated string with the same *content* but a different backing
  array is a different object → different weak identity → correctly untainted.
- **Empty / zero-length strings are never tainted** (no meaningful identity;
  also covered by `CanBeTainted`).

### Residual risk: in-place reuse of a live backing buffer

`weak.Pointer` distinguishes object *generations*, but **not** in-place reuse of
a buffer that is never reclaimed. The problematic pattern:

```go
buf := make([]byte, 256)        // long-lived, reused
n := readUntrusted(buf)
tainted := unsafe.String(&buf[0], n)  // taint this
// ... later, SAME buffer, no reclamation ...
m := readTrusted(buf)
fresh := unsafe.String(&buf[0], m)    // shares object+offset identity!
```

Here `buf` stays reachable, so the weak pointer for `fresh` compares **equal**
to `tainted`'s — taint aliases onto unrelated (possibly trusted) content. This
is the same hazard as `[]byte` in-place mutation, and `weak` does not save us.

For Phase 1 this is an **accepted, documented limitation**: zero-copy
`unsafe.String` over a recycled buffer is an unusual, low-level pattern, and
normal `string` allocation (which copies) is unaffected.

**Targeted mitigation (Phase 2 instrumentation, API hook in Phase 1):** the
`unsafe.String(ptr, len)` call is the precise moment a new logical string is
minted over that memory. If orchestrion hooks those call sites, the hook can
synchronously **evict any existing taint entry for the resulting
`(object+offset)` identity** at construction time — before any code can query the
new value. The new string then starts untainted (correct: taint is opt-in via
sources, so genuinely untrusted content is re-tainted by a source call). This
turns the silent false positive into correct behaviour wherever the constructing
code is instrumented. Boundaries:

- Only covers instrumented construction sites; zero-copy `unsafe.String` in
  un-instrumented third-party/stdlib code remains exposed.
- Covers `unsafe.String` construction only — **not** arbitrary `[]byte` in-place
  mutation via `b[i] = x`, which is far too hot to hook per write.
- Requires a Phase-1 API primitive the instrumentation calls (see `Untaint`
  below); the actual call-site weaving is Phase 2.

Other mitigation options (content fingerprint stored alongside the entry, or
refusing to match when a cheap length/hash check disagrees) are noted under
Future Work — each trades hot-path cost for precision.

### Extending identity to `[]byte`

Untrusted data almost always enters a Go program as `[]byte` first (a socket /
file / body is read into a buffer) and is *then* converted to `string`. Taint
tracking is useless if it cannot follow that path, so `[]byte` is a first-class
tracked type in Phase 1.

A `[]byte` reduces to the **same identity scheme** as a string:
`weak.Make(unsafe.SliceData(b))` for the object+offset, with `len(b)` for the
bucket hash. The store therefore needs **no type discrimination** — every entry
is "a `weak.Pointer[byte]` + length," whether it came from a string or a slice.
Subslicing `b[i:j]` advances the data pointer and changes the length, exactly
like substringing.

**The string↔[]byte boundary needs explicit propagation.** A standard
`string(b)` or `[]byte(s)` conversion **copies** into a fresh backing array, so
the result has a *different* identity and would lose taint. The conversion is a
propagation point: ranges copy 1:1 (same length, same coordinates). Phase 1
exposes this (see `TaintIfTainted` / the `OnBytesToString` / `OnStringToBytes`
helpers). The source instrumentation taints `buf[:n]` after a read; the
conversion then carries taint into the resulting string.

**Mutability makes `[]byte` tracking inherently best-effort.** Unlike immutable
strings, slices are mutated in place (`b[i] = x`), grown (`append`, which may
reallocate → new identity, or grow in place → changed length → changed
identity), and copied into (`copy`). Any of these can invalidate position-keyed
ranges, and per-element writes are far too hot to hook. Consequences:

- Source-level `Taint`/`TaintRange` on a slice use **replace** semantics (set,
  not merge), so re-reading into a pooled/reused buffer and re-tainting cleanly
  overwrites stale taint rather than accumulating it — important because servers
  reuse read buffers across requests (`bufio`, buffer pools), reproducing the
  live-buffer aliasing hazard described above.
- Accurate propagation through `append`/`copy`/reslice needs Phase-2
  instrumentation hooks; arbitrary in-place mutation is an accepted blind spot.

> Arbitrary objects (Java's `taintObjectDeeply`, `Taintable`) remain deferred;
> Phase 1 covers `string` and `[]byte` only.

## Storage Model

### Decision: a single global, capacity-bounded, weak-keyed store

Most propagation points (e.g. an instrumented `a + b`) have **no
`context.Context`**, so a per-request/context-threaded store cannot cover
value-level propagation. We therefore use **one process-wide store**, mirroring
Java's *global* `TaintedMap` (the `buildWithPurge` variant), and handle
per-request *reporting* scope separately in Phase 2.

Key properties:

- **Open, fixed-capacity hash table** of intrusive bucket chains. Capacity is a
  power of two; index = `hash & mask`. No rehashing/growth — capacity is the
  memory bound.
- **Weak references** to the tainted value via `weak.Pointer[...]` (Go 1.24+,
  available on this module's `go 1.25`). The store never keeps a customer value
  alive.
- **Eviction via `runtime.AddCleanup`**: when the tracked value is collected,
  the cleanup unlinks its entry. Combined with lazy skip-dead-on-traversal, this
  bounds staleness without a scheduler. (A generational/age-based purge like
  Java's `DEFAULT_MAX_AGE` is a Future Work option if cleanup latency proves
  insufficient.)
- **Flat-mode overwrite under pressure**: when a bucket exceeds
  `maxBucketSize`, a new insert overwrites the bucket head rather than growing
  the chain — drops data instead of unbounded growth (matches Java's
  `DEFAULT_MAX_BUCKET_SIZE`).
- **Non-throwing, non-blocking concurrency**: reads/writes are safe to lose
  under contention. Use sharded locks or atomics; never block a customer
  goroutine. Lost puts are acceptable.

### Capacity / cost-control constants (tunable, Java-derived defaults)

| Constant | Default | Meaning |
|---|---|---|
| `DefaultCapacity` | `1 << 14` (16384) | hash-table buckets (power of two) |
| `MaxBucketSize` | `10` | chain length before flat-mode overwrite |
| `MaxRangeCount` | (Java: `Config.getIastMaxRangeCount`) | max ranges retained per value |
| `MaxValueLength` | (Java: truncation length) | cap on stored value snapshot used for reporting |

All are package-level vars/consts so Phase 2 / config can override them.

## Core Data Model

Package `taint`. All types are designed to be allocation-light and to share
immutable range slices by reference (copy-on-write semantics).

### `Source`

Provenance of a tainted span.

```go
type Source struct {
    Origin OriginType // byte-sized enum, e.g. http.request.parameter
    Name   string     // optional: parameter/field name
    Value  string     // optional snapshot of the originating value (truncated to MaxValueLength)
}
```

- `OriginType` is a `byte` enum mirroring Java's `SourceTypes` (`None = -1`,
  request parameter/header/path/body, etc.). Only the handful needed to exercise
  the API ship in Phase 1; the full set lands with sources in Phase 2.
- **`Value`/`Name` must not strong-reference the tainted value.** A plain
  `string` field that aliases the originating value holds a strong reference to
  its backing array. Because the `Source` is reachable from the global store via
  its `Range`, that would **pin the tainted value alive** — the `weak.Pointer`
  never goes nil, `runtime.AddCleanup` never fires, and the "bounded store"
  becomes an unbounded leak of request data. So we cannot just keep the string.
  Two correct options:
  1. **Copy (Phase 1 choice):** store `strings.Clone(value[:min(len,MaxValueLength)])`
     so the `Source` owns an independent, length-bounded backing array. Cost: a
     one-time allocation + copy of ≤ `MaxValueLength` bytes, paid only at *source*
     time (request-entry boundaries), **not** on every propagation — propagation
     copies the `[]Range` slice, which shares the same `*Source`, so no
     re-snapshot occurs. Memory is bounded by `MaxValueLength × store capacity`.
     The downside is that this bounded copy is retained for the entry's lifetime.
  2. **Weak reference (deferred, mirrors Java):** keep `weak.Pointer[byte] +
     length` for the value and materialize a snapshot lazily at report time via
     `unsafe.String`, reporting a "garbage-collected" placeholder if the
     referent is gone. No copy, does not pin the value, but more complex and
     subject to the same in-place-reuse caveat as identity. Listed under Future
     Work as the optimization once reporting lands in Phase 2.

  Phase 1 takes option 1 for simplicity and correctness; the `Value` snapshot is
  only consumed by reporting (Phase 2), so the field exists in the model but its
  capture path is exercised minimally until then.

### `Range`

A contiguous tainted span attributed to one `Source`.

```go
type Range struct {
    Start  int
    Length int
    Source *Source
    Marks  Mark // bitmask of sanitizations applied to this span
}
```

- Immutable by contract. `Shift(offset)` returns a copy (identity when 0).
- `IsMarked(m Mark) bool` → `r.Marks&m != 0`.
- An "unbounded" range (whole value, length unknown) is represented with a
  sentinel length; helper `FullRange` constructs it.

### `Mark`

```go
type Mark uint32
const NotMarked Mark = 0
// per-vulnerability bits, e.g. SQLInjection Mark = 1 << iota ...
```

Bitmask identical in spirit to Java's `VulnerabilityMarks`. A mark on a range
means the relevant sanitizer already ran, so a sink may skip reporting. Full
enumeration ships alongside sinks in Phase 2; Phase 1 defines the type and a few
representative bits.

### `TaintedValue` (internal store entry)

```go
type taintedValue struct {
    ref    weak.Pointer[byte] // identity: object+offset of the data; match key
    length int                // value length (part of bucket hash; not identity)
    next   *taintedValue      // intrusive bucket chain
    ranges []Range            // immutable, capped at MaxRangeCount
}
```

Not exported, and **identical for strings and `[]byte`** — `ref` is built via
`weak.Make(unsafe.StringData(s))` or `weak.Make(unsafe.SliceData(b))`. Matching
compares `ref` for weak equality and checks `ref.Value() != nil` for liveness;
the raw `(addr, length)` is hashed only to select the bucket. Ranges are
truncated to `MaxRangeCount` at construction.

## Public API (Phase 1, minimal)

Exported from the `taint` package. Every function starts with `CanBeTainted`
and is panic-safe. The core functions are **generic over `string` and `[]byte`**
so the same call covers both representations:

```go
// Bytes is the set of tracked value kinds.
type Bytes interface { ~string | ~[]byte }
```

Internally each generic function extracts `(dataPtr, len)` via a type switch on
`any(value)` (`unsafe.StringData` vs `unsafe.SliceData`) and delegates to the
shared store. (Caveat: a defined type whose underlying type is `string`/`[]byte`
won't match the exact-type switch; Phase 1 handles only `string`/`[]byte`
themselves, which is the overwhelmingly common case.)

### Gating

```go
// CanBeTainted is the cheap pre-check gating all expensive work.
// False for empty/zero-length values and (Phase 2) when sampling opts out.
func CanBeTainted[T Bytes](v T) bool
```

### Sourcing (step 1)

```go
// Taint marks the entire value as tainted, attributing it to src.
// Replace semantics: any existing entry for value's identity is overwritten
// (so re-tainting a reused buffer drops stale taint rather than merging).
func Taint[T Bytes](value T, src *Source)

// TaintRange marks value[start:start+length] as tainted (replace semantics).
func TaintRange[T Bytes](value T, src *Source, start, length int)
```

### Queries

```go
// IsTainted reports whether value has any tainted range.
func IsTainted[T Bytes](value T) bool

// Ranges returns the tainted ranges for value (nil if untainted).
// The returned slice is read-only.
func Ranges[T Bytes](value T) []Range

// SourceOf returns the highest-priority source for value (first unmarked
// range, else the first range), or nil if untainted.
func SourceOf[T Bytes](value T) *Source
```

### Propagation (step 2, minimal set)

```go
// TaintIfTainted taints dst when src is tainted, copying src's ranges 1:1.
// Cross-type (D and S may differ), so it doubles as the string<->[]byte
// conversion propagator. Used by transformations that preserve content 1:1
// (including string(b) and []byte(s), where len(dst) == len(src)).
func TaintIfTainted[D, S Bytes](dst D, src S)

// OnBytesToString / OnStringToBytes are named wrappers over TaintIfTainted for
// the conversion call sites, for instrumentation clarity.
func OnBytesToString(result string, src []byte)
func OnStringToBytes(result []byte, src string)

// Concat records that result == left+right, propagating left's ranges as-is
// and right's ranges shifted by len(left).
func Concat(result, left, right string)

// Substring records that result == value[start:start+length], intersecting and
// shifting value's ranges into result's coordinate space.
func Substring(result, value string, start, length int)

// Mark ORs m into every range of value (no-op if untainted). The sanitizer
// primitive for step 3.
func Mark[T Bytes](value T, m Mark)

// Untaint evicts any taint entry for value's identity. Used to reset taint
// state when a new logical value is minted over reused memory — notably by
// instrumented unsafe.String call sites (see the in-place-reuse mitigation
// above). Cheap and non-throwing; no-op if untainted.
func Untaint[T Bytes](value T)
```

This set is deliberately small but exercises every moving part: sourcing
(string and `[]byte`), querying, the string↔[]byte boundary, range copy, range
shift, range intersection, and marking. The full `StringModule` surface
(replace, format, join, trim, split, builder ops, case folding, etc.) and the
`[]byte`-specific operations (`append`/`copy`/reslice) are enumerated in Future
Work and added incrementally.

### Range arithmetic helpers (internal)

Port the essentials from Java's `Ranges`:

- `forSubstring(offset, length, ranges)` — intersect + shift (used by
  `Substring`).
- `copyShift(src, dst, dstPos, shift)` — append shifted ranges (used by
  `Concat`).
- `mergeRanges` / `mergeRangesSorted` — combine while preserving order and the
  `MaxRangeCount` cap.
- `highestPriorityRange` — first `NotMarked` range, else `ranges[0]`.

A `rangeBuilder` accumulator capped at `MaxRangeCount` backs operations that
assemble many ranges.

## Package Layout

```
taint/
  taint.go        // public API (Taint, IsTainted, Ranges, SourceOf, propagation, Mark, CanBeTainted)
  source.go       // Source, OriginType
  range.go        // Range, Mark, range helpers (forSubstring, copyShift, merge...)
  store.go        // global weak-keyed bounded map, identity keying, eviction
  store_test.go
  taint_test.go
  range_test.go
```

`internal/` may host store internals if we want to keep them unexported from the
public `taint` package; Phase 1 keeps them in `taint` as unexported symbols for
simplicity.

## Testing Strategy

Per `AGENTS.md`, tests run under orchestrion and begin with the
`built.WithOrchestrion` skip guard. Phase-1 coverage:

- **Identity & lifecycle:** taint a value, confirm `IsTainted`; drop the
  reference, force GC, confirm the entry is evicted (no leak).
- **Capacity bounds:** insert beyond `MaxBucketSize` / `DefaultCapacity` and
  assert the store never exceeds its bound (data dropped, no panic, no growth).
- **Range math:** table-driven tests for `Concat` (shift) and `Substring`
  (intersection + shift), including partial overlaps and `MaxRangeCount`
  truncation.
- **`[]byte` & conversions:** taint a `[]byte`, confirm `IsTainted`; verify
  `string(b)` / `[]byte(s)` propagation (`TaintIfTainted` / `On*`) carries
  ranges 1:1; verify `Taint` replace semantics clear stale taint on a reused
  buffer; verify a string and a `[]byte` share one store with consistent
  identity.
- **Marks:** `Mark` ORs correctly; `SourceOf` prefers unmarked ranges.
- **Safety:** fuzz/property test that no input causes a panic and that
  `CanBeTainted == false` paths never touch the store.
- **Concurrency:** race-detector test hammering the global store from many
  goroutines; asserts no panic / no deadlock (lost data tolerated).

A microbenchmark (analogous to Java's JMH `TaintedMap*Benchmark`) tracks the
cost of `CanBeTainted`, `Taint`, and `IsTainted` to guard the hot-path budget.

## Risks & Open Questions

- **In-place buffer reuse via `unsafe.String`** (see identity section). `weak`
  handles GC reclamation but not live-buffer overwrite; accepted/documented for
  Phase 1, mitigation deferred to Future Work.
- **Cleanup latency:** `runtime.AddCleanup` runs "some time after" collection.
  If staleness is unacceptable, add an age/generation purge.
- **`unsafe` usage:** `unsafe.StringData` is stable and supported, but pins us
  to the value-header layout; isolate it behind one helper.
- **Tiny/pointer-free batching:** the `weak` docs warn the runtime may batch
  tiny (≤~16 byte) pointer-free objects into one slot, so such a weak pointer
  "may never become nil." String backing arrays are pointer-free, so very short
  tainted strings might evict slowly. Capacity bounds + flat-mode overwrite keep
  this from breaching the memory cap; precision impact to be measured.
- **`[]byte` mutability:** slices are mutated in place (`b[i]=x`), grown
  (`append`) and copied into (`copy`), any of which can invalidate
  position-keyed ranges or change identity. Phase 1 keys `[]byte` by
  `weak.Pointer`+`len` like strings, uses replace semantics on source-tainting,
  and treats arbitrary in-place mutation and un-hooked `append`/`copy` as an
  accepted blind spot (see "Extending identity to `[]byte`").

## Future Work / Phase 2+

- **Full source-type & mark enumerations** matching `README.md` vulnerability
  table and Java's `SourceTypes` / `VulnerabilityMarks`.
- **Complete string-propagation suite:** replace, format/`Sprintf`,
  join, trim/strip, split, repeat, case folding, `strings.Builder` and
  `bytes.Buffer` equivalents.
- **`[]byte`-specific propagation hooks:** `append`, `copy`, reslice, and the
  `bytes` package operations, so taint survives slice growth/mutation where the
  call site is instrumented.
- **Defined-type support:** handle named types whose underlying type is
  `string`/`[]byte` (the generic exact-type switch misses them in Phase 1),
  likely via a reflect-based slow path gated behind `CanBeTainted`.
- **`taintObjectDeeply` analogue:** reflective tainting of struct fields for
  body/JSON sources.
- **Request-scoped reporting context:** bridge the global store to per-request
  finding aggregation via dyngo (the `iast/crypto/hash` package already shows
  the `dyngo.FromContext` + `SpanTag` reporting path).
- **Cost-control / sampling integration:** wire `CanBeTainted` to the sampling
  decision described in `README.md` so untracked requests pay near-zero cost.
- **Generational purge** as a fallback to `runtime.AddCleanup` if needed.
- **Weakly-referenced `Source.Value`:** replace the Phase-1 bounded copy with a
  `weak.Pointer` + lazy materialization at report time (Java-style), removing
  the copy allocation and the retained snapshot.
- **Identity precision hardening:** optionally store a cheap content
  fingerprint (or length-only guard) alongside each entry to defend against
  in-place buffer reuse / `[]byte` mutation, trading hot-path cost for fewer
  false positives.
- **Telemetry** on store occupancy, drops, and eviction (mirrors Java's
  `TaintedObjectsWithTelemetry`).
- **Orchestrion aspects** that invoke this API at string-operation and
  source/sink call-sites (the actual instrumentation wiring).
