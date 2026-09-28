# Plan: allocator-backed taint bits

## Status

- **Phase 0 (theory and proof of concept): done.** The proof of concept (PoC)
  is in [`allocator-taint-bits-poc/`](allocator-taint-bits-poc/). All its tests
  pass on 22 configurations (section 3.2).
- **Critic round 1: done** (GPT-6 Astra, verdict "not solid", 3 blockers, 5
  major, 1 minor). All findings are answered in this version (appendix A). Two
  fixes were proved in the PoC (appendix A, items 1 and 2).
- **Critic round 2: done** (verdict "not solid": 1 blocker, 3 major). All
  findings are answered in this version (appendix B).
- **Critic round 3: done** (verdict "solid after fixes": 3 major, 1 minor).
  All must-fix items are answered in this version (appendix C).
- **Critic round 4: done** (verdict "solid after fixes": 2 major, both
  fixed in this version, appendix D). The critic listed these 2 fixes as the
  only remaining items.
- **User review: done** (section 10). Phase 1 is approved.
- **Phase 1 (production heap bits): in progress.** Steps 1 to 3 of
  section 9 are done. Next: step 4.
- Phases 2 to 4 (stack values, origins and marks, propagation): outline only
  (section 8). Each one gets its own plan after phase 1.

## 1. Goal

Put one taint bit for each heap byte next to the Go allocator metadata:

- bit 0: the byte is not tainted;
- bit 1: the byte is tainted.

The quick check "does this value have taint?" then becomes a few loads and no
lock. It works for any sub-slice or sub-string of a tainted value, because the
bits follow the memory and not a `(pointer, length)` key.

Origins (sources) and marks stay in a separate store (phase 3). The bits only
tell the caller that it must do the slower lookup.

## 2. Theory

The design depends on 6 facts about the Go runtime (go1.26 and go1.27). Each
fact has a test or a compile-time check in the PoC.

1. **The heap is divided into arenas, and each arena has a metadata record.**
   `mheap_.arenas[l1][l2]` points to a `heapArena` (64 MiB of heap on 64-bit
   Linux and macOS, 4 MiB on Windows and 32-bit). `heapArenaOf(p)` finds the
   record in 2 or 3 loads. The runtime already has one lazily allocated side
   bitmap per arena: `heapArena.checkmarks` (GC debug mode). The taint bitmap
   uses the same model: a new field `heapArena.__dd_taint`, allocated off-heap
   on the first taint in the arena (PoC: one flat 8 MiB bitmap for 64 MiB of
   heap; phase 1: small chunks, section 5.4).
2. **The GC does not move heap objects.** An address stays valid until the
   object dies. Thus a bit for each address is a bit for each byte of the
   object.
3. **Heap memory is used again only after the sweeper frees it.** The sweeper
   (`(*sweepLocked).sweep`) runs once for each span in each GC cycle, before any
   allocation from that span. At its start, the mark bits tell which objects
   are dead. A hook at the start of `sweep` clears the bits of the dead objects.
   Then a new object never gets the taint of an old object at the same address.
   This costs nothing on the allocation path (`mallocgc` has no hook).
4. **There are 2 other ways to reuse memory, and both are handled:**
   `freegc` (`GOEXPERIMENT=runtimefreegc`, used by `append`) frees an object
   at once; a hook at its start clears the bits. User arenas
   (`GOEXPERIMENT=arenas`) free a chunk without a sweep; the bits are not
   accepted in user arena chunks.
5. **Only spans with taint need the sweep hook.** A new 1-byte field
   `mspan.__dd_taint` is set when a bit is set in the span. The sweep hook runs
   only when the field is not 0. With no taint in the process ("inert"), the
   only added work is one byte load in `sweep`.
6. **Stack and static memory are not heap spans.** `spanOfHeap(p)` returns nil
   for them, so the bits refuse them. Stacks are allocated from arenas too, but
   their spans are `mSpanManual`; their bits stay 0.

## 3. Phase 0 results (PoC)

### 3.1 What the PoC contains

- `heapbits/orchestrion.yml`: 5 aspects on package `runtime`:
  1. `struct-definition: runtime.heapArena`: field `__dd_taint *__dd_taintBitmap`
     and all injected declarations (bitmap type, set, clear, check, sweep hook,
     compile-time checks, exported function variables);
  2. `struct-definition: runtime.mspan`: field `__dd_taint uint8`;
  3. `(*sweepLocked).sweep`: prepended statements
     `if s := sl.mspan; s.__dd_taint != 0 { __dd_taint_sweep(s) }`;
  4. `freegc`: prepended clear of `[ptr, ptr+size)` when
     `runtimeFreegcEnabled` is true;
  5. `mmap` (only the definitions with a Go body): an injected non-fatal
     allocator and an `init` function that makes it available (critic A.1).
- `heapbits/heapbits.go`: the user API (`TaintString`, `TaintBytes`,
  `ClearBytes`, `IsTainted`, `IsTaintedBytes`, `Stats`).
- `heapbits/*_test.go`: 10 behavior tests (section 3.2).
- `bench/`: benchmarks and raw results (section 3.3).

Bitmap layout: word `k` of the bitmap holds the bits of arena bytes
`[64k, 64k+64)`. All accesses use 64-bit words, so the byte order of the CPU
does not matter. Partial words use `atomic.Or64` / `atomic.And64` (a neighbour
object can use the same word). Full words belong to one range only, so a plain
store is sufficient. The check uses plain loads.

The runtime exposes the functions with the pattern of the dd-trace-go GLS
aspect: the runtime defines function variables with a push `//go:linkname`
(`__dd_iast_heapbits.set`, ...), and `heapbits` declares the same variables
without a value. When the runtime is not woven, the variables are nil and the
API returns "not tainted". The functions take `uintptr` arguments so that the
checked values do not escape to the heap (section 3.4, item 3).

### 3.2 Correctness evidence

Tests (all in `heapbits/`):

| Test | What it proves |
|---|---|
| `TestByteGranularity` | Exact bits for all offsets 0..23 and lengths 1..23, and no effect on neighbour bytes |
| `TestRefusesNonHeap` | Stack, global and read-only memory are refused and never reported as tainted |
| `TestLiveObjectKeepsTaint` | 3 GC cycles do not remove the taint of a live object |
| `TestNoTaintAfterReuse` | 10 sizes from 8 B to 1 MiB, 2000 objects each: 0 new objects get old taint |
| `TestNoTaintAfterReuseNegativeControl` | With the sweep hook off, the same test finds approx. 4000 to 8000 false taints (runs in a child process) |
| `TestTinyAllocatorNeighbours` | Objects of 3 bytes in shared 16-byte tiny blocks keep separate bits |
| `TestCrossArena` | A 192 MiB object: correct bits on the two sides of an arena boundary |
| `TestConcurrentNeighbours` | 8 goroutines set and clear bits in the same words, with a GC loop: no lost update |
| `TestNoTaintAfterFreegc` | With `GOEXPERIMENT=runtimefreegc`: 0 false taints after `freegc` (1000 of 1000 before the hook) |
| `TestFinalizerRevivalKeepsTaint` | An object that a finalizer makes live again keeps its taint (100 of 100 lost before the fix) |

Matrix: all tests pass (`-shuffle=on`) on **go1.26.6, go1.26.8 and go1.27.1**,
each with: default flags, `-race`, `-gcflags=all=-N -l`,
`-ldflags=-checklinkname=1`, `GOEXPERIMENT=nogreenteagc`,
`GOEXPERIMENT=runtimefreegc`, `GOEXPERIMENT=nosizespecializedmalloc`. They also
pass on darwin/amd64 (Rosetta), linux/arm64 and linux/amd64 (containers). The
woven package also builds for linux/386, windows/amd64 and linux/s390x (not
run). The first PoC run also had the dd-trace-go integrations (GLS aspect on
`runtime.g`) in the same build: no conflict.

### 3.3 Performance evidence

Apple M5 Pro, go1.27.1, `benchstat`, 10 process samples per variant,
`-test.cpu=1` for the overhead benchmarks. Raw data: `bench/*.txt`.

**Overhead** (`plain` = no weaving; `inert` = woven, no taint; `active` =
woven, 1 object in 4 tainted):

| Benchmark | plain | inert | active |
|---|---:|---:|---:|
| `AllocChurn/16` (alloc 16 B, ring of 4096) | 8.99 ns | ~ (no difference) | +16% (+1.5 ns) |
| `AllocChurn/64` | 12.2 ns | ~ | +16% |
| `AllocChurn/512` | 92.5 ns | ~ | +10% |
| `AllocChurn/4096` | 159 ns | ~ | +31% (+50 ns) |
| `GC` (full GC, 1 Mi live 64 B objects) | 10.4 ms | ~ | ~ |
| `JSON` (unmarshal + marshal, tainted input) | 1.87 µs | ~ | ~ |

The `active` cost includes the `Set` calls of the benchmark (1 in 4
allocations). Inert: no difference that `benchstat` can detect (all
differences are less than 3%, and they change sign between runs).

**Quick check** (one goroutine unless "parallel"; `map` = a model of the
exact-key index `store.MayContain` of the taint-tracking branch: 256 shards,
`TryRLock`, linear probe):

| Case | 16 B | 256 B | 4096 B |
|---|---:|---:|---:|
| bits, clean value | 2.9 ns | 3.8 ns | 18.6 ns |
| bits, only the last byte tainted | 2.6 ns | 2.9 ns | 2.8 ns |
| bits, sub-string of a tainted value | 2.5 ns | 2.9 ns | 2.8 ns |
| map, miss | 4.1 ns | 4.1 ns | 4.1 ns |
| bits, same value, 18 goroutines (wall time per operation) | 0.20 ns | 0.25 ns | 1.3 ns |
| map, same value, 18 goroutines | 90 ns | 89 ns | 83 ns |
| map, different values, 18 goroutines | 0.29 ns | 0.29 ns | 0.31 ns |
| bits, stack value / literal | 3.2 ns / 2.6 ns | | |
| `Set` | 5.5 ns | 6.8 ns | 57 ns |

What this shows:

- On one goroutine, the bits are approx. 1.5 times faster than the map for
  short values, and slower for long clean values (the cost grows with the
  length: 1 word for each 64 bytes).
- When many goroutines check the **same** value, the map collapses (read-lock
  contention on one cache line: 90 ns); the bits do not.
- The map cannot answer for a sub-string. The bits can, at no added cost.

### 3.4 Problems that the PoC found and fixed

1. `freegc` reuses memory without a sweep. Fix: hook in `freegc`.
2. The sweeper makes objects with a finalizer live again after our hook
   cleared them. Fix: the hook does not clear dead objects that have a
   `_KindSpecialFinalizer` special.
3. A function variable call makes its pointer arguments escape. The first API
   version moved all checked values (also stack buffers) to the heap. Fix: pass
   `uintptr` values and call `runtime.KeepAlive` after `Set` and `Clear`.
4. Byte-wise atomic access was slow (15 ns for a 16 B check). Fix: 64-bit words.
5. The flag in `mspan` was never reset, so spans stayed on the slow sweep
   path. Fix: a reset protocol (section 5.3).

### 3.5 Limits of the approach

- **Memory, not values.** The bits describe bytes. The Go compiler can make
  `[]byte(s)` share the memory of `s` when the slice is not changed. Then both
  have the same bits. This is correct: they are the same bytes.
- **No propagation.** A copy of tainted bytes (`copy`, `string(b)`,
  concatenation) is not tainted. Propagation needs hooks that copy the bits
  (phase 4).
- **Stack values** are refused (phase 2).
- **Memory use (PoC).** The PoC allocates one flat 8 MiB bitmap for each
  arena. This is not acceptable for production (critic A.4): clearing can
  touch every page, the first PoC version used `sysAlloc` (which charges the
  full size to the memory limit), and the bitmaps are never freed. Phase 1 uses small chunks (section 5.4).
- **Allocation (PoC).** `sysAlloc` can exit the process on Linux (`EACCES`,
  `EAGAIN`). The PoC now uses a direct `mmap` call that returns nil on error
  (critic A.1). Phase 1 keeps this.
- **Platforms.** Supported: linux and darwin on amd64 and arm64. All other
  targets compile the woven runtime, but the feature is off (`Set` returns
  false). Phase 1 adds an explicit `GOOS`/`GOARCH` check in the injected
  `init` function, because `runtime.mmap` also has a Go body on some targets
  that are not supported (for example freebsd/amd64). Proved by cross builds for linux/386, linux/s390x, windows/amd64,
  js/wasm and freebsd/amd64.
- **`-race` cells.** The race detector does not instrument package `runtime`
  (`cmd/internal/objabi/pkgspecial.go`). These cells only prove that the woven
  runtime works in race builds. They do not prove the absence of races in the
  injected code.

## 4. Scope of phase 1

In scope:

1. Move the PoC into the repository as a production package.
2. Add the API that phase 3 and phase 4 need (section 5.2).
3. Add the version drift tests and the CI matrix (section 6).
4. Add the micro benchmarks and a 3-variant overhead run (section 7).

Out of scope: stack values, origins, marks, propagation hooks (section 8), and
use of the bits by the `taint` package.

## 5. Phase 1 design

### 5.1 Files

| Path | Content |
|---|---|
| `internal/taint/heapbits/orchestrion.yml` | The runtime aspects (from the PoC) |
| `internal/taint/heapbits/heapbits.go` | Go API over the linknamed variables |
| `internal/taint/heapbits/*_test.go` | Behavior tests (external test package `heapbits_test`) |
| `internal/taint/heapbits/heapbitstest/` | Test knobs and counters of the woven runtime (tests only) |
| `internal/taint/heapbits/drift_test.go` | Source inventory of the runtime (section 6.2) |
| `internal/taint/heapbits/bench_test.go` | Micro benchmarks |
| `orchestrion.tool.go` | Add the import of `internal/taint/heapbits` |
| `benchmarks/overhead/...` | New workloads and the inert variant (section 7.2) |
| `.github/workflows/...` | Matrix job (section 6.3) |

The package is internal: no public API change.

### 5.2 API and contracts

```go
package heapbits

// Enabled reports whether the runtime was woven AND the platform is supported.
func Enabled() bool

// Set taints [p, p+n). All or nothing: it returns false and changes no bit
// when n is 0, p+n overflows, the range is not inside one allocation slot of
// an in-use heap span (stack, global, off-heap, user arena, or a range that
// crosses into a neighbour object), the platform is not supported, the chunk
// quota is reached, or another goroutine is allocating a chunk that the range
// needs (no wait: drop). The range must be the memory of one Go value: inside
// a 16-byte tiny-allocator slot, the runtime cannot check the bounds of each
// value.
func Set(p unsafe.Pointer, n uintptr) bool

// Clear removes the taint of [p, p+n). It never allocates. Non-heap ranges and
// ranges without chunks are ignored.
func Clear(p unsafe.Pointer, n uintptr)

// Any reports whether one byte of [p, p+n) is tainted. Safe for all addresses.
func Any(p unsafe.Pointer, n uintptr) bool

// Next returns the smallest off in [from, n) such that byte p+off is tainted,
// or n. NextClean is the same for a clean byte. In all cases (also without
// weaving), from >= n returns n. Without weaving (or on a platform that is not
// supported), Next returns n and NextClean returns from.
func Next(p unsafe.Pointer, n, from uintptr) uintptr
func NextClean(p unsafe.Pointer, n, from uintptr) uintptr

// Copy makes the bits of [dst, dst+n) equal to the bits of [src, src+n).
// Without concurrent writers, the result is the same as a memmove of the bits:
// overlap (dst == src included) is correct. With concurrent writers to src or
// dst, each destination word is replaced atomically, but there is no snapshot
// of the whole range. All or nothing for dst, with the same failure cases as
// Set; a source that is not heap memory counts as clean. The bits are written
// before the span flag of dst (section 5.5).
func Copy(dst, src unsafe.Pointer, n uintptr) bool

// Helpers for string and []byte: SetString, AnyString, SetBytes, AnyBytes, ...
```

Concurrent operations on overlapping ranges: for each bitmap word, the result
is the result of one of the operations (last writer wins). There is no
torn word, because the feature is on only for 64-bit targets.

### 5.3 Pointer safety and preemption (critic A.2, B.N3, B.N4)

The runtime functions take `uintptr` values, so that the checked values do not
escape (PoC item 3.4.3). A `uintptr` is not updated when the stack moves, and
it does not keep an object live.

**Two parts for each entry point.**

1. **Classifier** (`//go:nosplit`, short, no loop over the bitmap). It decides
   for each pointer argument: "heap memory in one in-use span" or "not heap".
   It uses only `nosplit` or inlined code: an injected `nosplit` arena lookup
   (in place of `heapArenaOf`, which has no `nosplit` directive), `spanOfHeap`
   (already `nosplit`), and atomics. `Copy` classifies **both** pointers here;
   a source that is not heap memory is recorded as "clean" and is not read
   again. A stack address is refused (or read as clean) before the stack can
   move. The linker checks the stack size of this `nosplit` chain (800-byte
   limit); CI builds it also with `-gcflags=all=-N -l`.
2. **Worker** (normal function, called only after the classifier accepted the
   range). The range is heap memory, which never moves, and the Go wrapper
   keeps it live. The worker counts **work units**: one for each bitmap word,
   each slot or directory visited (also empty ones), and each failed CAS.
   After 512 units it runs a **checkpoint**: `if getg().preempt { Gosched() }`,
   only when the context permits it (`gp == gp.m.curg`, `m.locks == 0`,
   `m.mallocing == 0`, `m.preemptoff == ""`; else the loop continues, as the
   runtime code around it would).
   This is an explicit preemption point: without it, a long loop in package
   `runtime` cannot be preempted (runtime code is not an async safe point,
   `preempt.go`), and a call to a small function is not enough (the compiler
   can inline it, and the arm64 back end marks small leaf functions
   `NOSPLIT`, `obj7.go:570-573`). A `Copy` that fails a CAS on one word many
   times runs the checkpoint and then tries again; it never returns false
   after it changed a destination word. The chunk allocation uses a bounded
   number of CAS attempts (4) and then drops, before any bit is changed.

The sweep hook does not use the worker (no preemption point is allowed in
`sweep`). Its cost is bounded by design (section 5.5).

**Liveness.** Every Go wrapper (also `Any`, `Next`, `NextClean`) calls
`runtime.KeepAlive` on its pointer arguments after the call.

**The window in the Go wrapper.** Between the `uintptr` conversion and the
call there must be no call that can move the stack. The compiler loads the
function variable before it lowers the arguments, and async preemption does
not shrink a stack at an async safe point (`stack.go`), so no such call exists
today. CI checks this in the generated code (below).

**Tests.**

- A **stack probe**: a test-only runtime knob records, at classification
  time, whether the classified address is inside the current goroutine stack
  (`getg().stack`). A test passes a stack buffer and requires "inside". It
  runs with `-gcflags=all=-d=maymorestack=runtime.mayMoreStackMove`, which
  moves the stack at every function entry that has a stack check.
- **Negative control** for the probe: a test build variant adds a call with a
  stack check before the classifier. The probe test must then fail.
- **Generated-code check**: CI compiles the woven runtime and `heapbits` with
  `-S` (default flags and `-N -l`). It asserts that each entry point is
  `NOSPLIT`; that every `CALL` in it goes to a `NOSPLIT` function, except the
  one call to its worker after the decision; that each worker contains a call
  to `runtime.Gosched`; and that the wrapper has no `CALL` between the
  conversion and the call of the function variable.
- **Progress test**: 18 goroutines run `Copy` on partial words of one shared
  word, with `GODEBUG=asyncpreemptoff=1`, while the test calls
  `runtime.GC()` in a loop. Each STW must complete in less than 10 ms.

### 5.4 Memory: chunked bitmap and total budget (critic A.1, A.3, A.4, B.N1)

**Layout.** Each arena gets a lazily allocated directory (one slot for each
16 KiB chunk of bitmap; 512 slots = 4 KiB for a 64 MiB arena). A chunk covers
128 KiB of heap. A range that has no chunk has no taint.

**One kind of mapping only: 1 MiB slabs of 64 chunks.** Slabs are the only
memory that the feature maps. A directory uses one chunk (16 KiB; 4 KiB are
used). A **slab descriptor** is permanent: `base` (the mapping) and `free`
(a `uint64` with one bit for each chunk; 1 = free). The descriptors are in a
fixed array in the runtime BSS (1024 descriptors, 16 KiB), so the budget can
be at most 1 GiB. "Mapped bytes" is exactly "number of descriptors in use x
1 MiB".

**Slot encoding.** A slot (the `heapArena` field, or one entry of a
directory) is a `uintptr` accessed only with atomics: 0 = empty, 1 = claimed,
other = `2 + slabIndex*64 + chunkIndex`. The address of the chunk is
`descriptors[slabIndex].base + chunkIndex*16KiB`. There are no raw pointers
in slots, so there is no pointer packing and no tag.

**Get a chunk** (only the worker, on a user goroutine):

1. Scan the descriptors in use; for one with a free bit, clear the bit with a
   CAS on `free` (this makes the chunk owned). At most 4 failed CAS attempts,
   then drop. Recycled chunks are thus used **before** a new mapping.
2. If no chunk is free: become the **refill owner** (CAS of a global flag
   from 0 to 1; if it fails, drop). Reserve 1 MiB in the budget with a CAS
   loop that cannot overflow (`used+1MiB <= budget`, else release the flag and
   drop). `mmap` 1 MiB. On success: add the accounting (below), write the next
   descriptor (`base`, `free` = all bits set except the one for this chunk),
   then publish the descriptor count (atomic store). On failure: release the
   reservation. In all cases, clear the refill flag before return. The owner
   calls no application code and does not block while it holds the flag.
   If it is preempted, the other goroutines only drop the operations that
   need a new slab.
3. Zero the chunk (in batches, with checkpoints), then store its code in the
   claimed slot.

**Total budget.** One global budget in bytes of mapped slabs (default 64 MiB,
maximum 1 GiB). Nothing else maps memory, so the peak of mapped plus reserved
bytes is at most the budget. Recycling changes only the free bits: it never
changes the budget counter, `OtherSys` or `mappedReady`. A budget of 0 turns
the feature off. `heapbits` sets the budget once at init from the IAST
configuration (invalid values: the default); it cannot change after the first
slab.

**Allocation.** Slabs come from a direct `mmap` call (proved in the PoC: it
returns nil on error and never exits; it is injected next to the Go body of
`runtime.mmap`; both the cgo and the non-cgo Linux paths decode the error the
same way). After a successful `mmap`, a short `nosplit` helper adds 1 MiB to
`memstats.other_sys` (with its atomic `add`) and to
`gcController.mappedReady`, the same accounting as `sysAlloc`. Thus
`GOMEMLIMIT` sees the memory. On failure nothing is charged. The feature is
off in ASan and MSan builds (`asanenabled`, `msanenabled`), because `sysAlloc`
also registers memory with the sanitizers and this path does not.

**Bounded atomics only.** The sweep hook uses `Or64` and `And64`, and it
cannot yield. On amd64 they are single `LOCK` instructions. On arm64 without
LSE atomics they are `LDAXR`/`STLXR` retry loops with no progress bound
(`internal/runtime/atomic/atomic_arm64.s:443-461`). Thus the feature is off on
arm64 when `cpu.ARM64.HasATOMICS` is false (the injected `init` checks it, and
`Enabled()` reports it).

**Claim before allocation.** A slot is claimed with a CAS from 0 to 1. Only
the winner gets a chunk; the others do not wait (drop). The winner stores the
chunk code, or stores 0 again on any failure (budget, refill busy, CAS limit,
`mmap` error). The value 1 is never decoded: readers treat it as "no chunk".

**All or nothing.** `Set` and `Copy` first make sure that all chunks for the
destination exist, then write the bits. If one chunk cannot be obtained, they
write no bit and return false. Chunks that were obtained stay (they are empty
and in the budget).

**Chunk recycling.** Let the dead object be `[b, e)` and the chunk be
`[c, c+128KiB)` (aligned in the arena). Only if `b <= c` and
`c+128KiB <= e` (the chunk is fully inside the dead object), the sweeper does
not clear the 2048 words: it stores 0 in the slot, then sets the free bit of
the chunk with one `atomic.Or64` on the descriptor (no loop on amd64 and on
arm64 with LSE atomics; an LL/SC loop on older arm64). A chunk at the edge of
the object is partly cleared (words) and stays. No live object can use a
chunk that is fully inside a dead object. A reader that still has the old slot
value can only be a reader of the dead object, which the API does not permit
(the Go wrappers keep their objects live).

**Largest taintable span.** `Set` and `Copy` refuse a destination in a span
larger than 64 MiB (a drop counter records it). This is a hard maximum in
phase 1: the configuration can make it smaller, not larger. Thus a flagged
span intersects at most 513 chunk slots (512 when aligned), and the sweep work
for one span is bounded (section 5.5).

**Clear without dirty pages.** `Clear` and the sweep hook skip missing chunks
and store a word only if it is not 0. Thus they do not make new dirty pages
(a read can still fault in a zero page).

### 5.5 Runtime side: concurrency and sweep cost (critic A.5, A.6)

**Atomics.** All bitmap word reads use `atomic.Load64` and all writes use
`atomic.Store64`, `Or64` or `And64`. The flag reads in the sweep prologue use
`atomic.Load8`. The PoC used plain loads and stores; phase 1 measures the
atomic version (on arm64, `atomic.Load64` is `LDAR`) and keeps it unless the
check gets more than 20% slower. A change back to plain accesses needs a
written proof in the code.

**Writes.** `Set` uses `Store64` for full words and `Or64` for partial
words; `Clear` uses `Store64` and `And64`. `Copy` needs a replacement of some
bits in a partial word: it uses a `Cas64` loop (`new = old&^mask | bits&mask`),
so that a neighbour writer is never lost. For overlap, `Copy` reads the source
words before it writes a destination word that can overlap them (it goes
backward when `dst > src`), as `memmove` does.

**Flag reset protocol.** Every operation that can add taint (`Set`, `Copy`)
writes the bits, then stores `s.__dd_taint = 1` (atomic) for the span of the
destination. `sweep` stores `s.__dd_taint = 0` (atomic),
clears the dead objects, then checks the bits of the live objects with atomic
loads and stores 1 again if one bit is set. A concurrent `set` on a live object
cannot be lost: its flag store is after the sweep store, or its bits are
visible to the sweep check (Go atomics are sequentially consistent). The live
check has a work limit (default: 1024 words). When the limit is reached, the
flag stays 1. This is always safe: a flag of 1 only costs a sweep hook later.

**Sweep work.** The dead-object pass cannot have a limit (the invariant needs
it). Its cost is bounded:

- a span of small objects is at most 80 KiB (`internal/runtime/gc/sizeclasses.go`,
  1280 words): the pass reads at most these words, and only in chunks that
  exist;
- a large object: at most 64 MiB (section 5.4), thus at most 2 directories
  and 513 slots; for each whole chunk one slot store and one `Or64`
  (recycling); plus at most 2 partial chunks at the ends (at most 4096 words);
- the finalizer check walks the sorted `s.specials` list once with a cursor
  (the PoC restarts from the head for each dead object: O(objects x specials)).

**Latency gate (phase 1).** On the reference CI machine: the sweep hook adds
at most 20 µs for one span in the worst-case benchmarks (7.1), and the STW
rendezvous delay (`/sched/pauses/stopping/gc:seconds`, p99) does not grow by
more than 10% against `inert`.

**No panic, no allocation, no lock in the sweep hook.** Every bitmap index has
an explicit guard, so that a bug gives a missed taint, not a crash. The hook
is `//go:nowritebarrierrec`. It does not call the allocator.

**Specials.** The hook reads `s.specials` without `speciallock`. This is the
same access as the sweep code after it: `addspecial` and `removespecial` call
`ensureSwept` first, so they cannot run during the sweep of the span.

### 5.6 Linkname contract

- The runtime defines `var __dd_taint_api_<name> = __dd_taint_<name>` with a
  push `//go:linkname __dd_taint_api_<name> __dd_iast_heapbits.<name>`.
- `heapbits` declares `var rt<Name> func(...)` with the same linkname and no
  value. Without weaving, the variables are nil.
- The prefix `__dd_iast_heapbits.` has no package path, so it cannot collide.
- Test: all tests also run with `-ldflags=-checklinkname=1`.

## 6. Test surface for new Go releases

The aspects use unexported runtime internals. A new Go release can change them.
Four layers detect this.

### 6.1 Compile-time checks (in the injected code)

The injected declarations assign every runtime function and field that the
hooks use to a variable of the expected type. For example:

```go
var _ func(uintptr) *heapArena = heapArenaOf
var _ func(uintptr) *mspan = spanOfHeap
var _ func(*sweepLocked, bool) bool = (*sweepLocked).sweep
var _ func(unsafe.Pointer, uintptr, bool) bool = freegc
var _ = func(s *mspan) (uint16, uintptr, *special, bool, uintptr) {
	return s.nelems, s.elemsize, s.specials, s.isUserArenaChunk, s.limit
}
var _ byte = _KindSpecialFinalizer
```

A rename or a type change makes the woven runtime fail to compile. The build
of the application fails with a clear message. This is the wanted result: a
silent wrong hook is worse.

### 6.2 Source inventory test (drift detector)

`drift_test.go` parses `$(go env GOROOT)/src/runtime` with `go/parser`
(no weaving needed, it runs in the normal `go test`). It lists:

1. all call sites of `freeSpan`, `freeSpanLocked`, `freeManual`, `freegc`,
   `freeUserArenaChunk`, and all functions that write `freeindex` or
   `allocBits`;
2. the first statements of `(*sweepLocked).sweep` up to the specials loop;
3. the `_KindSpecial*` constants;
4. the body of `markBitsForIndex` and of `gcUsesSpanInlineMarkBits` (mark bit
   layout), `sysAlloc` accounting (`mappedReady`), the `mmap` definitions with
   a Go body and their build constraints, and `spanOfHeap`.

It compares the lists with a golden file for each supported Go minor version
(`testdata/runtime-go1.26.golden`, `...go1.27.golden`). A new minor version
without a golden file, or a difference, fails the test with the diff. A human
then reads the new runtime code and decides if the hooks are still complete.
The test is the forcing function for this review: it is not a proof.

### 6.3 Behavior tests and CI matrix

The PoC tests move to the repository (section 3.2), plus:

- the flag protocol stress test (section 5.3);
- `Next`, `NextClean` and `Copy` tests with all alignments (0..63) and lengths
  across word and arena boundaries;
- a random model test: 10 000 random operations (allocate, taint a random
  range, clear, drop, GC) compared with a reference model that holds, for each
  live object, the expected bits (the objects are held by the test, so they
  stay live; dropped objects are checked by the reuse check);
- a test that `heapbits` works (returns "not tainted") without weaving;
- a test that **fails** (not skips) when the test binary was built with
  Orchestrion (`built.WithOrchestrion`) but `Enabled()` is false on a supported
  platform: a woven build where an aspect stops to match must not pass as
  "all skipped";
- a dead-neighbour test: two objects in the same bitmap word, one live and
  tainted again in a loop, one dead; the sweep clears the dead one while the
  live one gets `Set` calls; the live bits must stay;
- allocation failure tests with a test knob that makes the chunk allocator
  return nil: single, repeated, concurrent; `Set` returns false, no bit
  changes, and the accounting does not change;
- quota tests: same-chunk contention (one winner, others drop), different
  chunks, cross-arena range with one free quota slot (all or nothing), and the
  peak (not only the final) chunk count;
- `Copy` with overlap in the two directions and `dst == src`; concurrent
  partial-word `Copy` with a neighbour writer; a "`Copy` only" destination
  that dies and is reused (the flag must be set by `Copy`);
- slot rollback at each failure point (budget, refill busy, `mmap` error)
  and concurrent slab refill;
- accounting: after success, `runtime.ReadMemStats().OtherSys` and
  `/memory/classes/other:bytes` grow by exactly the slab size; after a
  failure, they do not change;
- chunk recycling: a large tainted object dies, its whole chunks get their
  free bits, the next `Set` gets a zeroed chunk; boundary placement: a dead
  and a live object on the two sides of a chunk boundary (the shared chunk is
  not recycled, the live bits stay); reuse when the budget is fully mapped;
- refill owner: a test knob parks the owner after the reservation; other
  goroutines drop only operations that need a new slab, and operations on
  existing chunks continue; after the release, the flag is 0 on every exit
  path (success, budget, `mmap` error);
- forced interleavings (test knobs that pause at each step of "get a
  chunk" and of recycling) with concurrent `Set`, `Clear` and sweeps;
- the stack probe and its negative control (5.3).

CI job (woven tests), one cell for each combination of:

- Go: go1.26.x (latest patch), go1.27.x (latest patch), **the latest
  pre-release** (`GOTOOLCHAIN=go1.28rc1` when it exists, or `gotip`, allowed to
  fail but reported);
- flags: default, `-race`, `-gcflags=all=-N -l`,
  `-gcflags=all=-d=maymorestack=runtime.mayMoreStackMove`;
- `CGO_ENABLED`: 0 and 1 (Linux has two `mmap` paths);
- `GOEXPERIMENT`: default, `nogreenteagc`, `runtimefreegc`;
- OS/arch: linux/amd64, linux/arm64 (and darwin/arm64 for the default cell);
- build only (feature off): linux/386, windows/amd64, js/wasm, and one
  `-asan` build.

A pre-release failure does not block a merge, but it opens an issue. This
gives time to fix the aspects before the Go release.

### 6.4 Negative controls

Each important hook has a test that proves the test can fail:

- sweep hook off: the reuse test must find false taints (PoC: done);
- `freegc` hook off: the `freegc` test must find false taints (PoC: done by
  hand, to automate with a test knob like `nosweep`);
- finalizer skip off: the revival test must fail (to add, with a knob);
- `nosplit` entry off (test build variant): the `mayMoreStackMove` test of a
  stack buffer must detect the move (to add; if this cannot be made
  deterministic, the disassembly check of 5.3 is the gate).

The knobs are runtime variables that only tests change.

## 7. Benchmarks

### 7.1 Micro benchmarks (`internal/taint/heapbits/bench_test.go`)

From the PoC: `Check` (clean, last byte, middle byte, sub-string, stack,
literal; 16 B, 256 B, 4 KiB; one goroutine and parallel), `Set`, plus `Next`
and `Copy`. The map baseline stays in the benchmark file only, for comparison.

Worst cases for the sweep hook (critic A.7), each measured for `Set` cost and
GC cost separately:

- alternating live and dead small objects, sparse taint (1 in 64);
- large objects of 1 MiB and of 64 MiB (the largest taintable span), aligned
  and not aligned to a chunk, with one late tainted byte, and with taint then
  clear;
- the budget fully used, and many Ps that sweep (recycle) and `Set` (get
  chunks) at the same time;
- taint then clear of live objects (flag stays 1, no bit left);
- spans with many finalizers;
- first-chunk contention (18 goroutines, same chunk) and quota saturation;
- allocation latency (p50, p99) with allocation-driven sweeping, RSS, and GC
  frequency with `GOMEMLIMIT`.

### 7.2 Overhead benchmarks (`benchmarks/overhead`)

Today the runner compares 2 variants: `control` and `iast`. Add a third one:

| Variant | Weaving | Taint |
|---|---|---|
| `control` | dd-trace-go only | none |
| `inert` | dd-trace-go + dd-iast-go | none (`DD_IAST_REQUEST_SAMPLING=0`) |
| `active` | dd-trace-go + dd-iast-go | normal |

Add the PoC workloads `AllocChurn`, `GC` and `JSON` as new benchmarks. Until
the `taint` package uses the bits, `active` taints with a benchmark-only
helper. The runner writes a 3-column `comparison.txt`.

Numeric gates (CI fails if exceeded, on the 10-sample median):

- `inert` against `control`: no statistically significant regression greater
  than 2% on any benchmark;
- `active` `GC`: less than 10% with 25% of objects tainted;
- worst-case sweep benchmarks: the latency gate of section 5.5.

## 8. Later phases (outline, not in this plan)

### Phase 2: stack values

Decision: S1 (section 10). Options that were considered:

- **S1, keep tainted data on the heap.** Runtime functions that
  produce strings or slices (`concatstrings`, `slicebytetostring`, ...) get
  `buf = nil` when one input is tainted, so the result is on the heap. The
  taint-tracking branch proved this in its phase 0 (`runtime-operator-hooks.md`
  section 2.1). Gap: user code that copies tainted bytes into a stack array
  loses the taint.
- **S2, bits for stacks too.** Stacks are in the arenas. Hooks in `copystack`
  (move the bits) and `stackfree` (clear). Problem: a new frame reuses the
  memory of a dead frame and sees its bits (false taint). There is no cheap
  point to clear them. Not recommended.
- **S3, small table for each goroutine.** A fixed table in `runtime.g` of
  `(address, length)` stack ranges, moved by a `copystack` hook, expired when
  the stack pointer is above them. Stale entries are still possible.

### Phase 3: origins and marks

Decision: O1 (section 10). Options that were considered:

- **O1, runtime specials.** A new special kind in `mspan.specials` for each
  tainted object, with a pointer to a bounded off-heap record (ranges, source
  index, marks). The runtime frees it when the object dies (`freeSpecial`
  hook). Exact object lifetime, no weak pointers. Cost: a span lock for add
  and lookup (slow path only).
- **O2, per-span side array.** On the first taint in a span, allocate an
  off-heap array with one `uint32` for each object (index into a bounded
  record table). O(1) lookup without a lock. The sweep hook already visits the
  dead objects and clears their index. Memory: 4 bytes for each object of a
  tainted span.
- **O3, external store** (the current `store` package), with the bits as a
  filter before the lookup. No runtime change, but the store keeps its
  identity and lifetime problems.

### Phase 4: propagation

Use `Copy` in the runtime hooks of `runtime-operator-hooks.md` (concatenation,
conversions) so that results get the bits of their inputs. Then use the bits
in the `taint` package as the first check of every operation.

## 9. Steps and time estimates (phase 1)

1. **(Done.)** Move the PoC to `internal/taint/heapbits`, add the import in
   `orchestrion.tool.go`, pass the existing tests: **0.5 day**. Also done in
   this step: the `Enabled()` function, the platform and sanitizer gate of the
   allocator (3.5), `KeepAlive` in all wrappers (5.3, rule "Liveness"), and
   the test that fails when a woven build on a supported platform is not
   enabled (6.3).
2. **(Done.)** Pointer safety (5.3): classifiers, workers with work units
   and checkpoints, own arena lookup, `KeepAlive`, stack probe and its
   negative control, generated-code check: **2 days**. Notes:
   - `Any` has a `nosplit` fast path for ranges of up to 16 bitmap words
     (about 1 KiB) in one arena; it needs no classification, because the
     bits of stack memory are always 0. Longer ranges are classified, then
     the worker checks them.
   - The negative control of the stack probe forces exactly **one** stack
     move: two moves can give back the first stack (the stack cache reuses
     the last freed stack), and then a stale address looks valid.
   - The generated-code check is the Go test `TestGeneratedCode` (it builds
     the woven runtime with `-S`, default flags and `-N -l`). With `-N -l`,
     calls to `runtime.panicBounds` are permitted (the explicit guards make
     them unreachable, but the compiler does not remove them without
     optimizations); with optimizations, such a call fails the test.
   - Work units also count arenas (with or without a bitmap), not only
     words. The slow path of `Any` stops at the end of the span of `p` (a Go
     value never extends after it), which bounds the work.
   - The checkpoint also checks the P status (`_Prunning`) and the goroutine
     status (`_Grunning`), as `canPreemptM` does, for the runtime hooks of
     phase 4.
   - A **worker probe** (test knob) records whether a worker ran for a stack
     address. `TestNoWorkerForStackAddress` requires that no worker runs
     for a long stack range. This test proves the order "worker after the
     decision", which the generated-code check cannot see.
   - The progress test with `Copy` (5.3) moves to step 6, with `Copy`.
     Step 2 has `TestWorkerCheckpoints` (the workers yield at least once for
     each 512 words when a test knob forces the yield).
3. **(Done.)** Slabs, budget, refill ownership, slot claim protocol,
   accounting (5.4), with the failure, rollback, budget and accounting
   tests: **2.5 days**. Notes:
   - The slab descriptors with their free masks (5.4) are in this step, as
     "get a chunk" uses them. Recycling (the sweeper sets free bits) and the
     zeroing of recycled chunks are in step 4.
   - The directory slot of an arena holds the address of the directory,
     not a code (directories are never given back): one decode less on the
     read path. Chunk slots hold codes. `Any` on 16 bytes: 4.0 ns (flat
     PoC bitmap: 3.2 ns).
   - `heapbits.SetBudget` exists; the wiring to the IAST configuration is
     done when the `taint` package uses the bits (phase 4).
   - Concurrent first writers of one new chunk drop (slot busy), as the
     protocol says: Set never waits. The tests that are not about this get
     their storage first.
   - The storage tests run in a child process with a budget of 32 MiB (a
     heap where no memory had taint). The other tests set the budget to
     1 GiB in `TestMain`: chunks of small objects are never given back, so
     the default budget is used after a few tests.
   - `OtherSys` also changes by other runtime metadata (for example a new
     256 KiB chunk of `persistentalloc`): the accounting tests use a margin
     of half a slab.
4. Chunk recycling (the sweeper sets free bits), zeroing of recycled
   chunks, largest taintable span (5.4), with the boundary and interleaving
   tests (the slab descriptors and the refill-owner tests are in step 3):
   **1.5 days**.
5. Atomics, bounded flag reset, single-walk finalizer check (5.5), with the
   dead-neighbour and flag stress tests: **1 day**.
6. `Next`, `NextClean`, `Copy` (CAS writes, overlap) and their tests:
   **1.5 days**.
7. Random model test and negative control knobs: **1 day**.
8. Drift test with golden files for go1.26 and go1.27: **0.5 day**.
9. CI matrix job: **0.5 day**.
10. Micro, worst-case and 3-variant overhead benchmarks, latency gate:
    **1.5 days**.
11. Full review (code-review skill) and fixes: **1 day**.

Total: approx. 14.5 days. Each step is one commit. Steps 2 to 6 can change
the performance numbers of section 3.3; step 10 measures them again.

## 10. User decisions (Romain)

1. **Phase 1: approved as written.**
2. **Stack values (phase 2): S1**, keep tainted data on the heap. Later
   research (not scheduled): use the bits of the stack arenas too, with a way
   to clear them when a frame is dropped, or a generation counter that detects
   and clears stale bits.
3. **Origins and marks (phase 3): O1**, runtime specials.
4. **Base branch: `main`.**

## 11. Risks

| Risk | Effect | Mitigation |
|---|---|---|
| A new Go release changes a hooked internal | Build failure (compile-time checks) or missed free path (drift test) | Section 6; pre-release CI cell |
| A new reuse path in the runtime that the hooks do not see | False taint on new objects | Drift test; reuse test; random model test |
| A bug in the sweep hook | Fatal error of the host application | No-panic rules (5.3); `nowritebarrierrec`; matrix; stress tests |
| Much taint | Bitmap memory | Total budget of mapped slabs, charged to `GOMEMLIMIT` (5.4) |
| OS refuses memory | Taint dropped | Direct `mmap`, no exit, no charge on failure (5.4) |
| Stack moves during a call | Wrong address checked or tainted | `nosplit` entries, `mayMoreStackMove` cell (5.3) |
| Long sweep of tainted spans | Allocation latency | Chunk skip, zero-word skip, bounded flag reset (5.5); latency benchmark (7.1) |
| Weaving `runtime` | All users rebuild `runtime` | Already the case with dd-trace-go (GLS aspect) |

## Appendix A. Critic round 1 responses

Reviewer: GPT-6 Astra (OpenAI), read-only. Verdict: "not solid".

| # | Severity | Finding | Response |
|---|---|---|---|
| A.1 | BLOCKER | `sysAlloc` can `exit(2)` on Linux (`mem_linux.go:21-32`) and charges `mappedReady` before it knows the result | Accepted. The PoC now uses a direct `mmap` that returns nil on error, injected next to the Go body of `runtime.mmap` (only where it exists; elsewhere the feature is off). Proved: tests pass on darwin/arm64, linux/arm64, linux/amd64; cross builds pass for linux/386, linux/s390x, windows/amd64, js/wasm, freebsd/amd64. Accounting after success (5.4). |
| A.2 | BLOCKER | `uintptr` arguments: no liveness for `Any`; a stack move makes the address stale | Accepted. `nosplit` entries up to the heap decision, own arena lookup, `KeepAlive` in all wrappers, `mayMoreStackMove` test cell (the PoC passes in this mode), disassembly check (5.3). |
| A.3 | BLOCKER | The quota does not bound peak memory (racing first writers each allocate 8 MiB); cross-arena `Set` is not all or nothing; `Set` returns true without a bitmap | Accepted. Claim-before-allocation with a sentinel, losers drop; quota reserved before allocation; preflight of all chunks; `Set` returns the real result (5.2, 5.4). |
| A.4 | MAJOR | Clearing touches untouched pages; `mappedReady` affects the `GOMEMLIMIT` pacer; Windows commits and wasm charges linear memory | Accepted. 16 KiB chunks from slabs, zero-word skip, quota charged to `GOMEMLIMIT` on purpose, feature off on Windows and wasm (5.4). |
| A.5 | MAJOR | Plain loads and stores weaken the protocol; 32-bit tearing; `-race` does not cover `runtime` | Accepted. Atomics for all word accesses and flag reads, measured (5.5); 64-bit only; `-race` limit written in 3.5. |
| A.6 | MAJOR | Non-preemptible sweep work; O(objects x specials) finalizer check | Accepted. Single-walk finalizer check; bounded flag reset (safe direction); chunk and zero-word skip (5.5). |
| A.7 | MAJOR | Benchmarks cover favourable cases; the "worst case" comment is wrong; no dead-neighbour test | Accepted. Worst-case benchmarks and latency measurements (7.1); comment fixed in the PoC; dead-neighbour test (6.3). |
| A.8 | MAJOR | API contracts not specified (overlap, failure, edge cases); platform support; estimates | Accepted. Contracts in 5.2; platform policy in 3.5; estimates changed from 5 to 10.5 days (9). |
| A.9 | MINOR | Drift manifest too narrow; woven tests can pass as "all skipped" | Accepted. Manifest extended (6.2); fail-if-woven-but-disabled test (6.3). |

Items that the reviewer verified as correct: no other reuse path for normal
heap memory (mcache, mcentral, reclaim, large objects, tiny blocks all go
through `sweep`); `markBitsForIndex(0)` at the start of `sweep` selects the
correct mark bits (Green Tea inline or `gcmarkBits`); the mark byte reads are
in bounds; the unlocked `s.specials` read is correct; masks for neighbour
objects in one word are correct; the `Casp1` publication is correct.

## Appendix B. Critic round 2 responses

Reviewer: GPT-6 Astra (OpenAI), read-only. Verdict: "not solid". Status of
round 1 items: A.1, A.5, A.7, A.9 resolved; A.2, A.3, A.4, A.6, A.8 partial
(their open parts are the new items below).

The reviewer checked against the runtime source: the `mmap` return convention
on linux/amd64, linux/arm64 (cgo and non-cgo) and darwin; that `runtime.mmap`
can be called from a user goroutine; that an `init` function in `runtime` is
legal and runs before user packages; that `sysAlloc` accounting is
`sysStat.add` + `mappedReady.Add` (+ sanitizer registration); that the wrapper
has no stack-move point between the function variable load and the call; the
chunk arithmetic.

| # | Severity | Finding | Response |
|---|---|---|---|
| B.N1 | BLOCKER | Directories, slab slack and concurrent slab creation are outside the chunk quota | Accepted. Slabs are the only mappings; directories are carved from slabs; the budget counts mapped slabs and is reserved before `mmap`; one refill owner, others drop (5.4). |
| B.N2 | MAJOR | `Copy` needs masked atomic replacement, overlap rules, flag publication; "snapshot at start" is wrong | Accepted. `Cas64` for partial words, `memmove` direction rule, bits-before-flag for every taint-adding operation, contract changed to "per-word atomic, no range snapshot" (5.2, 5.5). |
| B.N3 | MAJOR | `nosplit` entries must not run long bitmap loops; sweep latency has no gate | Accepted. Classifier/worker split, preemption point every 512 words (5.3); sweep cost bounded by span size and chunk recycling; latency gate (5.5). |
| B.N4 | MAJOR | The `mayMoreStackMove` test can pass with the bug (a stale stack address is refused too) | Accepted. Stack probe at classification time with a negative control; generated-code check of the classifier call graph and the wrapper window (5.3). |
| B.other | — | Test cgo and non-cgo; ASan policy; accounting through `ReadMemStats`; rollback tests; `NextClean` precedence; budget configuration; keep "no plain accesses without a proof" | Accepted: 6.3 (tests, `CGO_ENABLED` cells), 5.4 (ASan/MSan off, budget rules), 5.2 (precedence), 5.5 (rule kept). |

## Appendix C. Critic round 3 responses

Reviewer: GPT-6 Astra (OpenAI), read-only. Verdict: "solid after fixes".
Resolved from round 2: B.N1, B.N2, B.N4 and all "also required" items; B.N3
partial (items C2 and C3). The reviewer confirmed that a chunk that is fully
inside a dead object cannot be used by a live object, that the sweeper can
publish a free chunk without a lock with preemption disabled, that a
preempted refill owner only causes drops, and that `Set` after recycling is
correct when the chunk is zeroed before publication.

| # | Severity | Finding | Response |
|---|---|---|---|
| C1 | MAJOR | The tagged Treiber stack is not a complete protocol (node metadata, tag width, `lfstack` can throw on packing) | Accepted. Replaced by permanent slab descriptors with a free-chunk bit mask; slots store `(slab, chunk)` codes, not pointers; no packing, no tag, no ABA (5.4). |
| C2 | MAJOR | Sweep cost is not bounded: CAS loop in the push; very large objects | Accepted. Recycling is one slot store and one `Or64`; a largest taintable span (64 MiB) bounds the slots for one span; latency tests at 64 MiB, full budget, many Ps (5.4, 5.5, 7.1). |
| C3 | MAJOR | 512-word batches do not bound CAS retries or empty-slot traversal; a small function call is not a stack check | Accepted. Work units count words, slots and failed CAS; explicit `if getg().preempt { Gosched() }` checkpoint; generated-code check for its presence; progress test with `asyncpreemptoff=1` (5.3). |
| C4 | MINOR | Refill and recycling invariants | Accepted. Recycled chunks first; recycling never changes the budget or accounting; refill flag cleared on every exit; tests for a parked owner and a full budget (5.4, 6.3). |

## Appendix D. Critic round 4 responses

Reviewer: GPT-6 Astra (OpenAI), read-only. Verdict: "solid after fixes". C1,
C3 and C4 resolved. The reviewer confirmed that "slot = 0, then `Or64` of the
free bit" has no ownership hole, and that the `Gosched` checkpoint is a valid
point for STW (`goschedImpl` makes the goroutine `_Grunnable`, which
`suspendG` accepts).

| # | Severity | Finding | Response |
|---|---|---|---|
| D1 | MAJOR | On arm64 without LSE, `Or64`/`And64` are LL/SC loops with no progress bound, inside the sweep | Accepted. Feature off when `cpu.ARM64.HasATOMICS` is false (5.4). |
| D2 | MAJOR | The span limit can be configured to 1 GiB, but the analysis and the tests use 64 MiB | Accepted. 64 MiB is a hard maximum in phase 1; an unaligned span intersects 513 slots; tests use aligned and unaligned spans (5.4, 5.5, 7.1). |
