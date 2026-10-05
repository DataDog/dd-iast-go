# Plan: SQL and command injection on the allocator-backed taint bits

## Status

- **State:** draft 5, ready for user review. Critic round 4 (GPT-6 Astra):
  "solid after fixes", 2 major and 1 minor findings, all fixed in this draft
  (appendix D); the critic required no other architecture change.
- **Critic history** (all GPT-6 Astra, maximum effort):
  - round 1: stopped by a gateway error, 4 blockers + 9 major (appendix A);
  - round 2: "not solid", 10 major + 5 minor (appendix B);
  - round 3: stopped by gateway errors after 7 major findings (appendix C);
  - round 4: "solid after fixes", 2 major + 1 minor (appendix D).
- **Base:** this branch (PR #52, `feat(taint): allocator-backed heap taint bits`).
- **Reference:** PR #39 (`feat(taint): detect SQL and command injection`,
  head `58bd751`). In this document, `P/` is the root of the PR #39 tree and
  `G/` is the Go 1.26.6 `src` directory.
- **Research:** tau tasks T1 (sources, sinks, reporting), T2 (propagation
  inventory), T3 (benchmarks and gates), T4.1.1 (critic sub-review).
- **Toolchains:** Go 1.26.x and Go 1.27.x (the same as `heapbits`). The 8
  hooked runtime functions have the same body in go1.26.6 and go1.27.1
  (hash of each function body).

## 1. Goal

Detect `SQL_INJECTION` and `COMMAND_INJECTION` with the same sources,
propagations, sinks and reports as PR #39, but use the heap taint bits of
`internal/taint/heapbits` as the taint storage. Then compare the overhead of
the 2 implementations (time, `B/op`, `allocs/op`) with the PR #39 benchmarks
and gates, on the same machine.

### 1.1 User decisions (Romain)

| # | Decision |
|---|---|
| D1 | Source attribution: each request keeps a small fixed list of sources (origin, name, value). At the sink, each tainted range is matched to a source. |
| D2 | Scope: full parity with PR #39 (sources, propagations, sinks, reporting). |
| D3 | Port the non-propagation code (sinks, evidence, redaction, span reporting, request ownership and sampling) from PR #39. Change only the taint lookup. |
| D4 | Put the propagation in the Go runtime where possible. Hooks in unexported runtime functions are permitted. |
| D5 | **Never instrument the `+` operator or other source expressions (slicing, conversions) with Orchestrion.** Concatenation and conversions are hooked in the runtime functions that the compiler calls. Scope of the rule: it applies to *propagation*. The `function-call`, `method-call` and `function-body` join points that PR #39 uses for sources, sinks and bootstrap (for example the `wrap-expression` on the `os.StartProcess` call in `exec.(*Cmd).Start`) stay. |
| D6 | Bytes that a propagation changes (quote, escape, Unicode case change, JSON escapes) are attributed with a per-request **derived table** (section 4.3). |
| D7 | Body source: up to 8 `(address, length)` pairs of the chunks that `body.Read` filled, used only to locate a match, plus a copy of the first **64 KiB** of body bytes (PR #39 limit), for content match, match checks and the report value (section 4.4). Charged to the owner budget. |
| D8 | Measure the same performance gates as PR #39 and give a comparison. |
| D9 | Accept the inlining loss of the hooked stdlib functions (6.1 rule 3); measure it. Same cost class as PR #39 (its call-site wrappers also replace the inlined calls; it measured Builder +0.96 ns). |

Note: the plan `allocator-taint-bits.md` (section 10, item 3) chose runtime
specials (O1) for origins and marks in a later phase. D1 and D6 replace O1
for this proof of concept. O1 stays a possible later improvement.

## 2. Why the design is simpler than PR #39

The bits describe memory, not values. A sub-string or a sub-slice uses the same
memory, so it has the same bits:

| Operation | PR #39 | This plan |
|---|---|---|
| Windows: `s[i:j]`, `TrimSpace`, `Cut`, `Split`, `Fields`, `bufio.ReadSlice`, `Buffer.Bytes` | One aspect for each form; store lookup with an exact key | Free (no hook) |
| Reader wrappers: `LimitReader`, `TeeReader`, `MultiReader`, `MaxBytesReader` | Reader bindings, guards and tokens (`P/internal/taint/iobridge`) | Free: the bytes that `body.Read` writes are tainted |
| JSON `Decoder`, JSON strings without escapes | Decoder slots and document bindings (`P/internal/taint/jsonbridge`) | Free (alias) + runtime `slicebytetostring` |
| `+`, `string(b)`, `[]byte(s)`, rune conversions | Runtime hooks + bridges + store roots | Runtime hooks that call the bit functions directly |
| Builder, Buffer | Writer store, 3 invalidation aspects | A few stdlib `function-body` hooks |

PR #39 code that is **not necessary**: `internal/taint/store`, most of
`internal/taint/ranges`, `internal/taint/propagation`, `iobridge`,
`jsonbridge`, `writerbridge`, `runtimebridge`, `iast/io`, `iast/bufio`,
`iast/encoding/json`, `iast/propagation` (call-site wrappers), the reader part
of `internal/taint/request`: about 15 000 lines of non-test code.

## 3. Architecture

```text
 HTTP request ──► sources (net/http function-body aspects) ──► heapbits.Set
      │                     │
      │                     └─► owner.sources[] (origin, name, value)
      ▼
 request owner (sampling, permit, span binding)   ◄── ported from PR #39
      │
 application code
      │  windows: free (same memory)
      │  +, string(b), []byte(s), runes, append growth: RUNTIME hooks → bit copy
      │  Builder, Buffer, fmt, strconv, url, json, bufio, io: STDLIB hooks
      │     exact copy → bit copy;  changed bytes → Set + owner.derived[]
      ▼
 sinks: database/sql, os/exec (ported from PR #39)
      │  heapbits.Any(query) ? (cheap gate)
      ▼
 runs = heapbits.Next/NextClean ──► segmentation + attribution (4.5)
      ▼
 evidence + redaction + span annotation (ported from PR #39)
```

## 4. Taint, owners and attribution

### 4.1 Request owner

Port `P/internal/taint/request/{owner,scope,table,source,http,lazy}.go`,
`P/internal/spans/owner.go` and `P/internal/taint/scopebridge` with these
changes:

- `Manager`: keep the bitset of at most 64 permits, the generation, the
  sampling decision (`DD_IAST_REQUEST_SAMPLING`), the
  `DD_IAST_MAX_CONCURRENT_REQUESTS` limit and `sourceMu.TryLock` (drop under
  contention). Replace `store.Owner` with the identity `(index, id,
  generation)` that the manager makes.
- In `scope.go`, delete the store wiring (`store.New`, `BindWriterActive`,
  `BindRuntimeBridge`, `iobridge`). **Keep** the source registrations of
  `init` (`P/internal/taint/request/scope.go:162-177`):
  `httpbridge.Register(...)`, `RegisterLazy(...)` and
  `urlbridge.Register(ManageURLQuery)`.
- Keep `table.go` (fixed table of 256 sources, de-duplication by `(origin,
  name, value)`). `ranges.SourceID` becomes `uint16`.
- The first activation of an owner also sets the sticky gate (5.3), so that
  the reader hooks (6.2) are on before the first body `Read`.

**Owner data lifetime (non-blocking, critic round 2 item 1, round 3 M1).**
Each owner slot has one state word (`atomic.Uint64`: generation, `closing`
bit, accessor count) and one `sync.Mutex` for its mutable data (the ported
source table is not safe for concurrent access,
`P/internal/taint/request/table.go:76-87`, `:154-168`):

- **Every accessor** (reader or writer, on any goroutine: the request, a
  hook on another goroutine, an ownerless sink) first **pins** the slot: it
  increments the accessor count only when the generation is the expected one
  and `closing` is 0 (CAS loop with a fixed number of tries; drop on failure).
- Then every accessor uses `TryLock` on the slot mutex (drop when busy).
  No accessor ever waits, and the acquisition work is bounded (`TryRLock`
  has no fixed retry bound, `G/sync/rwmutex.go:87-109`, round 4 minor 3).
- The accessor unlocks, then unpins (decrement).
- `Finish` sets `closing` and returns at once; it never waits. Cleanup (clear
  the slot data, release the permit) is done only by the one goroutine whose
  atomic transition reaches "`closing` set and count 0" (`Finish` itself when
  the count is already 0, else the last accessor). A slot is not given to a
  new request before it is cleared.
- User callbacks (`Visit*`) never run while a reader count is held: the
  sink copies the attributed segments first (bounded), then releases, then
  calls the visitor.

### 4.2 Sources: taint in place, match on a copy

A source hook calls `heapbits.SetString(value)` (or `SetBytes`) on the value
that the standard library returns (no change of the value), and adds a record
to `owner.sources`:

- `origin`, a copy of `name` (at most 256 bytes), a copy of the value (at most
  64 KiB), and the `(address, length)` of the original value. **All retained
  data are owner copies, charged to the owner budget (4.6)**, so the owner
  never retains application memory, and the match code never reads
  application memory (critic round 2 items 2, 3).
- When `Set` fails (read-only data such as an interned header name, stack,
  budget used), and the hook can replace the returned value, the hook clones
  the value to the heap, sets the bits on the clone, and returns the clone.
  Else the taint is dropped, and a telemetry counter is incremented.
- Source values shorter than 2 bytes or longer than 64 KiB are not tainted
  (PR #39 admission rule, `P/taint/taint.go`).
- `RequestURI`, `URL.Path` and `URL.RawQuery` share bytes. One `Set` taints
  the shared bytes; each source record has its own address range.

### 4.3 Derived table (decision D6)

Each owner has a fixed table of **64 entries**. An entry describes one output
value that a "changed bytes" propagation made:

```text
entry = { address, length,          // of the output value (locator only)
          copy,                     // owner copy of the output bytes (budget)
          segments[≤ 16] = { start, length, source index } }
```

- Writers: the "changed bytes" stdlib hooks (6.3) and the runtime rune
  conversions (5.1, rows 5 and 6). The hook attributes its input (4.5) for
  each owner that has a match, and writes one entry **for each such owner**
  with the segments that belong to that owner. Bytes of other owners are not
  in the entry (they are foreign for this owner).
- Segment rules:
  - **Positional** transforms (ASCII `ToUpper`/`ToLower`, rune conversions):
    each input segment maps to its output positions (exact).
  - **Coarse** transforms (quote, escape, `Map`, Unicode case, JSON escapes,
    generated `fmt` text): for each owner, one segment that covers the whole
    output, with the **first contributing source of that owner** (PR #39
    coarse rule, `P/internal/taint/propagation/string_coarse.go:37-66`).
- When the table is full, the budget is used, the slot is closing, or the
  lock is busy, the entry is dropped: the bits stay, and the sink reports the
  bytes as foreign.
- When a copy of a derived value is copied again (`+`, Builder), the content
  match of 4.5 finds the entry copy.

### 4.4 Body source (decision D7)

- Hooks in `net/http.(*body).Read` (`G/net/http/transfer.go:831`),
  `net/http.(*http2requestBody).Read` (`G/net/http/h2_bundle.go:6543`) and
  `golang.org/x/net/http2.(*requestBody).Read` (h2c server of
  `golang.org/x/net`, used by the PR #39 h2c test,
  `P/iast/net/http/http_test.go:697-712`) call `heapbits.SetBytes(p[:n])`
  after the read.
- `(*body)` is also used for client response bodies
  (`G/net/http/transfer.go:568-578`). Thus `EagerHTTP` registers the body
  object of `r.Body` in the owner. It unwraps `expectContinueReader`
  (`G/net/http/server.go:2043`). The `Read` hook does the work only when
  `activeOwners != 0` and its receiver is a registered body (fixed array of
  64 `weak.Pointer` values, one for each owner slot). The weak pointer does
  not retain the body, and it cannot match a new object at a reused address
  (`G/weak/pointer.go:25-36`) (round 3 M5).
- The owner keeps up to **8** `(address, length, body offset)` pairs of the
  filled chunks (`uintptr`, no reference). They only locate a match: the
  match is accepted only when the sink bytes equal the body copy at the same
  body offset (4.5.1).
- The owner keeps a copy of the **first 64 KiB** of body bytes read (PR #39
  limit), charged to the owner budget: for content match, match checks and the
  report value (truncated by `DD_IAST_TRUNCATION_MAX_VALUE`).
- Body bytes after 64 KiB keep their bits but are foreign at the sink (PR #39
  also stops at 64 KiB).
- The wrappers (`MaxBytesReader`, `LimitReader`, `TeeReader`, `bufio`,
  `io.ReadAll`) need no source hook. `io.ReadAll` and `bufio` need propagation
  hooks for their internal copies (6.2).

### 4.5 Attribution

#### 4.5.1 Runs and segmentation

`heapbits.Next`/`NextClean` give **runs** of contiguous tainted bytes. One run
can contain bytes of several sources (for example `a + b` with 2 tainted
operands). Thus each run is cut into **segments**, from left to right. The
"candidates" are the owner records: sources, derived entries, body.

1. **Locate by address:** find a candidate whose `(address, length)` contains
   the start of the remaining run. Then **check** the bytes: the sink bytes
   must equal the owner copy at the same offset. The segment is the longest
   equal part inside that candidate. A failed check rejects the candidate
   (stale bits, reused address, overwrite).
2. **Content match:** else, find the candidate copy that contains the
   longest prefix of the remaining run (derived entries first, then sources,
   then the body copy). The segment is that prefix. Needed for copies
   (concatenation, Builder, `string(b)`). A match of **1 byte** is valid
   (critic round 2 item 10): the 2-byte rule is for source admission only.
3. A derived candidate gives the source of each part of the segment from its
   own segments.
4. Tie rule: the address match wins; then the longest prefix; then the
   shortest candidate; then the last registered candidate.
5. When nothing matches, the next byte is **foreign**, and the loop continues
   at the next byte. Adjacent foreign bytes are merged.

Only owner copies and the sink value itself (on the sink goroutine) are read.

#### 4.5.2 Bounds and overflow

- At most `DD_IAST_MAX_RANGE_COUNT` (1-64) attributed segments, and a fixed
  budget of 4096 candidate checks for one sink call.
- When a bound stops the loop, **all remaining tainted bytes are foreign**
  (redacted in the evidence), never clean evidence. This keeps the PR #39
  overflow rule (`P/internal/taint/evidence/evidence.go:512-516`, `:557-559`).
- A foreign segment is shown as a redaction marker (PR #39 `Part.Foreign`,
  `P/internal/taint/evidence/evidence.go:62-76`) and is never a source of this
  request.
- The finding is reported only when at least one segment matches a source of
  the owner. Thus bits that stay on reused memory (section 12, R2) do not make
  a report unless their bytes equal a source of the current request.

#### 4.5.3 Owner search without a context

The coarse hooks (6.3), the runtime rune callback (5.1) and ownerless sinks
(`exec.Command` without a context, `P/iast/os/exec/testapp/exec_test.go:101`)
have no owner. They search all active owners (reader protocol of 4.1): address
locators first, then content, with a shared budget of 4096 candidate checks
for one call. They use **every** owner that has a match (one derived entry for
each, 4.3). Ownerless sinks first try the span annotation owner, then report
for the first owner with a match.

#### 4.5.4 Known limit (accepted by D1)

Content match cannot separate 2 requests (or 2 sources) that hold equal
bytes: a copy of B's bytes that are equal to a source of A is attributed to A.
The test of `shared_owner_test.go` is adapted to bytes that differ.

### 4.6 Owner memory budget

Each owner has a byte budget of **256 KiB** for all its copies: source names
and values, the body copy (up to 64 KiB), derived entry copies. When the
budget is used, new copies are dropped (their bits stay; their bytes become
foreign). The owner holds no reference to application memory. With 64 owners,
the copies use at most 16 MiB (PR #39 checks its store against 24 MiB).

### 4.7 Secure marks

PR #39 only carries marks: no production code sets a mark (T1 finding 2:
`MarkAll`, `MarkSource` and `UnsafeFor` have no production caller). Thus marks
are not necessary for parity. The public type `taint.Marks` stays, and
`Marks.Has` always returns `false`. The PR #39 mark tests are dropped (9.2).

### 4.8 Public API (`taint/taint.go`)

Port the PR #39 API: constants, `Source`, `SourceValue`, `Marks`, `Range`,
`TaintString`, `TaintBytes`, `IsTaintedString`, `IsTaintedBytes`,
`VisitString`, `VisitBytes`.

- `TaintString/TaintBytes`: inactive analysis → return the value unchanged.
  Else register the source (4.2) and set the bits in place (clone when `Set`
  fails).
- `IsTainted*` (round 3 M4): `heapbits.AnyString/AnyBytes` is the cheap
  gate; after a hit, the value is tainted only when the attribution of 4.5
  finds at least one source of an **active** owner (owner search of 4.5.3,
  generation-safe). Thus `IsTainted*` returns `false` after `Finish`, as in
  PR #39 (`P/taint/taint.go:155-165`, `P/taint/taint_test.go:72-73`,
  `:152-155`).
- `Visit*`: the segments of 4.5 for the owner of the context. Foreign
  segments are not visited.

## 5. Runtime propagation hooks (decisions D4, D5)

### 5.1 Hooked functions

| # | Runtime function (Go 1.26.6) | Covers | Bit mapping |
|---|---|---|---|
| 1 | `concatstrings` (`G/runtime/string.go:28`) | `a+b+...`, `+=` (via `concatstring2..5`) | Exact: one copy for each tainted operand, at its offset |
| 2 | `concatbytes` (`string.go:84`) | `[]byte(a+b)` (via `concatbyte2..5`) | Exact |
| 3 | `slicebytetostring` (`string.go:139`) | `string(b)`, `Buffer.String`, `fmt.Sprint*`, `strconv`, JSON `string(s)` | Exact |
| 4 | `stringtoslicebyte` (`string.go:224`) | `[]byte(s)` | Exact |
| 5 | `stringtoslicerune` (`string.go:236`) | `[]rune(s)` | Each rune (4 bytes) is tainted when one of its UTF-8 bytes is tainted. + derived callback (below) |
| 6 | `slicerunetostring` (`string.go:260`) | `string(runes)` | The UTF-8 bytes of a rune are tainted when one of its 4 bytes is tainted (PR #39 mapping, `P/_docs/plans/runtime-operator-hooks.md:721-750`). + derived callback (below) |
| 7, 8 | `growslice` (`G/runtime/slice.go:178`) and `growsliceBuf` (`slice.go:511`) | The copy of the old elements of every `append` that grows: Builder and `fmt` buffer growth, `strconv.Append*`, user `append` | Exact: copy the bits of `[oldPtr, oldPtr+oldLen*size)` for element types without pointers |

Not hookable (the compiler emits an inline `memmove`, which is assembly,
`G/cmd/compile/internal/walk/builtin.go:159-230`, `walk/assign.go:460-583`):
`copy`, the appended part of `append(x, y...)`, `make` + `copy`. The standard
library functions that use them get stdlib hooks (section 6). In user code,
these forms lose the taint, as in PR #39.

`slicecopy` runs only in race, msan and asan builds: no hook. `intstring`
(`string(r)`) is a value: no hook (same as PR #39).

**Derived callback of the rune conversions (critic round 2 item 6).** The
bytes of a `[]rune` are never equal to the UTF-8 source bytes, and invalid
UTF-8 becomes U+FFFD. Thus content match cannot attribute them. On the
**tainted path only** (after the context check, after the bits are copied),
hooks 5 and 6 call one leaf callback `propbridge.runeDerived(out, outLen, in,
inLen, kind)` (a function pointer that the runtime reads with one atomic load;
`nil` before `init`: then no call). The callback writes the positional
derived entries of 4.3 (rune index ↔ UTF-8 offsets). The callback runs on the
user goroutine (not g0, no lock, not mallocing), with a per-goroutine guard
that prevents re-entry of the analysis code. The callback is the only call
from the runtime to code outside the runtime.

### 5.2 Hook template (answer to Q-B: variant D)

Reuse the PR #39 "variant D" template (`P/iast/runtime/orchestrion.yml`, header
comment). It was measured and approved (gate off: ≤ +0.54 ns). The bridge
callbacks are replaced by direct calls to the bit functions in the runtime
(`__dd_taint_any`, `__dd_taint_copy`). Thus hooks 1-4, 7 and 8 have no bridge
call and no recursion guard (the bit code does no concatenation, conversion
or `append`). Hooks 5 and 6 have the derived callback above.

```go
// Prepended to runtime.concatstrings (shape only).
if atomic.Load(&__dd_taint_seen) != 0 {        // gate: 1 load + 1 branch
  if gp := getg(); gp.__dd_iast_bypass != 0 {   // inner call of the wrapper
    gp.__dd_iast_bypass = 0
  } else if __dd_iast_ok() {                    // not g0, no lock, not mallocing
    var hit bool
    if buf, a, hit = __dd_iast_concat_hit(buf, a); hit { // nosplit, Any per operand
      return __dd_iast_concatstrings(buf, a)    // buf = nil, call original, copy bits
    }
  }
}
```

- The wrapper sets `buf = nil` when an input is tainted, so the result is on
  the heap (decision S1 of `allocator-taint-bits.md`). For `growsliceBuf`, the
  wrapper calls `growslice` (heap) when the old elements are tainted.
- The wrapper calls the original function through its body-less alias
  (`//go:linkname __dd_iast_orig_concatstrings runtime.concatstrings`) with
  the bypass token on `g`.
- The filter returns its arguments, so no argument is live across the call
  and the gate-off prologue does not change (PR #39 rule).
- Keep the `__dd_iast_ok` context check before any call that has a stack
  check (`morestack` on g0 is fatal).
- Keep the compile-time signature checks, the escape comparison (the escape
  tags of the hooked functions must not change), the gate-off frame
  comparison, and the system-stack tests of PR #39
  (`P/iast/runtime/c4_test.go`, `safety_test.go`, `internal/g0test`).
- Keep the string-to-slice switch `DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED`
  (PR #39): writes into the result of `[]byte(s)` keep stale bits.
- Apply the escape, frame, safety and drift checks to all **8** hooked
  bodies (`growsliceBuf` included) and to `concatstring2..5` and
  `concatbyte2..5` (callers). Add the 8 bodies to the drift golden files
  (`internal/taint/heapbits/testdata/runtime-*.golden`).

### 5.3 Gate (answer to Q-C: sticky flag)

`__dd_taint_seen` is a sticky `uint32`: the set and copy workers store 1 after
the first successful bit change, and the first owner activation stores 1
(4.1), so the reader hooks are on before the first body `Read`. It never goes
back to 0.

A live counter of tainted spans was rejected for this proof of concept
(critic round 1):

- Go 1.26/1.27 `internal/runtime/atomic` has no `Cas8`.
- The sweep hook resets the span flag before its scan and sets it again after
  (`internal/taint/heapbits/orchestrion.yml:1258`, `:1364`). A counter could
  show 0 while live tainted bytes exist.
- The span flag also means "a chunk must be recycled" (`orchestrion.yml:729-740`,
  `:1320-1328`), so it is not an exact "taint is live" signal.

Effect: after the first tainted request, all hooks pay the clean-path cost
(context check + one `Any` per input). This is measured by the
"taint live elsewhere" variant (10.2). A correct reference-counted gate is
a later improvement.

The stdlib hooks read the gate with `heapbits.Live()`: the runtime pushes a
pointer to the gate word (pattern of `internal/taint/heapbits/heapbits.go:40-60`);
`Live()` is 2 loads and is inlinable.

## 6. Standard library propagation hooks

### 6.1 Rules for all stdlib hooks

1. **Imports (critic B1).** Hook code imports only `heapbits` (imports
   `runtime`, `unsafe`) and one leaf bridge `internal/taint/propbridge`
   (imports only `sync/atomic`, `unsafe`). The owner, derived and attribution
   work goes through atomic function pointers in the bridge; the `init` of
   `internal/taint/request` sets them. The pointers take `uintptr` and length
   values, not Go pointers (a pointer passed through a function variable
   escapes, `heapbits.go:36-40`). A test checks that `go list -deps` of the
   bridge contains no hooked package.
2. **Template (critic M1).** `if heapbits.Live() { if __dd_iast_<fn>(...) {
   return ... } }`. `__dd_iast_<fn>` is an injected in-package **twin**: it
   checks `Any` on the inputs (or the destination, 6.3), does the body again
   with the bit operations, and returns `true`; else it returns `false` and
   the original body runs. No `defer`. When the twin must run the original
   body and then look at its output (`fmt.(*pp).printArg`, `fmtString`,
   `fmtBytes`, `doPrintf`), it calls the hooked method once with a bypass
   field that an aspect adds to the receiver struct (`fmt.pp.__dd_bypass`),
   the same pattern as the runtime bypass token; the prologue clears the
   field and runs the original body.
3. **Inlining (critic M2, decision D9).** With one extra call,
   `(*strings.Builder).Write`, `WriteString`, `(*bytes.Buffer).Truncate`,
   `Grow` and `strconv.quoteWith` stop being inlined (go1.26.6 costs 32, 32,
   55, 78, 73; budget 80; each call to a function that is not inlined costs
   57, `G/cmd/compile/internal/inline/inl.go:50-56`). No supported pattern
   avoids this. Accepted by the user; measured by G-A3. A woven
   `-gcflags=-m` test lists the hooked functions that must stay inlinable
   (`fmt.(*buffer).write*`, `(*bytes.Buffer).Reset`, `strings.Clone`,
   `bytes.Clone`). An escape comparison runs for each hooked stdlib function.
4. **No re-entry of analysis (critic round 1 minor 7, round 2 minor 2).**
   The twins call nested stdlib operations normally (for example a twin of
   `strings.Join` writes through `Builder.WriteString`, and that hook
   propagates the bits). Only the **analysis** code (bridge callbacks:
   attribution, derived entries) must not re-enter itself: it uses no hooked
   function and has a per-goroutine guard. Application callbacks (for
   example `strings.Map` mapping functions) run exactly once, as in the
   original body. Tests check both rules.
5. **`uintptr` contract (round 2 minor 3).** A twin passes `uintptr` values
   to the bridge only for memory that it keeps alive with a typed reference
   until the callback returns (`runtime.KeepAlive`). The bridge classifies
   heap memory before any call that can grow the stack, and never saves a
   pointer into a caller stack. Tests: forced GC, stack growth, `checkptr`.
6. **Drift (critic minor 10).** Golden hashes of each hooked stdlib function
   body, and compile-time checks of the unexported fields that the twins use
   (`b.buf`, `b.off`, `dec.buf`, `dec.scanp`, `pp.buf`, `bufio` `r`/`w`). An
   aspect count guard (PR #39 `strings_test.go:25`). With
   `GOEXPERIMENT=jsonv2`, the json hooks do not apply (v1 files have
   `!goexperiment.jsonv2`); the tests skip, as PR #39 `variant_v2_test.go`.
7. **Never hook** a package that `runtime` imports (`internal/stringslite`,
   `internal/bytealg`).

### 6.2 Exact copies and overwrites

| Package | Function (Go 1.26.6) | Gate | Bits |
|---|---|---|---|
| strings | `(*Builder).Write` (`G/strings/builder.go:87`), `WriteString` (`:112`), `grow` (`:66`) | `Any(src)` | Copy. Builder never writes into memory it gave out (`Reset` sets nil, `:59-62`), so the destination has no old bits. |
| strings | `Clone` (`G/strings/clone.go:21`) | `Any(s)` | Copy |
| strings | `Repeat` (`G/strings/strings.go:616`) | `Any(s)` | Skip the read-only fast path (`:640-655`) when `s` is tainted; the Builder hook copies the bits |
| bytes | `(*Buffer).Write` (`G/bytes/buffer.go:193`), `WriteString` (`:205`), `WriteByte`, `WriteRune`, `ReadFrom`, `grow` (`:144`), `growSlice` (`:247`) | `Any(src) \|\| Any(dst)` | Copy only on the bytes that are overwritten (with a clean source, `Copy` clears the destination). The old tail after the slide of `grow` (`:160-166`) is **not** cleared: a value copy of the Buffer can still show it (critic round 2 item 4) |
| bytes | `Clone`, `Join`, `Repeat`, `Replace` (+`ReplaceAll`), `ToValidUTF8` | `Any(inputs)` | Copy |
| fmt | `(*buffer).write` (`G/fmt/print.go:103`), `(*buffer).writeString` (`:107`) | `Any(src) \|\| Any(dst)` | Copy (`%s`, `%v` of strings and `[]byte`, format text, `Errorf`, `Fprint*`); a clean source clears the destination |
| fmt | `(*fmt).writePadding` (`G/fmt/format.go:74-78`) | `Any(buf)` | Copy of the old output into the new buffer (unhooked `make` + `copy`); the padding region is clean (round 3 M2) |
| io | `ReadAll` (`G/io/io.go:709`) | `Live()` only | Copy of each chunk into the final slice |
| bufio | `(*Reader).Read` (`G/bufio/bufio.go:216`), `fill` (`:99`), `ReadBytes` (`:478`) | `Live()` only (a read can create taint, critic round 2 item 5) | Copy after each read and each copy; slide of `fill` (`:101-104`): Copy on the overwritten bytes, no clear of the tail (`ReadSlice`/`Peek` results alias the buffer). Delegated reads (`:113`, `:231`, `:245`) use the **read rule** below (round 3 M6, round 4 item 1) |
| encoding/json | `(*Decoder).refill` (`G/encoding/json/stream.go:148`) | `Live()` only | Copy of the slide (`:151-155`) and of the growth copy (`:161-164`); no clear of the tail; the delegated read (`:167-168`) uses the read rule |
| bytes | `(*Buffer).ReadFrom` | `Live()` only | Each delegated read uses the read rule |

**Read rule** (a delegated `Read` into reused storage `dst`): when
`Any(dst)` is false, call `Read` (the body hook sets new bits). Else, when
`len(dst)` ≤ 64 KiB: allocate a heap shadow of `len(dst)` bytes, `Copy`
the bits of `dst` to the shadow, `Clear(dst)`, call `Read` and get `n`, then
`Copy` the shadow bits back to `dst[n:]` only. Thus `dst[:n]` has only the
bits of the new data, and the untouched tail (and its aliases) keeps its old
bits. When `len(dst)` > 64 KiB, call `Read` with no change (stale bits can
stay; the sink match check of 4.5.1 limits the effect). When `Read` panics,
the panic goes on unchanged; the old bits of the tail are then lost (taint
loss only, never a crash). Tests: zero read and short read into a tainted
`dst` (clean written prefix, tainted tail, the tail of a Buffer value copy
stays tainted), and a panicking reader.
| encoding/json | `valueQuoted` (`G/encoding/json/decode.go:408`) and `,string` path (`:760`) | `Any(item)` | Covers `,string` fields without the string-to-slice switch (critic minor 11) |

### 6.3 Changed bytes (coarse + derived table)

| Package | Function | Rule |
|---|---|---|
| strings | `ToUpper`, `ToLower` (`G/strings/strings.go:687`, `:727`) | ASCII, same length: exact positional copy + derived entry. Else as `Map` |
| strings | `Map` (`:532`), `ToValidUTF8` (`:790`), `(*Replacer).Replace` (`G/strings/replace.go:95`) | Coarse |
| bytes | `ToUpper`, `ToLower`, `Map` | Same as strings |
| fmt | `(*pp).printArg` (`G/fmt/print.go:682`) | When the argument is a tainted string or `[]byte` (also a named type), after the original body: if the path is an **exact copy** (verb `s` or `v`, no `Stringer`/`Formatter`/`error` method), keep the exact bits; else (generated text or method output) **always** coarse on the output span `pp.buf[before:after]` and add the derived entry of the argument's owner, also when the span already has bits from another owner (round 4 item 2). Covers `%T`, `%p` (`:696-705`), `handleMethods` (`:754-761`), and generated text (`%q`, `%x`, `%X`, `%v`/`%d` of `[]byte`) (round 3 M7). Exact copies (`%s`) keep their exact bits. Application methods run exactly once |
| fmt | `(*pp).fmtString` (`G/fmt/print.go:489`), `(*pp).fmtBytes` (`:510-543`) | Same rule for nested values (through `printValue`) |
| fmt | `(*pp).doPrintf` (`G/fmt/print.go`) | When the format string is tainted: coarse on the whole output (PR #39 rule, `P/internal/taint/propagation/string_coarse.go:115-128`) |
| strconv | `quoteWith` (`G/strconv/quote.go:23`), `unquote` (`:391`) | Coarse on the returned string. `appendQuotedWith` is **not** hooked: `fmt` passes its scratch array `intbuf` to it (`G/fmt/format.go:40-51`, `:447-471`), and bits there would taint later clean `%c` output (round 3 M3). `fmt` quote provenance comes from the `printArg`/`fmtString` span rule |
| net/url | `escape` (`G/net/url/url.go:196`), `unescape` (`:106`) | Coarse |
| encoding/json | `unquoteBytes` (`G/encoding/json/decode.go:1193`) (strings with escapes) | Coarse |

**Coarse (critic M3)** = when `Any(input)`: `Set` the **whole** output (also
when a Builder hook already set a part of it), and add a derived entry with
the source of the input (4.3, 4.5.3). The hook sets the bits on the value that
escapes (Go 1.25+ can put small non-escaping `make` results on the stack,
`G/cmd/compile/internal/base/flag.go:189`). This is the PR #39 contract
(`P/iast/propagation/coarse.go:18-46`). JSON **encoding** has no propagation
in PR #39; it has none here.

### 6.4 Clear on release (internal pools only)

`(*fmt.pp).free` (`G/fmt/print.go:161`) clears `pp.buf[0:len)` before the
buffer goes back to the pool. Buffer `Reset`/`Truncate` do **not** clear
(users can alias the memory, and PR #39 `TestBufferCopyResetThenOverwrite`
expects the old view to stay tainted); the next write clears with `Copy`
(6.2).

### 6.5 Sources of `net/url`

`URL.Query()` (`G/net/url/url.go:1144`) has no context. Its values are
sub-strings of `RawQuery` (free) or `unescape` results (6.3). The owner is
found with a fixed per-owner slot that holds a `weak.Pointer[url.URL]` of the
request URL (no retention; no match on a reused address) (round 3 M5).

## 7. Sources, sinks and reporting (port from PR #39, decision D3)

| PR #39 path | Action |
|---|---|
| `iast/net/http/*`, `internal/taint/httpbridge` | Copy. Change `TaintString` calls to 4.2. Drop the `MaxBytesReader` aspect. Add the `Read` hooks (4.4). |
| `internal/taint/request/{http,lazy}.go` | Adapt: `isManagedSource` → "the value is a registered source of this owner (address match)". |
| `internal/taint/request/scope.go` | Adapt: keep the registrations of `init` (4.1). |
| `iast/net/url`, `urlbridge` | Adapt (6.5). |
| `internal/taint/request/lookup.go` | Rewrite on heapbits (4.5). |
| `internal/spans/*` (owner, annotation, tainted, payload, orchestrion, vulnerability) | Copy the PR #39 versions (including the diffs of `annotation.go`, `orchestrion.go`, `vulnerability.go`); `taintstore.MaxOwners` → `request.MaxAnalyses`. |
| `iast/database/sql`, `sqlbridge` | Copy. |
| `iast/os/exec`, `commandbridge` | Adapt: the cheap gate becomes `heapbits.AnyString` for each argument; `store.MaxRootBytes` becomes a local constant (64 KiB). |
| `internal/vulnerability/tainted.go`, `report.go`, `dedup` | Copy; single-owner selection; ownerless rule of 4.5.3. |
| `internal/taint/evidence` | Adapt (heavy): keep `Snapshot`, `Part`, `Source`; new collector input (4.5); remove the multi-owner code. |
| `internal/taint/redaction` | Copy; remove `HasMark`. |
| `internal/model/event.go` | Copy (`MaxVulnerabilities = 64`). |
| `internal/config`, `internal/config/loader` | Adapt: `DD_IAST_MAX_RANGE_COUNT` bounded to 1-64; copy the loader diff (redaction fallback names), the bounds of `MaxConcurrentRequests` and `VulnerabilitiesPerRequest`, the new default regexps and `config.Observe`. |
| `internal/instrumentation/telemetry` | Copy the `CoarsenedPropagation` and `DroppedPropagation` counters (`P/internal/instrumentation/telemetry/telemetry.go:41-44`); add `DroppedSource`. |
| `iast/crypto/*/orchestrion.tool.go`, testapp `orchestrion.tool.go` files | Copy; the testapps also import the propagation packages (PR #39 matrix gap 1). |
| `go.mod` | Add `github.com/DataDog/go-sqllexer v0.2.4` and `golang.org/x/net` (h2c test and hook). |
| `orchestrion.tool.go` | Import `iast/database/sql`, `iast/net/http`, `iast/net/url`, `iast/os/exec`, `iast/runtime`, `iast/propagation`. |

## 8. Package layout (new code)

- `internal/taint/heapbits/orchestrion.yml`: the sticky gate (5.3) and the
  `Live()` pointer push.
- `iast/runtime/orchestrion.yml` + tests: the 8 runtime hooks (5.1). They use
  the bit functions that the heapbits aspects inject, so the 2 aspect files
  must be woven together. `orchestrion.tool.go` imports both; a compile-time
  reference in `iast/runtime` fails the build with a clear message when the
  heapbits aspects are missing.
- `iast/propagation/orchestrion.yml`: the stdlib hooks of section 6.
- `internal/taint/propbridge`: the leaf bridge (6.1 rule 1).
- Ported packages of section 7.

## 9. Tests

### 9.1 Ported and new tests

1. **PR #39 scenario tests** (T1 section 6), with the same names when
   possible:
   - `iast/integration/testapp`: `TestHTTPSourceToSQLPrepareAndExecute`,
     `TestHTTPSourceToCommandAttempt`, the negative controls,
     `TestHTTPTransformedQueryToSQL`,
     `TestHTTPTransformedCommandReportsOnlyOnAttempt`,
     `TestHTTPTransformedSQLBoundArgumentDoesNotReport`, the JSON chains
     (body → `json.Unmarshal`/`Decoder` → SQL), the bootstrap tests,
     `request_event_test.go`, `shared_owner_test.go` (A's report shows B's
     bytes as foreign; the bytes differ, 4.5.4).
   - `iast/database/sql/testapp`, `iast/os/exec/testapp`: keep; replace the
     store constants.
   - Propagation tests from `P/iast/propagation/*_test.go` and
     `P/iast/runtime/*_test.go`: same inputs; assert the exact tainted ranges
     (`heapbits.Next/NextClean`) and the attributed source.
   - HTTP source tests of `P/iast/net/http/http_test.go`, including h2c.
2. **Runtime hook safety:** g0 / signal stack, locks held, `mallocing`, early
   init (before `main`), escape comparison, gate-off frame comparison.
3. **Attribution:** address locate + check, failed check (overwrite of a
   `TaintBytes` buffer, address reuse, 2 registrations at one address),
   content match, 1-byte window → concat → sink, segmentation of one run
   with 2 sources, `ToUpper(a+b)` with 2 sources and with 2 owners, tie rule,
   overflow → foreign, derived table full, byte budget used (short substring
   of a large allocation, large source name), foreign segments, ownerless
   sink, 2 concurrent requests, use after `Finish`, `Finish` with a paused
   reader (returns at once; slot not reused before cleanup).
4. **Propagation edge cases from round 2:** `string([]rune(tainted("\xff\xfe")))`
   → sink with its source; 8 KiB JSON body whose sink uses only a field after
   byte 4096; first small `bufio` read with clean buffers, nested readers;
   `fmt` `%v`/`%d` of a tainted `[]byte`; tainted format string; copied
   `bytes.Buffer` + `Grow` slide (the other copy keeps its taint).
5. **Bits lifetime:** reused `bytes.Buffer`, `fmt` pool, JSON decoder reuse,
   tainted read then `bufio.Reader.Reset(clean)` and decoder retarget
   (`P/iast/encoding/json/decoder_exclusive_test.go:330-350`), clean `%c`
   after a tainted `%q` on the same printer: no false finding.
6. **Round 3 cases:** `Sprintf("%s%1000s", tainted, "x")` (padding growth);
   `%T`, `%p`, a named tainted string with a `String()` method; `IsTainted*`
   is `false` after `Finish`; concurrent source/body/derived writes and
   cross-owner reads under `-race`; a paused writer while `Finish` returns;
   `r.URL` replaced during the request.
7. **Import and inlining guards** (6.1 rules 1, 3), aspect count guard,
   stdlib drift goldens, `uintptr` contract tests (6.1 rule 5).
8. Ordinary, woven, race, `checkptr`, vet, checklocks, gofmt (AGENTS.md).

### 9.2 Deviations from PR #39 (asserted differently, or dropped)

| PR #39 test or behavior | Here | Why |
|---|---|---|
| Coarse whole-value ranges of `fmt.Sprint*` | Exact ranges | `fmt` buffer hooks copy bytes exactly |
| `TestToValidUTF8UsesOnlyContributingProvenance`, `url`, `strconv` coarse ranges | Whole output tainted when the input is tainted | Coarse rule (6.3) |
| `TestBufferPeekOverwrite` (fixture `P/iast/internal/propagationtest/writer.go:42-67`) | Stale bits stay after an unhooked `copy` into the peeked slice | `copy` cannot be hooked (5.1) |
| `/direct-body` (`P/iast/net/http/http_test.go:155-162`, `:736-738`): a direct `Read` is not tainted | Tainted | The body source taints at `Read` (4.4) |
| `io.TeeReader` side writer is never tainted | Tainted when the side writer is a hooked type | The bits follow the bytes |
| `TestReplacerReplacementProvenanceIsUnsupported` | The replacement text of `singleStringReplacer` is tainted when it is tainted | Builder hook |
| Store, reader binding, decoder slot, writer store and mark tests | Dropped | Code not ported (section 2, 4.7) |
| Equal bytes in 2 requests keep separate sources | Not supported | Content match (4.5.4) |
| Body bytes after 64 KiB | Bits stay, but foreign at the sink | Same 64 KiB limit as PR #39 (4.4) |
| User `copy`/`append` of tainted bytes | Taint lost | Same as PR #39 (5.1) |

## 10. Benchmarks and comparison (decision D8)

### 10.1 Gates of PR #39

PR #39 has gates in 2 places: its plans (group A) and the runtime-hook bench
harness `P/.github/runtime-bench.{sh,py}` with `PROFILES` `local` and `ci`
(`runtime-bench.py:104-140`) (group B).

| Gate | Workload | Compare | Threshold (PR #39 source) |
|---|---|---|---|
| G-A1 HTTP sampled out | `HTTPRoundTrip`, sampling 0 | control vs iast | ≤ +3.70 % local, ≤ +6 % ci (`runtime-operator-hooks.md:1189`, `:1368`; `runtime-bench.py` `http` row) |
| G-A2 HTTP sampled | `HTTPRoundTrip`, sampling 100 | control vs iast | record only |
| G-A3 disabled / no request | 21 `Strings*`/`Bytes*`/`Fmt*`/`URL*`/`Strconv*` + `BytesBufferCopies` | control vs iast | < 80 ns: ≤ +4 ns; ≥ 80 ns: ≤ +5 %; +0 allocs; estimate and paired-bootstrap 95 % upper bound (`phase-5.md:113`, `phase-6.md:344-348`) |
| G-A4 active, untainted | `PropagationActiveUntainted/*` | control vs iast | same as G-A3 |
| G-A5 concat chain | `a+b+c+d` | control vs iast | same allocs |
| G-B (runtime) | `P/iast/runtime/bench_test.go:133-240`: `RuntimeOff`, `RuntimeClean`, `RuntimeS2SOff`, `RuntimeTainted`; concat 2/4/6/16 heap and stack; `b2s`, `s2b`, `r2s`, `s2r` | hook vs nohook woven builds, ≥ 8 code placements, ≥ 8 runs, bootstrap CI (`runtime-bench.sh`) | `local` profile shown: off ≤ +2 ns; clean ≤ +3 ns + 1.5 ns/operand; rune clean ≤ +6 ns; s2s-off ≤ +2 ns; tainted ≤ 1 µs and +1 alloc (`runtime-operator-hooks.md` §9.3). The port keeps both `local` and `ci` profile maps |
| G-B N/A rows | `hit`, `full2`, `maycontain*`, `admission` | — | N/A: they measure the PR #39 store |
| G-C (heapbits) | `HeapBits*` | as today (`runner/gate.go`) | as today |
| Sampled tainted sinks | new workloads (10.2) | record only | no threshold (PR #39 rule) |

### 10.2 Runner, harness and workloads

1. **Overhead runner** (this branch): merge the `-sampling` flag of the
   PR #39 runner, the 21 `Strings*`/`Bytes*`/`Fmt*`/... benchmarks,
   `BytesBufferCopies` (`P/benchmarks/overhead/buffer_test.go:22`), and
   `PropagationActiveUntainted/*` rewritten on the public API (a sampled
   request through `httptest`, no internal imports). Put the same rewrite in
   the PR #39 copy, so the workloads are equal.
2. **Taint live elsewhere** variant (critic M9): one environment switch keeps
   an active request that holds a tainted value while the G-A3/G-A4
   workloads run. In this tree, the gate is then on. Run it on both trees.
3. **Sink workloads**, added to both trees (a writable copy of the PR #39
   tree in `$TMPDIR`): `SinkSQL/{clean,tainted,taintedConcat,taintedBuilder,taintedSprintf}`
   (HTTP query parameter → propagation → `db.QueryContext` on a no-op
   `driver.Conn`) and `SinkCommand/{...}` (→ `exec.CommandContext(...).Start()`
   with a missing binary). Setup outside the timed loop; same redaction
   configuration; deduplication off (both runners already do it). A
   validation step asserts exactly 1 vulnerability for each tainted call,
   with the expected ranges and source, in both trees.
4. **Runtime harness:** port `P/iast/runtime/bench_test.go` and
   `P/.github/runtime-bench.{sh,py}`. In this tree, the "nohook" build removes
   the runtime prepend aspects and keeps the heapbits weaving.
5. Add G-A1 to G-A5 to `runner/gate.go` (informative unless `-gate`).

### 10.3 Protocol

- `GOTOOLCHAIN=go1.26.6`, same machine, idle, on power.
- Overhead runner: `-count=20 -benchtime=1s -cpu=1` (PR #39 rule for G-A3/G-A4:
  20 samples of 1 s); sampling 100 and 0; with and without "taint live
  elsewhere". The 2 trees are **interleaved by sample** (a small driver
  script runs one sample of each tree in turn); one control-vs-control row
  checks the noise.
- Runtime harness: `runtime-bench.sh` with its default placements and runs,
  on each tree.
- PR #39 tree: patch `runner/main.go:533` (`git rev-parse` fails on a
  tarball), as the T3 smoke run did.
- Result: one table for each metric (`sec/op`, `B/op`, `allocs/op`):
  workload | gate | PR #39 Δ (CI) | heapbits Δ (CI) | pass/fail for each.
  Each Δ is against the control of the same tree.
- Wall time: about 2 h 30 min for the overhead runs (2 trees × 2 samplings
  × 2 taint variants, 20 × 1 s samples) and about 40 min for the runtime
  harness.

## 11. Steps and time estimates

Times are agent work time, with tests. "Done" = tests pass, gofmt, vet,
checklocks clean. One commit per step (conventional commits). **Each
implementation commit comes after the required multi-agent review of the
`code-review` skill for that step** (round 2 minor 4); step 13 is the final
review of the whole change.

| Step | Work | Estimate |
|---|---|---|
| 1 | PR #39 baseline: writable copy, runner patch, public-API rewrite, new workloads, runtime harness check | 2 h |
| 2 | heapbits: sticky gate, `Live()`, tests | 1 h |
| 3 | Runtime hooks (5.1), safety, escape and frame tests, goldens | 6 h |
| 4 | Request owner (non-blocking lifetime), source/derived/body data, budget, segmentation and attribution, `propbridge`, public API | 8 h |
| 5 | Port reporting: evidence, redaction, spans, vulnerability, dedup, model, config, telemetry | 4 h |
| 6 | Port sources (net/http, x/net h2c, url, body `Read`) | 3 h |
| 7 | Port sinks (sql, exec) | 2 h |
| 8 | Stdlib hooks (section 6), guards and tests | 8 h |
| 9 | Port the scenario tests (9.1) and the deviation tests (9.2) | 5 h |
| 10 | Benchmarks: runner merge, variants, workloads, harness, gates | 4 h |
| 11 | Comparison runs and the result table | 3 h 10 min (mostly machine time) |
| 12 | README and docs | 1 h |
| 13 | Final multi-agent code review, fixes, final validation | 4 h |
| | Per-step reviews (steps 2-10) | +6 h |
| | **Total** | **about 57 h of agent time (7 to 8 working days)** |

Order: steps 1 and 2 in parallel. Step 3 after 2. Step 4 after 2. Steps 5, 6,
7 in parallel after 4. Step 8 after 3 and 4. Step 9 after 5 to 8. Steps 10
and 11 after 9 (step 10 can start after step 1). Then 12, 13.

## 12. Risks

| ID | Risk | Effect | Mitigation |
|---|---|---|---|
| R1 | `Set` refuses read-only, stack, or budget | Source not tainted | Clone fallback (4.2); telemetry counter |
| R2 | Bits stay on memory that a hook does not see (`copy` into a tainted buffer, aliases) | False taint | Clear by overwrite in the hooks (6.2), clear on release of internal pools (6.4); report only with a source match of the owner (4.5.2) |
| R3 | Content match picks the wrong source for equal content | Wrong source in a report | Address match first; tie rule; documented limit (4.5.4) |
| R4 | Attribution cost | Sink and hook latency | Only on the tainted path; budget of 4096 candidate checks; reader protocol drops when busy (4.1) |
| R5 | Sticky gate: after the first tainted request, all hooks pay the clean-path cost | Throughput | Measured ("taint live elsewhere"); counter gate later |
| R6 | A Go release changes a hooked function or field | Build failure or wrong bits | Signature and field checks; drift goldens (runtime and stdlib); supported releases only |
| R7 | The `(*body).Read` hook also sees client bodies | Client data tainted | Pointer registration of the server body (4.4) |
| R8 | Retention | Memory | Owner holds only copies: 256 KiB budget per owner (16 MiB for 64 owners), cleared when the slot is released |
| R9 | Stdlib hooks stop inlining of `Builder.Write*`, `Buffer.Truncate`/`Grow`, `quoteWith` | Cost also with IAST off | Accepted (D9); measured (G-A3) |
| R10 | Address locate on a freed and reused address | Wrong attribution | Byte check against the owner copy (4.5.1) |
| R11 | Runtime → Go callback in the rune conversions | Re-entry, unsafe context | Only on the tainted path, after the context check; guard; safety tests (5.1) |

## 13. Open questions

None for the critic. For the user, at review: accept R5 (sticky gate) as a
known cost of the proof of concept (R9 is accepted: D9).

## Appendix A. Critic round 1 responses

| Finding | Answer |
|---|---|
| Live-span gate can show 0 while live taint exists; no `Cas8` | Sticky gate (5.3) |
| One run can join 2 sources | Segmentation (4.5.1) |
| Equal bytes of 2 requests | Documented limit (4.5.4), test adapted |
| Body chunks are mutable, racy, unbounded | User decision D7 (revised twice): address-only pairs + 64 KiB copy (4.4); byte budget (4.6) |
| Max range count stops the walk | Overflow → foreign (4.5.2) |
| D5 scope | Stated in D5 |
| B1 import cycle | Leaf bridge (6.1 rule 1) |
| M1 no stdlib template | Twin template (6.1 rule 2) |
| M2 inlining | Known cost, guards (6.1 rule 3), R9 |
| M3 coarse `!Any(output)` wrong | Whole output (6.3) |
| M4 clear on rewind breaks tests, stale bits | Clear by overwrite (6.2); release clear only for internal pools (6.4) |
| M5 h2c, `/direct-body`, `expectContinueReader` | 4.4; deviation table (9.2) |
| M6 port gaps | 4.1, section 7 |
| M7 runtime harness | 10.2 item 4 |
| M8 G-A1 label | 10.1 |
| M9 gate-on cost of stdlib hooks | "Taint live elsewhere" variant (10.2 item 2) |
| Minor 1-14 | 10.1, 10.2, 10.3, 6.2 (`Repeat`, `valueQuoted`), 6.3 (`fmtString`), 6.1 rules 4-5, 9.2, section 7 |

## Appendix B. Critic round 2 responses

| # | Finding | Answer |
|---|---|---|
| 1 | `Finish` blocks on readers | Non-blocking state word, last reader cleans up (4.1) |
| 2 | Retained strings and names not charged | All retained data are owner copies, charged; no reference to app memory (4.2, 4.6) |
| 3 | Mutable address matches accept stale bytes | Address only locates; byte check against the owner copy (4.5.1) |
| 4 | Clearing the Buffer slide tail removes alias taint | No tail clear in aliasable storage; copy only on overwritten bytes (6.2) |
| 5 | Entry gate loses the first buffered body read | Reader hooks gate on `Live()` only; first owner activation sets the gate; json growth copy added (5.3, 6.2) |
| 6 | Rune conversions need derived attribution | Runtime derived callback on the tainted path (5.1) |
| 7 | Body fields after 4 KiB lose their source | User decision: 64 KiB body copy (D7) |
| 8 | One derived entry loses exact ranges | Derived entries with segments, one entry for each owner; positional vs coarse rules (4.3) |
| 9 | `fmt` generated text and tainted formats | `fmtBytes` coarse for all generating verbs; `doPrintf` coarse for a tainted format (6.3) |
| 10 | 2-byte match minimum | 1-byte matches valid; 2-byte rule for admission only (4.5.1) |
| m1 | 8 runtime bodies | 5.1, 5.2 |
| m2 | Recursion rule too wide | Rule scoped to analysis code (6.1 rule 4) |
| m3 | `uintptr` contract | 6.1 rule 5 |
| m4 | Review before commits | Section 11 |
| m5 | `local` and `ci` profiles | 10.1 |

## Appendix C. Critic round 3 responses

Round 3 said that the derived segments and the runtime rune callback solve the
main round-2 attribution gaps in principle.

| # | Finding | Answer |
|---|---|---|
| M1 | Owner protocol: reader/writer races, cleanup during a writer | All accessors pin, then `TryRLock`/`TryLock`; one goroutine cleans at "closing + 0" (4.1) |
| M2 | `fmt` padding growth loses bits | `(*fmt).writePadding` exact copy (6.2) |
| M3 | Quote bits in the `fmt` scratch array | No `appendQuotedWith` hook; span rule on `pp.buf` (6.3) |
| M4 | `IsTainted*` lifetime contract | Bits + match with an active owner (4.8) |
| M5 | Strong `*url.URL` / body references | `weak.Pointer` (4.4, 6.5) |
| M6 | Clean reads into reused buffers keep old bits | Clear the destination before each delegated read (6.2) |
| M7 | `%T`, `%p`, methods bypass the `fmt` hooks | `printArg` span rule (6.3) |

## Appendix D. Critic round 4 responses

Verdict: "solid after fixes". Round 4 confirmed the answers M1-M5 of
appendix C and the bypass-field pattern.

| # | Finding | Answer |
|---|---|---|
| 1 | Pre-read clear removes taint of an untouched tail or alias | Read rule: shadow, clear, read, restore the tail only (6.2) |
| 2 | Existing output bits hide the `fmt` argument's owner | Generated or method output always gets the coarse entry of the argument's owner (6.3) |
| m3 | `TryRLock` has no fixed retry bound | One `sync.Mutex.TryLock` for all accessors (4.1) |
