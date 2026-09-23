# Research lessons: go-shadow patched compiler/runtime (orchestrion#858)

Source: `orchestrion@eliottness/iast-testing:experiments/go-shadow/` (README.md, COVERAGE-LEDGER.md,
go-taint-shadow.patch, suite/taint_test.go, fixture/README.md, report/). Condensed verdict table:
`.omo/review/evidence/res-shadow/ledger-verdicts.txt`. All of it is research. It compares two prototypes
on an `os.Getenv("TAINT_PATH")` source and an `os.Open`/`os.OpenFile` sink. dd-iast-go is a third, distinct design.

## What the shadow prototype is
- A patch to Go 1.26.1, labelled `iast-taint-shadow-v28`, gated by `-gcflags=all=-d=taint=1`. It adds about 1.4k lines, mostly
  `runtime/taint_shadow.go` (583) and `cmd/compile/internal/ssagen/ssa.go` (484). It also hooks chan/select (~100),
  Swiss maps, malloc/mheap/mgcsweep/stack/proc, and `string.go`/`slice.go` primitives.
- Each tracked SSA string value carries a runtime `uint8` label. A dense per-arena data shadow also exists: a bitmask with
  one bit per application byte, for heap and stack. It propagates through `concatstrings*`, `slicebytetostring`,
  `stringtoslicebyte`, rune conversions, `growslice`, `slicecopy`, `makeslicecopy`, indexed byte loads and stores, and `clear()`.
  Because the shadow is attached to backing bytes, taint survives every header copy (maps, channels, structs, goroutine args,
  sub-slices) at no per-operation cost.
- The sink scans both the SSA label and the backing-byte shadow. Sweep cleanup and exact-address heap reuse clear the shadow.

## Coverage ledger categories (155 rows; IDs 149-151 are absent)
A. Source, values, calls, control (1-20). B. Strings, bytes, runes, library transforms (21-51).
C. Named/generic types, Builder, Buffer (52-75). D. Channels, selects, maps, closures, concurrency (76-100).
E. Memory lifecycle, capacity, platforms, foreign code (101-120). F. Source/sink/provenance/policy semantics (121-130).
G. Concrete unadapted APIs and regression targets (131-158).
Final tallies: Patched Go 129 Win, 7 Loss, 11 Partial, 8 Not proven. Orchestrion 124 Win, 11 Loss, 15 Partial, 5 Not proven.
The ledger itself warns that the two columns are NOT commensurable. The Orchestrion harness asserts the exact value, exact ranges, and
the complete report multiset. The patched-Go suite asserts only the report COUNT for 107 of its 112 positive cases, and only 5 of them assert
exact ranges. Clean and disabled controls exist for only 29 case descriptors each. Cells without the measured mark are unverified claims.

## What shadow covered that source rewriting did not
- **Indirect source/sink function values (18).** Rewriting needs direct-call join points. The compiler recovers
  `f := os.Getenv` aliases.
- **Implicit/control-flow taint (20).** A synthetic PC-taint SSA variable is joined into assignments and sinks. It is coarse
  (header-only, no byte ranges), and fixture 122 shows it reporting header-only.
- **GC/heap lifecycle (101, 104).** The rewriting registry pinned dirty owners for the process lifetime. Case 104 was downgraded to
  a Loss because the backing array is never swept, which is effectively a leak. The shadow clears on sweep and on exact-address reuse.
- **Code outside the rewrite closure.** This covers fresh allocations in uninstrumented dependencies and prebuilt no-inline functions (51, 117, 118,
  140, 141). Runtime primitives are universal, so propagation does not depend on which package ran. The rewriting column
  won 51 and 141 only through extra root-only summaries.
- **Aliases for free (152-155).** `strings.Cut`, `TrimPrefix`, `Split`, and `regexp.FindString` need no per-API adapter in either
  prototype, because both look up by backing address or range. **dd-iast-go does not**: its key is an exact `(pointer, length, kind)`
  (`internal/taint/store/store.go:41-61`), so it needs a wrapper for every window-producing API.
- Zero-sized channel resource bound (84), independent concurrent registrations (100), and 65,536+ live tainted values (105)
  with no record cap.

## What source rewriting covered that shadow did not
- **Deployability.** It uses a stock toolchain. The shadow requires shipping a forked compiler/runtime and has only been validated on darwin/arm64.
- **Disabled-mode cost (119).** The rewriting column has zero cost when not woven. The shadow compiler gate is inert, but arena shadow memory
  and runtime structures are allocated unconditionally.
- **Lifecycle/policy features.** Request-scoped `StartRequest()` generations (108, Partial). An `Unknown` state after
  saturation (106). Both are Not proven for the shadow.
- **Precision/coverage cells the shadow left Partial.** Named conversion chain (52), Buffer `Read`/`ReadBytes`/`ReadFrom` (73),
  reflection (95, header-only), struct fields (97), stack move and reuse with no fixture (102, 103), `os.OpenFile` (122).
- **Scalars across calls (README boundary).** The interprocedural protocol carries only one string, so byte-at-a-time
  transforms stay clean until they are special-cased (`path.Clean`, `strconv.Quote`, `url.QueryEscape`, and base64 got
  `calleeLSym.Name` guards). Scalar arithmetic does not propagate.
- **Losses shared by both.** unsafe (112), cgo (113), assembly (114), `go:linkname` (115), plugins (116), sink-specific sanitizer
  policy (128), and declassification API (129). Also unproven for both: moving GC, 32-bit, and non-darwin (109-111).

## Measured costs
There are essentially none, and no benchmarks were run. The only data point is fixture `registrcategorreaches65536r`: 65,536 live
tainted values ran in 0.66 s with a peak of about 18 MB and "no slowdown observed". That is a single run with no baseline. The whole Lane B
suite takes about 71 s, which is a test duration, not an overhead measure. The README states that arena shadow memory is unconditional.

## Process lessons worth copying
1. **Reject silent green runs.** The suite preflights `go tool compile -V=full` for the version tag, because an unpatched toolchain
   makes every zero-report fixture pass. `TestFixtureInventory` fails on an empty manifest or a missing `dirtyReports`.
2. **Every positive case needs paired clean-provenance and disabled controls.** Use byte-identical clean literals, so a
   value-matching false positive cannot pass.
3. **Assert the exact value, ranges, and source IDs.** Count-only assertions hid imprecision (runes 25 and control flow 20 are coarse).
4. **Grade the evidence, not the wording.** 90 "Verified" cells turned out to be unmeasured until observation hooks
   (`TAINT_OBSERVED`, `IAST_E2E_OBSERVED`) dumped actual sink reports.

## CHECKS: propagation scenarios to evaluate dd-iast-go against
The source is HTTP request data and the sinks are SQL/exec. "Exp" is the expectation per dd-iast-go README, and application-root direct calls are assumed.
S = supported (must report, exact ranges), U = unsupported (must not crash or false-positive, and may miss), ? = undocumented (verify).
1. Byte-identical clean literal next to a tainted value, and an empty source (2, 3). Exp: no report (identity keys, no value matching). S
2. Local copy, SSA phi, static call, function-value identity call, closure capture, interface dispatch returning the same string (4-7, 15, 16). Exp: S (header copy keeps the key)
3. Recursion, stack growth, deferred named result, panic/recover, address-taken param (8-13). Exp: S (managed heap roots)
4. Callee discards the tainted arg and returns a literal; clean interface receiver (14, 17). Exp: no report
5. Sink reached through a function/method value (`run := cmd.Run`, `q := db.QueryContext`) (18). Exp: exec is S (reported at `os.StartProcess`); SQL via method value is ?
6. Package-global assignment, read in a later request after the owner finished (19). Exp: U (dropped); must NOT report cross-request
7. Implicit/control-flow taint (`if tainted == "x" { q = "..." }`) (20). Exp: U, and must not report
8. `+` chains of 2-16 operands with exact ranges (21), 17+ operands, and `+=` in loops. Exp: 2-16 S; 17+ and `+=` U (no false ranges)
9. Two- and three-index string/`[]byte` slicing (22, 23). Exp: S
10. string->[]byte->string and string->[]rune->string round trips (24, 25). Exp: U (README: string-to-byte creates no root)
11. `append`/`copy`/index writes into `[]byte`, and a clean byte overwriting a tainted byte (26-33). Exp: U, but stale ranges after a write to a tracked window are a documented rule-4 risk; measure how often a clean overwrite still reports
12. Byte/rune scalars through locals, calls, maps, channels (34-36). Exp: U
13. strings/bytes `Clone`, `Replace*`, `Repeat`, `ToUpper`/`ToLower`, `Map`, `Join` (37-45). Exp: S (case conversion and `Map` coarse)
14. `fmt.Sprintf` with a string, and with struct/map aggregates holding tainted fields (46, 47, 97). Exp: string S; aggregates ?
15. `filepath.Join`, `path.Clean` (48, 156). Exp: U
16. `strconv.Quote`, `url.QueryEscape` and their inverses (49, 131). Exp: S
17. Identity through an uninstrumented dependency, versus a fresh allocation in a dependency (51, 117, 118, 140, 141). Exp: identity S, fresh U
18. Named string/byte types and generic `~string` concatenation (52-57, 148). Exp: ? (named types are listed only for JSON)
19. `strings.Builder`/`bytes.Buffer` `WriteString`/`Write`/`String`/`Grow`/`Reset`/`Truncate`/`Next`/`NewBufferString`/`NewBuffer` (58-63, 66-70). Exp: direct calls S
20. Method-value or method-expression `Grow`/`Write`, Builder value copy (64, 65). Exp: U, and must not corrupt state
21. `Buffer.Bytes()` alias receives a dirty or clean write (71, 72). Exp: `Bytes` is untainted and overlapping views are invalidated; verify there is no stale report after a clean overwrite
22. Buffer `Read`/`ReadBytes`/`ReadString`/`ReadFrom`/`WriteByte`/`WriteRune`/`WriteTo`, `io.Copy` into a Buffer, `bufio.Reader.ReadString` (73, 74, 136, 138, 139). Exp: ? (the README table does not list them; `iast/io` and `iast/bufio` exist)
23. Buffered, unbuffered, closed, and select channels carrying a tainted string (76-83). Exp: S by identity; a closed channel yields clean
24. Map assign, lookup, growth, `maps.Clone`, overwrite, delete, `clear`, small-struct keys, tainted key ranged back (85-94, 145). Exp: values/keys S by identity; clean overwrite/delete yields clean
25. `reflect.Value.SetMapIndex` delete or clean overwrite (95, 146, 147). Exp: clean
26. Goroutine-launched sink, multi-result function, `[]string` element store/load (142-144). Exp: S
27. Race detector over select/map lifecycle and concurrent tainting from many goroutines (98-100, 120). Exp: race-free
28. After the owner finishes, force GC and allocate a new value at the same address and length, then hit the sink (101, 104). Exp: no stale report, and roots are released (no pinning leak like Orchestrion case 104)
29. A value escaping the request into a goroutine or channel and reaching a sink after the request ends (108). Exp: dropped, no cross-request bleed, and no process-wide over-taint latch
30. Saturation: exceed owner/range/writer capacities (105, 106), for example 65,536 tainted values in one request. Exp: drop data with bounded memory, never report `Unknown` for clean values
31. Two independent sources concatenated, the same source used twice, source-ID identity (125, 126, 157). Exp: S, capped by `DD_IAST_MAX_RANGE_COUNT`
32. Alias results: `strings.Cut`/`TrimPrefix`/`Split`/`Fields` (152-154) versus `regexp.FindString` and `regexp.ReplaceAllString` (155, 132). Exp: the strings windows S; regexp U (exact-key miss)
33. `base64`, `json.Marshal`, `xml.Marshal` of tainted data (133-135). Exp: U. JSON decoding is the supported direction
34. SQL `Rows.Scan` of driver bytes into a string (137). Exp: ? (`DD_IAST_DB_ROWS_TO_TAINT` implies a DB source)
35. Built without Orchestrion, IAST disabled, or request not sampled (1, 119). Exp: zero reports and near-zero overhead
36. unsafe aliases/writes, cgo, assembly, `go:linkname`, plugins (112-116). Exp: U; must compile and never panic (plugins/non-root executables do not activate sinks)
37. Sink evidence redaction for a tainted secret-looking value (130). Exp: S (redacted)
