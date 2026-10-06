# Plan: `encoding/json` propagation on the v2-backed decoder (Go 1.27)

Status: DRAFT, revision 6 (critic rounds 1 to 5 applied; user decisions of
section 9 applied, including the answers to critic round 5; the changes of
revision 6 are not reviewed by a critic).

## 1. Decision (proposed)

Keep the Phase 8 v1 aspects. They apply on Go 1.26 and on
Go 1.27 with `GOEXPERIMENT=nojsonv2`. Add a second, small set of aspects for
the v2-backed `encoding/json`. This set is the default on Go 1.27.

The v2 set does not keep decoder state in the bridge. The design has these
parts:

1. A wrapper around the default string unmarshaler of `encoding/json/v2`.
   The wrapper reads the raw token of the string that was just decoded. Then
   it sends the raw token and the destination `reflect.Value` to the existing
   literal callback.
2. For `(*json.Decoder).Decode`, a wrapper around the
   `dec.dec.ReadValue()` call in `Decode` ONLY. A template guard on the
   enclosing function keeps the two other `ReadValue` calls of the package
   unchanged (section 6.3). `NewDecoder` records the ONE owner that has an
   exclusive binding to the reader (section 6.5). At `Decode`, the wrapper
   replaces the value bytes with an immutable managed clone and gives the
   clone ONLY to that owner, if it is still live and still the only
   exclusive owner. It never uses the request that is current at `Decode`
   time. Then `jsonv2.Unmarshal` decodes the clone, and all raw tokens alias
   tainted memory (section 6.3).
3. Reader bindings get an "exclusive" flag, and reader lookups report if
   they are complete (section 6.5). The decoder attributes a value only
   when the binding proves that every byte of the reader comes from one
   owner. In all other cases it is a safe miss.
4. The retargetable wrappers `io.LimitReader` and `bufio.NewReader(Size)`
   keep an exclusive binding. A bounded, allocation-free guard checks the
   target of the wrapper at each `Read`. If the target changed, the guard
   removes exclusivity before a byte of the new target flows
   (section 6.6, decision Q8).
5. The v1 `Decode` document and `io.ReadAll` use the same exclusive
   single-owner rule as the v2 decoder (section 6.7, decisions Q6 and Q9).
   `io.ReadAll` captures the owner token BEFORE it reads, and checks it
   again after (decision Q11).
6. One residual is accepted by user decision: a `bufio.Reader` that user
   code copies by value shares its buffer with the copy (section 6.6,
   R15, decision Q10).

Dispatch rule (section 4): an aspect that matches on every toolchain
references only symbols that it declares itself. It declares a nil function
variable and calls it only when it is not nil. A variant-specific aspect,
anchored on a declaration that exists in that variant only, sets the variable
in an injected `init`. On an unknown variant, no aspect sets the variable, so
the build compiles and nothing propagates.

## 2. Facts from the Go 1.27.1 source

GOROOT: `/opt/homebrew/Cellar/go/1.27.1/libexec/src/encoding/json`.
All paths below are relative to that directory.

### 2.1 Variant selection

- All v1 files (`decode.go`, `stream.go`, `scanner.go`, ...) have
  `//go:build !goexperiment.jsonv2` (for example `decode.go:8`).
- All `v2_*.go` files, all `v2/*.go` files, and all `jsontext/*.go` files have
  `//go:build goexperiment.jsonv2` (for example `v2_decode.go:5`,
  `v2/arshal.go:5`, `jsontext/decode.go:5`).
- `internal/buildcfg/exp.go:87` sets `JSONv2: true` by default on 1.27.
- With `GOEXPERIMENT=nojsonv2`, `encoding/json/v2` and `jsontext` contain no
  files, and `encoding/json` does not import them.
- Go 1.27 v1 files are equal to Go 1.26.6 v1 files for all hooked
  functions. The only non-comment change in `decode.go` is the removal of
  `_ "unsafe"`. `decodeState.unmarshal` (`decode.go:174`), `init` (`:235`),
  `valueQuoted` (`:409`), `literalStore` (`:857`), and the `Decoder` fields
  `r`, `buf`, `d` (`stream.go:16-27`) are unchanged.

### 2.2 `json.Unmarshal` call path (v2-backed)

1. `v2_decode.go:110-112` `Unmarshal(data, v)` calls
   `jsonv2.Unmarshal(data, v, DefaultOptionsV1())`.
2. `v2/arshal.go:386-395` `Unmarshal` calls
   `export.GetBufferedDecoder(in, ...)`. This is
   `jsontext/pools.go:132-136`: `d.s.reset(b, nil, ...)`. The decoder buffer
   IS the caller slice. There is no copy. `rd` is nil, so `fetch`
   (`jsontext/decode.go:175-177`) never replaces the buffer.
3. `v2/arshal.go:446-490` `unmarshalDecode`. With legacy semantics it first
   runs `CheckNextValue` (`:457`). Then it calls
   `lookupArshaler(t).unmarshal` (`:467`, `:528-540`).
4. Destination dispatch (all use `lookupArshaler`, so all reach the same
   cached string arshaler for a string-kind type):
   - struct fields: `v2/fields.go:256` sets `f.fncs = lookupArshaler(sf.Type)`;
     `v2/arshal_default.go:1375` calls `f.fncs.unmarshal`.
   - slices, arrays, pointers: `valFncs = lookupArshaler(t.Elem())`
     (`arshal_default.go:1472`, `:1619`, `:1722`).
   - maps: `keyFncs`, `valFncs` (`arshal_default.go:789-790`). The key goes
     through `unmarshalKey(dec, k, uo)` (`:1019`). The value goes through
     `unmarshalVal` (`:1059`). `SetMapIndex` copies both (`:1060`).
   - `interface{}`: the fast path to `unmarshalValueAny`
     (`arshal_default.go:1904-1914`) needs `!AllowDuplicateNames`. v1 default
     options set `AllowDuplicateNames` (`internal/jsonflags/flags.go:51-52`).
     Thus the v1 facade uses `newAddressableValue(stringType)` (`:1924`) and
     then `lookupArshaler(stringType).unmarshal` (`:1950-1954`). This is the
     same string arshaler.
5. `v2/arshal_default.go:211` `makeStringArshaler(t)`. Its unmarshal closure
   (`:257-302`):
   - `:270` `val, err := xd.ReadValue(&flags)`. `val` is the raw token,
     with quotes, as a sub-slice of the decoder buffer.
   - `:274-278` `null` token: sets `""`, or keeps the old value when
     `MergeWithLegacySemantics` is set (v1 default).
   - `:282` `val = jsonwire.UnquoteMayCopy(val, flags.IsVerbatim())`.
   - `:283-293` `,string` option: second unquote. Inner `null` keeps the old
     value in merge mode.
   - `:295-299` `str := makeString(xd.StringCache, val)`, then
     `va.SetString(str)`.

The raw token and the destination meet in ONE place: this closure. The
closure is a function literal. No named function has both values.

### 2.3 `(*json.Decoder).Decode` call path (v2-backed)

1. `v2_stream.go:20-32` `Decoder{dec *jsontext.Decoder; opts; err; hadPeeked;
   hadEOF}`. There is no `r` field and no `d` field.
2. `v2_stream.go:38-50` `NewDecoder(r)` wraps a `*bytes.Buffer` as
   `struct{ io.Reader }{r}` (`:42-44`). Then it calls
   `jsontext.NewDecoder(r, dec.opts)` (`:48`). The original reader is kept
   only inside `jsontext.decodeBuffer.rd` (unexported).
3. `v2_stream.go:74-91` `Decode(v)`:
   - `:78` `b, err := dec.dec.ReadValue()`. This returns
     `d.buf[pos-n : pos : pos]` (`jsontext/decode.go:773-775`), an alias of
     the stream buffer.
   - `:90` `return jsonv2.Unmarshal(b, v, dec.opts)`. This is the same path as
     section 2.2, with `in == b`.
4. Stream buffer (`jsontext/decode.go:175-258`): `fetch` copies reader data
   into `d.buf`. It moves or grows the buffer (`:219-231`). On the next read,
   `invalidatePreviousRead` (`:261-272`) writes `#` over the first byte of the
   previous value. Thus `b` is mutable and short-lived. It must never be a
   taint root.

### 2.4 Raw token access and string creation

- `jsontext/decode.go:84-90`: `decoderState` embeds `decodeBuffer`.
  `export.Decoder(dec)` (`jsontext/export.go:58`) returns `*decoderState`.
  `v2` has `var export` at `v2/arshal.go:65`.
- `jsontext/decode.go:290-307` `PreviousTokenOrValue()` returns
  `buf[prevStart:prevEnd]`. `ReadValue` sets `prevStart` and `prevEnd` to the
  bounds of the value (`:773-774`). After the string closure returns, no other
  read has happened, so this is the exact raw token. `v2` already uses it for
  the same purpose (`arshal_default.go:1046`, `:1786`).
- `jsonwire/decode.go:413-420` `UnquoteMayCopy`: for a verbatim string it
  returns `b[1:len(b)-1]`, an alias of the input. Otherwise it allocates with
  `AppendUnquote` (`:257`).
- `v2/intern.go:20-54` `makeString` always returns a copy (`string(b)`) or a
  cached string. The cache (`xd.StringCache`, 256 entries) is kept across
  pooled `Unmarshal` calls, because `reset` (`jsontext/decode.go:149-155`)
  does not clear it. Thus a decoded string never aliases the input. A cache
  hit can return a string that an earlier request produced.

Consequences:

- For `Unmarshal`, the raw token is an interior window of the caller slice.
  The store supports interior lookup (`store.Lookup`: "the ranges of its root
  that contains key, sliced to the window of key"). Thus
  `propagation.JSONString(raw, raw, result)` works with no document table.
- We must never taint the string that `makeString` returns. We must clone it
  (the existing `JSONString` does `strings.Clone`) and store the clone with
  `SetString`. The cache keeps the clean original.
- Correction (step 4): with the runtime hooks (plan runtime-operator-hooks),
  `string(b)` in `makeString` IS tainted when `b` has taint (a verbatim
  string aliases the input). Thus the cache can keep a tainted string, and a
  later decode of clean bytes (same or other request) gets it. Section 6.2,
  "String cache", adds a guard in `makeString`.

## 3. Hook candidates and what each one observes

| Candidate | Join point | Observes | Verdict |
|---|---|---|---|
| String unmarshal closure | `function-body` + `signature` on a `FuncLit` | `dec`, `va`, `uo` | Rejected: the signature is shared by every unmarshal closure in `v2` (bool, int, struct, map, methods, ...). Too broad. |
| `makeStringArshaler` result | `function-body` on `FuncDecl`, defer on `Result 0` | the `*arshaler`, once per type | Selected: wrap `r.unmarshal` with an injected wrapper. Runs once per type. |
| `makeString` | `function-body` on `FuncDecl` | unquoted bytes, result | Rejected as a source (no destination; cache hits skip the conversion; escaped strings have no link to input). Selected as the string cache guard (section 6.2, "String cache"): it is the only function that reads or changes the cache. |
| `va.SetString(str)` | `method-call` on `encoding/json/v2.addressableValue` | final string | Rejected: `val` is overwritten, so the raw token is lost; template must use local names. |
| `jsontext.(*decoderState).ReadValue` | `function-body` in `jsontext` | raw value, `d.rd` | Rejected for strings: runs for every value; no destination. |
| `unmarshalValueAny` | `function-body` on `FuncDecl`, defer on `Result 0` | raw token (via `PreviousTokenOrValue`), `any` result | Optional: only direct `encoding/json/v2` users with v2 default options reach it. Not needed for the v1 facade. |
| `dec.dec.ReadValue()` in facade `Decode` | `method-call` on `encoding/json/jsontext.Decoder`, name `ReadValue`, `import-path: encoding/json` | value bytes `b` | Selected, with a template guard: the join point matches THREE calls (`Decode`, `checkValid`, `Number.UnmarshalJSONFrom`); the guard `eq .Function.Name "Decode"` changes only the call in `Decode` (section 6.3). v2-only (v1 files do not import `jsontext`). |
| `NewDecoder(r)` | `function-body`, `Argument 0`, `Result 0` | original reader | Selected: snapshot the reader's bound owners into an added field. |

Coverage with the selected hooks (v1 facade, Go 1.27 default):

- Supported: typed string struct fields, slice/array elements, pointers,
  typed map values, `,string` values, nested values. Escaped strings get one
  coarse range (Phase 8 semantics).
- NEW on v2 (not on v1): typed map keys, `interface{}` string values,
  `map[string]any` keys and values. All use the string arshaler with the
  exact raw token. Decision Q1: KEEP this extra coverage. Tests expect it
  on lane B and expect the v1 result on lanes A and C (step 7).
- Not tainted: custom `UnmarshalJSON`, `UnmarshalText`, `UnmarshalJSONFrom`
  results (the method arshaler replaces the default one), `[]byte`, numbers,
  booleans, `null`, a `,string` value whose inner token is `null`, and a
  string whose own conversion fails.
- Failed documents (propagation is per string, with no whole-document
  staging, as in v1 `literalStore`):
  - Syntax errors: nothing is decoded. With legacy semantics,
    `unmarshalDecode` validates the whole value first
    (`v2/arshal.go:456-463`). No string propagates.
  - Semantic errors (for example a number into a `string` field): decoding
    continues and returns the first error (`v2/arshal.go:467-483`). Strings
    that were set before or after the failing member stay set and tainted.
    Maps store each entry before they return an error
    (`v2/arshal_default.go:1052-1074`). Each such string really comes from
    its own raw token, so the provenance stays exact. Bounded staging is not
    cheap (it needs a list of pending values for each decode), so the plan
    does not stage.
- Documented miss (decision Q3, out of scope): direct
  `encoding/json/v2` streaming APIs `jsonv2.UnmarshalRead`,
  `jsonv2.UnmarshalDecode`, and `jsontext.Decoder`. Direct
  `jsonv2.Unmarshal` on tainted bytes works (section 2.2).
- Safe miss: strings returned by `(*json.Decoder).Token`;
  `Decode` on a decoder whose reader had no exclusive single-owner binding
  at `NewDecoder`, whose owner has finished, or that is "closed"
  (section 6.3). Readers with no exclusive binding (section 6.5):
  `compress/gzip.Reader`, `io.MultiReader` with more than 8 inputs, with a
  clean or unbound input, or with two owners, a `bufio.Reader` or
  `io.LimitedReader` that was retargeted (section 6.6), a `bufio.Reader`
  that `NewReaderSize` did not make (pool `Reset` pattern, zero value),
  an `io.LimitedReader` from a composite literal, and any reader after a
  contended lookup. `Decode` after `Token`/`More` and read-ahead values DO
  propagate. Readers from `http.MaxBytesReader`, `io.TeeReader`,
  `io.LimitReader`, and `bufio.NewReader(Size)` (size <= 4096) of an
  exclusive input DO propagate, while they are not retargeted.
- Escaped and verbatim strings get one coarse range on the whole decoded
  string (decision Q2, Phase 8 parity). No precise ranges.

## 4. Selecting aspects for each toolchain

Facts from Orchestrion (pinned `v1.12.2-0.20260828141217-23afa71d6dcb`; the
relevant files are identical to `v1.13.1`):

- There is no Go-version or build-tag join point. `lang` on a template only
  raises the minimum language level.
- Orchestrion weaves only the files that the build selects. A join point that
  names an absent symbol does not match. Orchestrion reports no error.
- A template that names an absent field or method compiles to invalid Go.
  The package build fails. This is the current failure at
  `iast/encoding/json/orchestrion.yml:41-42` (`.r`, `.d`).
- `function-body` matches `FuncDecl` and `FuncLit`
  (`internal/injector/aspect/join/function.go:96-104`).
- Local identifiers have an empty `Path` (dst `ResolveLocalPath` is not set,
  `internal/injector/injector.go:138`).
- `inject-declarations` appends to the file of the matched node
  (`advice/inject.go`). It works with any join point.
- `{{ .Function.Result 0 }}` names an unnamed result `__result__0`
  (`advice/code/dot_function.go:233-273`).
- No join point limits a node by its enclosing function. `all-of` tests
  every point on the SAME node (`join/all-of.go:53-62`). `function` matches
  only a `FuncDecl` or `FuncLit`, and `function-body` only the body block
  of one (`join/function.go:90-114`, `:372-390`). `method-call` matches a
  `CallExpr` by the receiver type of the call only
  (`join/method_call.go:61-107`). Thus `all-of` with `method-call` and
  `function` never matches.
- In a template, `.Function` walks up the node chain to the nearest
  enclosing `FuncDecl` or `FuncLit` (`advice/code/dot_function.go:70-80`),
  and `.Function.Name` returns its name (`:89-91`, empty for a literal).
  Templates are `text/template`, so `if`/`else` is available, and a branch
  that is not taken is not evaluated. Orchestrion's own test uses
  `{{ if ... }} ... {{ else }}{{ . }}{{ end }}` on a call join point
  (`internal/injector/testdata/injector/selector-expr-fun-name/config.yml`).
  These files are the same in the pinned version and in `v1.13.1`.

A cross-variant reference is dangerous: if an always-matching aspect calls a
symbol that only a variant-specific aspect declares, a toolchain without that
variant fails to compile. Thus the plan uses the dispatch rule from section 1:
nil function variables, declared by the always-matching aspect, and filled by
an `init` from the variant-specific aspect.

Variant anchors (checked against the source):

- v1: `struct-definition: encoding/json.decodeState` (only `decode.go`).
- v2 on Go 1.27: `declaration-of: encoding/json/v2.errInvalidStringTag`
  (`v2/arshal_default.go:1103`). It is absent in Go 1.26.6 `v2`. Go 1.26.6
  `jsonflags` also has no `StringTag` and no `TagFlags`.
- `encoding/json/v2` has no package-level initializer that calls
  `lookupArshaler` (its only `init` is `v2/options.go:274`). Thus the
  injected `init` runs before any arshaler is built. The shape test pins
  this.

| Aspect | Go 1.26 / nojsonv2 | Go 1.27 default | Go 1.26 + jsonv2 |
|---|---|---|---|
| `decodeState.*` aspects (Phase 8) | match | no match | no match |
| `Decode` hook, declares `__dd_iast_decodeBind`/`Unbind` vars | match | match | match |
| v1 `init` sets those vars (`decodeState` anchor) | match | no match | no match |
| `add-struct-field` + `NewDecoder` snapshot | match (used by v1 `Document`, section 6.7) | match | match (unused) |
| `makeStringArshaler` hook, declares `__dd_iast_stringWrap` var | no match | match | match (var stays nil) |
| `makeString` string cache guard (uses only its arguments and `jsonbridge`) | no match | match | match |
| v2 `init` sets `__dd_iast_stringWrap` (step 4), enables bridge v2 flag (step 5) (`errInvalidStringTag` anchor) | no match | match | no match |
| `jsontext.Decoder.ReadValue` call wrapper (3 calls match; the guard changes only the call in `Decode`) | no match | match | match (no-op: bridge v2 flag off) |

The Decode template becomes:

```go
if __dd_iast_bind := __dd_iast_decodeBind; __dd_iast_bind != nil && __dd_iast_bind({{ .Function.Receiver }}) {
  defer __dd_iast_decodeUnbind({{ .Function.Receiver }})
}
```

The same aspect injects `var __dd_iast_decodeBind func(*Decoder) bool` and
`var __dd_iast_decodeUnbind func(*Decoder)`. The v1 aspect injects an `init`
that sets them to `BindDecoder(&dec.__dd_iast_binding, &dec.d)` and
`Unbind(&dec.d)` (section 6.7: v1 uses the binding that `NewDecoder`
captured, not `dec.r`). Cost on v1: one indirect call for each `Decode`.

Go 1.26 + `GOEXPERIMENT=jsonv2` is UNSUPPORTED. The build compiles, the
string wrapper is not installed, and the `ReadValue` wrapper returns the
original bytes. The Go 1.26.6 `,string` logic is different: it checks
`StringifyBoolsAndStrings` and compares the inner value after a second
unquote (Go 1.26.6 `v2/arshal_default.go:256-269`). Go 1.27.1 checks
`StringTag` with `StringifyWithLegacySemantics` and compares after the first
unquote (`v2/arshal_default.go:258-290`). One guard cannot be correct for
both.

## 5. Dependency rules

- `internal/taint/jsonbridge` is imported into `encoding/json` and now also
  into `encoding/json/v2`. It must not import `encoding/json`,
  `encoding/json/v2`, `encoding/json/jsontext`, or any package that imports
  them. It stays at `reflect`, `sync/atomic`, `unsafe`. New functions must
  not add `fmt`, `io`, or `bytes` unless a test proves that no cycle exists.
- Injected code in `encoding/json/v2` may use `jsontext`, `jsonopts`,
  `jsonflags` (internal to `encoding/json/`; the file already imports them),
  and the package variable `export`.
- No aspect weaves `jsontext`. This keeps the change small.
- The added `Decoder` field has a `jsonbridge` type, so `encoding/json`
  imports `jsonbridge` on every variant (v1 already does). `ReaderBinding`
  contains only `any` and integers.
- `internal/taint/iobridge` is imported into `io`, `bufio`, and `net/http`.
  Its additions (sections 6.5 and 6.6) use only integers and `any`. It
  imports only `sync/atomic` and `unsafe` (`unsafe` reads the two words of
  an `any`; it is not a package dependency). It must not import `io`,
  `bufio`, or any package that imports them. The `io.MultiReader` template
  and the `Read` guard templates pass each reader as `any` (an
  interface-to-interface or pointer-to-interface conversion, no
  allocation).
- The `Read` guard aspects (section 6.6) weave `io` (`(*LimitedReader).Read`)
  and `bufio` (`(*Reader).Read`). Both packages already import `iobridge`
  through the existing aspects. `iobridge` gets the per-`Read` state (the
  guard table), because it is the only package that both `io` and `bufio`
  can import. `internal/taint/request` registers the slow-path callback.
- Extend the dependency test: `go list -deps` of `iobridge` must list only
  `sync/atomic`, `unsafe`, and their runtime dependencies.
- Add a test that lists the transitive imports of `jsonbridge` (with
  `go list -deps`) and fails on any `encoding/` package.

## 6. Design

### 6.1 Bridge additions (`internal/taint/jsonbridge`)

- `func Active() bool` — inlinable: `active() && hasValues()`.
- `func EnableV2()` — sets an atomic flag. Only the Go 1.27 v2 `init` calls
  it, from step 5 (with the `ReadValue` wrapper). The step 4 `init` does not
  call it (appendix of step 4, note 2).
- `func EnableV1()` — sets the v1 consumer flag. Only the `init` of the v1
  dispatch aspect calls it (step 3a review, finding 1). Both flags are bits
  of one `atomic.Uint32` (`consumers`): `Capture` loads it once, and
  `ReaderDocument` tests the v2 bit.
- `func String(raw []byte, value reflect.Value)` — returns at once unless
  `Active()`, `len(raw) >= 2`, `raw[0] == '"'`. Then it calls the registered
  literal callback as `literal(raw, raw, value, nil)` under `shield`.
- `type OwnerToken struct{ Index uint8; Generation uint64 }` and
  `type ReaderBinding struct { reader any; owner OwnerToken; state uint8 }`
  (`state`: none, exclusive, or closed; about 40 bytes). ONE owner only:
  attribution needs exactly one exclusive owner (section 6.5). Plain
  integers only, so the bridge keeps its dependency rule.
- `func (b *ReaderBinding) Capture(reader any)` — returns at once unless a
  decoder consumer of the token is installed (`EnableV1` or `EnableV2`)
  and `active()` (owners only, NOT `hasValues()`). With no consumer (Go
  1.27 v2 before step 5), `NewDecoder` does no lookup and the state stays
  "none": no `Decode` uses the token (step 3a review, finding 1). Then it stores `reader` and
  calls the registered owner callback under `shield`. The state becomes
  "exclusive" only if the callback proves one exclusive owner. Else the
  state becomes "closed" (sticky: this decoder never propagates).
- `func ReaderDocument[V ~[]byte](b *ReaderBinding, value V) V` — returns
  `value` unless the v2 flag is on, `active()` (owners only, NOT
  `hasValues()`), and the state is "exclusive". Then it calls the
  registered document callback under `shield` (section 6.3). If the
  callback cannot prove the owner again, the state becomes "closed" and it
  returns `value`. It returns the clone only when
  `len(clone) == len(value)`. The generic type avoids an import of
  `jsontext` (for `jsontext.Value`).
- Gates: document creation uses `active()` only, as v1 `Document` does
  (`jsonbridge/bridge.go:92-106`), because a request whose first source is
  its JSON body has zero indexed roots before the clone. String propagation
  keeps `Active()` (owners AND indexed roots); after the clone is adopted,
  the root count is not zero.
- New request helpers (in `internal/taint/request`, registered by
  `iast/encoding/json`):
  - `ReaderOwnerToken(reader) request.ReaderToken` (it is
    `request.ReaderOwner`, section 6.5, rule (f)). The token is `OK` only
    when `store.LookupReaderValue` (section 6.5) is complete, finds exactly
    one owner, and that binding is exclusive. The token identifies that
    binding (owner slot, generation, entry; rule (f)).
  - `CloneForOwner(reader, token, data) (clone []byte, proven bool)`.
    It revalidates the token with `request.RevalidateReader` (rule (f)):
    a complete lookup of `reader` again must find exactly this owner
    (same generation, active), with the same exclusive binding, and no
    reader bind of another owner of `reader` since that binding was made
    (the creation baseline of rule (f)). If a check fails,
    `proven` is false. Else it adopts the clone into this owner only. An
    oversized value returns `(nil, true)`: a miss for this value, but the
    decoder stays open. `request.CloneReaderBytesForToken` (done with
    rule (f)) has these checks.
- `func BindDecoder(binding *ReaderBinding, state any) bool` — the v1
  replacement for `Bind(dec.r, &dec.d)` (section 6.7). The decoder slot
  keeps the `*ReaderBinding`, not the reader. v1 `Document` then uses the
  same `CloneForOwner` path as `ReaderDocument`, without the v2 flag test.
- No global slot table for v2. The per-decoder state lives in the
  `Decoder` value. (v1 keeps its existing 64-slot `decoderStates` table.)

### 6.2 v2 string wrapper

The Go 1.27 aspect (anchor `errInvalidStringTag`, same file
`v2/arshal_default.go`, which already imports `jsontext`, `jsonopts`,
`jsonflags`, `jsonwire`) injects:

```go
func init() {
	__dd_iast_stringWrap = __dd_iast_wrapStringUnmarshal
	// Step 5 adds: iastjsonbridge.EnableV2() (with the ReadValue wrapper).
}

func __dd_iast_wrapStringUnmarshal(next unmarshaler) unmarshaler {
	return func(dec *jsontext.Decoder, va addressableValue, uo *jsonopts.Struct) error {
		if !iastjsonbridge.Active() {
			return next(dec, va, uo)
		}
		err := next(dec, va, uo)
		if err != nil {
			return err
		}
		raw := export.Decoder(dec).PreviousTokenOrValue()
		if uo.Flags.Get(jsonflags.StringTag) && uo.Flags.Get(jsonflags.StringifyWithLegacySemantics) && __dd_iast_innerNull(raw) {
			return nil // arshal_default.go:284-289 kept or cleared the value
		}
		iastjsonbridge.String(raw, va.Value)
		return nil
	}
}

// __dd_iast_innerNull reports whether the outer token unquotes to `null`,
// with the same test as arshal_default.go:282-284.
func __dd_iast_innerNull(raw []byte) bool {
	if len(raw) > 26 { // longest form: "\u006e\u0075\u006c\u006c"
		return false
	}
	var buffer [32]byte
	inner, _ := jsontext.AppendUnquote(buffer[:0], raw) // same as UnquoteMayCopy
	return string(inner) == "null"
}
```

The guard uses only the raw token and the options, which are the inputs of
the decision in `arshal_default.go:283-290`. It never compares destination
identity, so a string cache hit (`v2/intern.go:44-54`) cannot hide a real
source. The check runs only for `,string` fields, has a fixed bound, and uses
a stack buffer.

The `makeStringArshaler` hook aspect (all toolchains with `v2`) injects
`var __dd_iast_stringWrap func(unmarshaler) unmarshaler` and prepends:

```go
defer func() {
	if wrap := __dd_iast_stringWrap; wrap != nil {
		if r := {{ .Function.Result 0 }}; r != nil && r.unmarshal != nil {
			r.unmarshal = wrap(r.unmarshal)
		}
	}
}()
```

The defer runs before `makeMethodArshaler` reads `fncs.unmarshal`
(`v2/arshal.go:533-535`). Thus custom methods replace the wrapper, and a
method fallback reaches the wrapped default.

Notes:

- The wrapper is built once per string type and is cached globally. Do not
  gate its creation on `Active()`: the cache can be filled before `main`.
- `propagateLiteral` (`iast/encoding/json/json.go:35-45`) is reused as is.
  It clones the result, adopts the clone, and calls `SetString`.

String cache (step 4 review, finding 1). The runtime hooks taint
`string(b)` when `b` has taint. `makeString` (`v2/intern.go:20-54`) puts
that string in the 256-entry cache of the decoder, and the pooled decoder
keeps the cache across `Unmarshal` calls (`jsontext/pools.go:118-140` does
not clear it). A later decode of clean bytes with the same string, in the
same request or in another live request, then gets the tainted string: a
false source. `makeString` has two callers in Go 1.27.1: the string arshaler
(`v2/arshal_default.go:298`) and the `any` fast path `unmarshalValueAny`
(`v2/arshal_any.go:89`, direct `jsonv2.Unmarshal` into `any`, `[]any`,
`map[string]any` with no `AllowDuplicateNames`). Go 1.26.6 has the same
two callers and the same signature. A fix in the wrapper covers only the
first caller. Thus the guard is in `makeString` itself:

```yaml
- id: "[v2] encoding/json/v2 string cache guard"
  join-point:
    all-of:
      - import-path: encoding/json/v2
      - function-body:
          function:
            - receiver: false
            - name: makeString
  advice:
    - prepend-statements:
        template: |-
          if iastjsonbridge.HasIndexedRoots() && iastjsonbridge.SkipCache({{ .Function.Argument 1 }}) {
            return string({{ .Function.Argument 1 }})
          }
```

- The gate `jsonbridge.HasIndexedRoots()` is the indexed-root counter of
  the process (inlinable): the runtime gate has the same value (the store
  changes both at the same time), and with the gate off the runtime hooks
  do not taint. Gate-off cost: two loads (the counter pointer and the
  counter), no call. (A gate and a call in one function do not fit the
  inline budget: cost 93 > 80.)
- `jsonbridge.SkipCache(b)` (not inlined) returns false for `len(b) < 2`
  (no taint, no cache) and with no indexed root. Else
  it calls the new `Callbacks.MayBeTainted` (`propagation.JSONMayBeTainted`:
  the store filter on `b`, the same filter as the pre-check of the runtime
  hooks; no lookup, no lock) under `shield`. A panic or a missing callback
  gives true (fail closed: one allocation, and the result is correct).
- When `SkipCache` is true, `makeString` returns `string(b)`: the result of
  `makeString` with no cache. The cache is not read and not changed. Thus a
  string of bytes that can have taint never goes into the cache, and a cache
  hit never gives it. The runtime hooks give `string(b)` the taint of `b`
  (correct provenance); the wrapper then replaces it with its own clone.
- Clean bytes: the filter does not match, and the cache works as before
  (no allocation added). A filter false positive costs one allocation.
- The aspect uses only the arguments of `makeString` and `jsonbridge`, thus
  it applies to each toolchain that has `encoding/json/v2` (also Go 1.26 +
  `jsonv2`). It replaces the scan-based removal of the first step 4 code.
- Residual: a root that another goroutine adds for the same bytes between
  the gate check and the conversion (a concurrent taint of the bytes that
  are being decoded) can put one tainted string in the cache.
- Documented miss (decision Q3, direct `encoding/json/v2` is out of scope):
  the `any` fast path makes object names with `Token.String`
  (`unmarshalObjectAny`), and gives `any` strings with no wrapper. Verbatim
  strings get the taint of the runtime hooks; escaped object names and
  escaped `any` strings get no taint. These names do not use the cache, so
  they cannot give a false source.

### 6.3 Decoder document (the `ReadValue` call in `(*Decoder).Decode` only)

Scope of the hook (critic round 3, finding 1). The Go 1.27.1
`encoding/json` package has three calls of `(*jsontext.Decoder).ReadValue`:
`(*Decoder).Decode` (`v2_stream.go:78`), `checkValid` (`v2_scanner.go:32`),
and `(*Number).UnmarshalJSONFrom` (`v2_decode.go:243`). Go 1.26.6 has the
same three (`v2_stream.go:73`, `v2_scanner.go:32`, `v2_decode.go:231`). The
`method-call` join point matches all three, and no join point can limit it
to one enclosing function (section 4). An unguarded template fails on
`checkValid` (`.Function.Receiver` returns `errNotMethod`,
`advice/code/dot_function.go:82-87`) and on `Number.UnmarshalJSONFrom`
(`*Number` has no `__dd_iast_binding` field). Thus the aspect keeps the
`method-call` join point and puts the scope in the template:

```yaml
- id: "[v2] encoding/json Decoder.Decode value document"
  join-point:
    all-of:
      - import-path: encoding/json
      - method-call:
          receiver: encoding/json/jsontext.Decoder
          name: ReadValue
  advice:
    - wrap-expression:
        imports:
          iastjsonbridge: github.com/DataDog/dd-iast-go/internal/taint/jsonbridge
          jsontext: encoding/json/jsontext
        template: |-
          {{- if eq .Function.Name "Decode" -}}
          func() (jsontext.Value, error) {
            __dd_iast_value, __dd_iast_err := {{ . }}
            if __dd_iast_err == nil {
              __dd_iast_value = iastjsonbridge.ReaderDocument(&{{ .Function.Receiver }}.__dd_iast_binding, __dd_iast_value)
            }
            return __dd_iast_value, __dd_iast_err
          }()
          {{- else -}}
          {{ . }}
          {{- end -}}
```

- `{{ .Function.Receiver }}` is in the `Decode` branch only. The template
  engine does not evaluate the branch that is not taken. Thus
  `checkValid` and `Number.UnmarshalJSONFrom` get their own call back
  (`{{ . }}`), with no change in behavior or cost. Their files can show in
  the woven output, with the same statements.
- The name test is sufficient because the shape test (section 6.4) pins
  that exactly one of the three calls is in a function named `Decode`, and
  that this function is the method `(*Decoder).Decode`. A new `ReadValue`
  call in another function named `Decode` fails the shape test on lane B.
- On v1 files, `encoding/json` does not import `jsontext`, so the join
  point does not match (`join/method_call.go:53-55`, `PackageImports`).
- Woven-build test (step 5), `TestV2ReadValueHookScope`, lane B only
  (`goexperiment.jsonv2` build tag):
  1. Run `go tool orchestrion go build -work -a -o <tmp>
     ./iast/encoding/json/testdata/scopeprobe`. The probe is a small `main`
     that calls `json.Valid`, decodes a `json.Number` with `json.Unmarshal`
     and with `Decoder.Decode`, and decodes a struct with
     `Decoder.Decode`. A successful build proves that `checkValid` and
     `Number.UnmarshalJSONFrom` compile after weaving.
  2. Read `WORK=` from the build output. Orchestrion writes each modified
     file to `$WORK/b*/orchestrion/src/<import path>/<file>`
     (`toolexec/aspect/oncompile.go:30-31`, `:114`). Parse each file of
     `encoding/json` there with `go/parser`. Assert: the bodies of
     `checkValid` and `(*Number).UnmarshalJSONFrom` contain no identifier
     with the prefix `__dd_iast` and no selector on `iastjsonbridge` (an
     absent file is not modified, and also passes); the body of
     `(*Decoder).Decode` contains exactly one call of
     `iastjsonbridge.ReaderDocument`.
  3. Run the probe with an active request and a bound reader: the results
     of `json.Valid` and of the `json.Number` decodes are equal to the
     unwoven results.
  Then delete `$WORK`.

Binding model (checked against the store, request, and aspect code;
corrected in round 3):

- A reader binding means "this reader was made from data of this owner".
  It does NOT mean "every byte of this reader comes from this owner".
  These verified cases break the second meaning:
  - `io.MultiReader` inspects only its first 8 inputs
    (`iast/io/orchestrion.yml:46-68`). With 7 clean inputs, the body of A
    as the 8th input, and the body of B as the 9th, the result is bound to
    A only, and B's bytes come out of it (`iast/io/io_test.go:120-149` pins
    this for `io.ReadAll`). A clean input is not bound, so its bytes also
    come out of a reader that is bound to the owners of the other inputs.
  - `bufio.NewReaderSize` binds its result
    (`iast/bufio/orchestrion.yml:15-36`), but `(*bufio.Reader).Reset` has
    no hook. A pooled reader that is bound to A, then reset onto B's data
    or clean data while A is live, stays bound to A only.
    `*io.LimitedReader` has the exported field `R`; user code can change it
    after `io.LimitReader` returns. (Section 6.6 adds a per-`Read` guard
    for both wrappers, decision Q8.)
  - `lookupObject` skips an owner whose `lifecycleMu` or binding-table
    lock is contended, and an owner that does not fit in `out`
    (`store/binding.go:129-160`). It records this only in owner telemetry.
    Thus a lookup result with one owner does not prove that the reader has
    only one owner.
- `http.MaxBytesReader` (`iast/net/http/orchestrion.yml:123-138`) and
  `io.TeeReader` (`iast/io/orchestrion.yml:29-44`) propagate the binding of
  their one input. Their result types have no exported field and no reset
  method, so user code cannot retarget them. `compress/gzip` has no
  propagation aspect: a `gzip.Reader` is unbound, so a decoder over it is a
  safe miss unless a later change binds it.
- Bytes that were read from a reader before `NewDecoder` do not change the
  owner of the bytes that the decoder reads later. The proof below uses
  only the bytes that the decoder reads.
- A reader binding belongs to one owner record. `BindObjectValue` adds it
  (`store/binding.go:95-110`, `:166-202`). Nothing removes a reader binding
  while its owner lives; the table is cleared only when the owner finishes
  (`store/owner.go:207`, `bindingTable.reset` at `store/binding.go:232`).
  The owner slot gets a new generation when it is reused
  (`store/owner.go:53`). The only in-place change is a kind change of the
  same pointer (`store/binding.go:186-197`), which needs the same object to
  be bound as a URL; this does not happen for readers.
- The binding keeps a strong reference to the reader, and the `Decoder`
  keeps one too. Thus the reader address cannot be reused by another
  object while the decoder lives.
- HTTP bodies are bound to their own request owner at entry
  (`request/http.go:74-77`). Wrappers get the union of their inputs'
  owners (`request/reader.go:28-39`; `io.MultiReader` in
  `iast/io/orchestrion.yml:46-68`).
- `OwnerRef.Handle` and `analysisForOwner` accept a ref only if its index,
  generation, and active state still match (`store/binding.go:55-64`,
  `request/http.go:15-35`).

Thus a binding alone is not a proof. The decoder attributes only when the
binding is provably complete: section 6.5 adds an "exclusive" flag to
reader bindings and a "complete" result to reader lookups. An exclusive
binding of reader R to owner O means: when R was bound, it was proven that
every byte that R can produce comes from data of O. A binding added later
cannot change the bytes that R produces. So an exclusive binding stays
true while O lives.

Mechanism:

- `add-struct-field` on `encoding/json.Decoder`:
  `__dd_iast_binding github.com/DataDog/dd-iast-go/internal/taint/jsonbridge.ReaderBinding`.
- `NewDecoder` prepend (valid in both variants). It captures the original
  argument, so a `*bytes.Buffer` keeps its identity:

```go
__dd_iast_reader := {{ .Function.Argument 0 }}
defer func() {
	if {{ .Function.Result 0 }} != nil {
		{{ .Function.Result 0 }}.__dd_iast_binding.Capture(__dd_iast_reader)
	}
}()
```

- `Capture` (in the `NewDecoder` defer) calls `ReaderOwnerToken`. The
  state becomes "exclusive", with the token, only if the lookup is
  complete, finds exactly one owner, and that binding is exclusive. Else
  the state becomes "closed".
- The `ReadValue` wrapper above calls `ReaderDocument`, which calls
  `CloneForOwner`. It revalidates the token at each `Decode` with
  `request.RevalidateReader` (section 6.5, rule (f)). If a check fails,
  the state becomes "closed". A check of the owner only ("the lookup
  finds O again") is not sufficient: a bind of another owner of the
  reader that starts and ends between `NewDecoder` and `Decode` is not
  visible at either point. Only the reader bind counter of rule (f)
  shows it.

Invariant:

> A `Decode` value is attributed only to owner O, and only when (1) at
> `NewDecoder`, a complete lookup found exactly one owner O, with an
> exclusive binding of the reader; and (2) at this `Decode`, the token of O
> is still valid (same generation, active), a complete lookup still
> finds exactly O, with the same exclusive binding, and no other owner did
> a reader bind of the reader since that binding was made (rule (f); this
> includes the time since `NewDecoder`). By (1) and section 6.5, every
> byte that the reader produces while O lives is data of O (except the
> documented residual R15, section 6.6). The decoder
> reads no byte before `NewDecoder` returns, and it reads only from that
> reader. Thus every byte of the value is data of O, including read-ahead
> by `fetch` (`jsontext/decode.go:175-256`), `More`
> (`v2_stream.go:270-285`), `Token`, and earlier `Decode` calls. The
> current request at `Decode` time is never used.

The proof does not depend on the time of the read, so it also holds for an
owner change during `ReadValue`. Check (2) is a second guard: in production
code, no existing reader gets a new owner after construction (only
`request.BindReader` and the entry binding bind an existing object). It
also closes the decoder when O has finished.

State (bounded, one byte). "Closed" is sticky: the decoder never
propagates again. The state becomes "closed" when a lookup is incomplete
(lock contention or fanout overflow), finds zero or more than one owner,
finds a non-exclusive binding, when the token fails revalidation, or when
the `Decode` lookup does not find exactly the captured owner.

Cases:

- One `json.NewDecoder(r.Body)` with many `Decode` calls, a `More()` loop, or
  `Token` then `Decode`: every value propagates to the body owner.
- `json.NewDecoder(http.MaxBytesReader(w, r.Body, n))`,
  `json.NewDecoder(io.TeeReader(r.Body, &log))`, and
  `io.MultiReader(r.Body)`: exclusive: propagate.
- `io.MultiReader` with 7 clean inputs, A's body 8th, B's body 9th: not
  exclusive: miss (never A, never B). `io.MultiReader(bytes.NewReader(peeked), r.Body)`:
  the clean input is unbound: miss.
- `bufio.NewReader(r.Body)`, `io.LimitReader(r.Body, n)`: exclusive and
  guarded (section 6.6): propagate on every value, while the wrapper is
  not retargeted.
- A `bufio.Reader` from `NewReaderSize`, bound to A, then reset onto B's
  data (bound or not) while A is live: the guard of the next `Read` sees
  that `b.rd` changed, and sets the "retargeted" bit of A before a byte of
  B flows (section 6.6): miss. Never A, never B. The same for
  `lr.R = other` on an `io.LimitReader` result.
- Known limit (R15, decision Q10): user code copies a guarded
  `bufio.Reader` by value (`q := *p`), then resets and reads the copy.
  The foreign bytes that `p` then produces go to A (section 6.6).
- `gzip.NewReader(r.Body)`: unbound: miss.
- A contended lookup at `NewDecoder` or at `Decode`: closed: miss.
- A value that spans several buffer refills: `ReadValue` returns one
  contiguous slice (`jsontext/decode.go:773-775`); the clone covers it.
- A decoder reused by a later request: the first owner finished, so its
  token fails revalidation: closed, miss. It is never given to the second
  request. If the first owner is still live, the value goes to the first
  owner, and by the invariant it is that owner's data.
- `*decoder = *json.NewDecoder(clean)`: the struct copy also copies the new
  binding (`TestJSONDecoderReinitializedWithCleanReader`).
- Decoder created while no request is active: state "none": miss.
- Oversized value (> `store.MaxRootBytes`, 64 KiB): the original bytes
  are kept, and the state does not change (the next value can fit). Safe
  drop, as in Phase 8.
- `jsonv2.Unmarshal(clone, v, dec.opts)` sees tainted raw tokens. Offsets in
  errors do not change, because the bytes are equal.

Source value and offsets (critic round 3, note 3):

- `ReadValue` consumes the whitespace first (`jsontext/decode.go:700-706`)
  and returns one contiguous slice `d.buf[pos-n : pos : pos]` for the
  value (`:773-775`), also when the value spans refills. The clone has the
  same bytes and length. Thus every raw token keeps its exact offset
  relative to the VALUE through `jsonv2.Unmarshal`.
- The body source that `CloneForOwner` adds is the copied value, not the
  full body. Offsets are relative to that value, not to the body. A body
  with several values (NDJSON, `More()` loop items) gives one source for
  each `Decode` value (through `adoptBodyBytes`, `request/reader.go:90-130`,
  the same function as v1).
- Comparison with v1: v1 also clones one value, not the full stream.
  `Decode` calls `dec.d.init(dec.buf[dec.scanp : dec.scanp+n])`
  (`stream.go:69`), and the `decodeState.init` hook clones that argument
  (`iast/encoding/json/orchestrion.yml:99`, `jsonbridge.Document`). So the
  scope of one source is the same on both variants.
- One user-visible difference: v1 `readValue` starts at `dec.scanp`
  (`stream.go:106`), which is directly after the previous value, so the v1
  source value can start with the whitespace between values (for example
  `"\n{\"a\":\"x\"}"` for the second NDJSON line). The v2 source value
  starts at the first byte of the value (`{"a":"x"}`). Thus a reported
  source value can be shorter on v2. String taint ranges do not change:
  both variants give one coarse range on the whole decoded string
  (Phase 8 semantics). Step 7 has a test that asserts the v2 source value
  and records the v1 value.
- `json.Unmarshal` on v2 has no decoder source: the source is the root
  that contains the caller slice (interior lookup), for example the
  `io.ReadAll` result. This is the same as v1.

Cost: one lookup in `NewDecoder` and one in each `Decode`, only while some
request is active (v1 already does one lookup for each `Decode` in
`CloneReaderBytes`). About 40 bytes for each `Decoder`.

Rejected alternative: a recorder that wraps the reader in `NewDecoder`
and records a byte range and an owner token for each `Read`. It changes
the reader identity that `jsontext` sees, and it does not detect a
`bufio.Reader.Reset`. Section 6.6 puts the check in the wrappers instead.

The v1 path uses the same rule in this change (section 6.7): v1
`Document` uses the `ReaderBinding` that `NewDecoder` captured, and
`CloneForOwner`.

### 6.4 Telemetry and shape

- Split `instrumentedPropagationPoints` into build-tagged files:
  `points_v1.go` (`!goexperiment.jsonv2`, value 5) and `points_v2.go`
  (`goexperiment.jsonv2`, value 2: string materialization, decoder document).
- Tag each aspect id with `[v1]`, `[v2]`, or `[shared]`.
  `TestInstrumentedPropagationTelemetry` counts ids with the tag of the
  current variant. The current substring count of
  `- import-path: encoding/json` would also count `encoding/json/v2`.
- Split `TestSourceShape` into `shape_v1_test.go` (`!goexperiment.jsonv2`,
  current checks, plus `decodeState` struct present) and `shape_v2_test.go`
  (`goexperiment.jsonv2`). The v2 test parses `encoding/json`,
  `encoding/json/v2`, and `encoding/json/jsontext` with `go/build` and checks:
  - `encoding/json`: `Decoder.dec` has type `*jsontext.Decoder`;
    `NewDecoder(r io.Reader) *Decoder`; `decodeState` does not exist; the
    package has exactly three `.ReadValue()` calls on a
    `*jsontext.Decoder`, in `(*Decoder).Decode`, `checkValid`, and
    `(*Number).UnmarshalJSONFrom`; exactly one of them is in a function
    named `Decode`, and that function has the receiver `*Decoder`.
  - `encoding/json/v2`: `makeStringArshaler(reflect.Type) *arshaler`;
    `arshaler.unmarshal` has type `unmarshaler`; `unmarshaler` is
    `func(*jsontext.Decoder, addressableValue, *jsonopts.Struct) error`;
    `export` exists; in the string unmarshal closure, `xd.ReadValue(&flags)`
    is the last decoder read and `va.SetString(str)` is present.
  - `jsontext`: `decodeBuffer.PreviousTokenOrValue() []byte`;
    `decoderState` embeds `decodeBuffer`; `export.Decoder` exists.
  - `jsonflags.StringTag` and `StringifyWithLegacySemantics` exist;
    `errInvalidStringTag` exists; no package-level initializer in `v2`
    calls `lookupArshaler`; in the closure, the `,string` null test is
    `string(val) == "null"` right after the first `UnquoteMayCopy`.
  - `jsontext.Decoder` has `InputOffset() int64` and `UnreadBuffer() []byte`.
- Under `GOEXPERIMENT=nojsonv2` on 1.27, only the v1 file is built, and it
  must pass. The build tags come from the test build, so no runtime
  detection is necessary.
- Shape of the io side (all lanes): `bufio.Reader` has a `Reset` method;
  `io.LimitedReader` has the exported field `R`; the result types of
  `io.TeeReader`, `io.MultiReader`, and `http.MaxBytesReader` are
  unexported and have no exported field and no `Reset` method. A change
  fails the test, so that section 6.5 can be checked again.
- Shape of the `Read` guard (all lanes, section 6.6):
  - `bufio`: the only assignments to the field `rd` are in `reset`
    (`*b = Reader{..., rd: r, ...}`); `reset` has exactly two callers,
    `Reset` and `NewReaderSize`; `reset` sets `r` and `w` to zero (buffer
    discarded); `NewReaderSize` returns its argument when it is already a
    `*Reader` of enough size; `(*Reader).Read` gets bytes only from
    `b.buf[b.r:b.w]` and `b.rd.Read`.
  - `io`: `(*LimitedReader).Read` reads only from `l.R.Read`;
    `LimitReader` returns `&LimitedReader{r, n}`.
  - Consumers read with `Read` only: `jsontext` `fetch` calls `d.rd.Read`
    (`jsontext/decode.go:240`), v1 `refill` calls `dec.r.Read`
    (`stream.go:179`), `io.ReadAll` calls `r.Read` (`io/io.go:722`), and
    `TeeReader`, `multiReader`, `LimitedReader`, and `maxBytesReader` call
    `Read` on their input.
  - Not a test (one-time check in step 2b): a `go/ast` scan of GOROOT
    `src` finds no copy of a `bufio.Reader` value outside `bufio`. This
    shows that the standard library itself never triggers residual A1
    (R15, section 6.6).

### 6.5 Exclusive reader bindings (store, request, iobridge, aspects)

Rules (the round 3 request, rules (a), (b), and (c)):

- (a) Exclusive flag. A reader binding is exclusive only when one of these
  is true when it is made:
  - the HTTP body binding at entry (`request/http.go:74-77`);
  - `request.BindReader` (the caller asserts it; no production caller
    today, only tests);
  - a single-input wrapper that user code cannot retarget
    (`io.TeeReader`, `http.MaxBytesReader`), when the lookup of its input
    is complete and finds exactly one owner, with an exclusive binding;
  - `io.MultiReader` with at most 8 inputs, when the lookup of each input
    is complete and finds the same one owner, with an exclusive binding.
  - a retargetable wrapper (`io.LimitReader`, `bufio.NewReaderSize`) with
    the same input proof, AND a `Read` guard entry in the guard table
    (section 6.6). This binding is also "guarded" (`viaGuard`).
  All other bindings are non-exclusive: `io.MultiReader` with more than 8
  inputs, or with an unbound, non-pointer, or non-exclusive input, or with
  more than one owner; a retargetable wrapper with no guard entry (full
  guard table, or the manual helper `iast/bufio.Propagate`, which has no
  `Read` guard in an unwoven `bufio`). A new bind of the same pointer
  keeps `exclusive = old && new`. An output gets `viaGuard = true` when
  it is guarded itself or when its input binding has `viaGuard`.
- (a2) Effective exclusivity. Each owner record gets a sticky
  "retargeted" bit (section 6.6). A lookup reports a binding as exclusive
  only when `exclusive && !(viaGuard && owner.retargeted)`. All consumers
  (v2 decoder, v1 `Document`, `io.ReadAll`) and all wrapper proofs use
  this effective value. Fail closed (review 2 of batch 1, finding 3): the
  `Retarget` callback that sets the bit runs under `recover`. If it does
  not return normally, the bit can be missing, and `CheckRead` removes
  the guard. Thus `iobridge` then sets a process-wide sticky bit
  (`iobridge.RetargetLost`) BEFORE `CheckRead` returns (before a byte of
  the new target flows). While it is set, `request.lookupReader` reports
  no ref with `ViaGuard` as exclusive. A binding over a guarded binding
  has `viaGuard` too (rule (a)), thus no binding that depends on a lost
  retarget is exclusive. Cost: one atomic load for each reader lookup
  while a request is active.
- (b) Complete lookups. A lookup that skipped an active owner (lock
  contention or fanout overflow) reports `complete = false`. An
  incomplete lookup is "unknown", and unknown is a miss. It never gives
  attribution, and it never makes an exclusive binding.
- (c) Pooled or reset readers (changed by decision Q8). A record of the
  binding identity at each `Read` cannot detect `(*bufio.Reader).Reset`,
  because `Reset` changes no binding. Section 6.6 checks the TARGET of
  the wrapper (`b.rd`, `l.R`) at each `Read` instead, against the input
  that was proven at construction.

- (d) Identity is type plus address (critic round 4). The current
  binding table keys readers by pointer only (`store/binding.go`,
  `dynamicPointer`, `bindingTable.find(pointer)`). Two different readers
  can have the same address: a custom body type `*Body` whose first field
  is a `bytes.Buffer` has the same address as `&body.Buffer`. Thus a
  lookup of `&body.Buffer` could find the exclusive binding of `*Body`
  and give unrelated bytes to its owner. Rule: a binding records the
  dynamic type of the reader (the `*abi.Type` word of the interface, read
  without allocation), and a lookup matches only the same type and the
  same address. A binding of the same address with a different type is a
  different binding; if the table cannot hold both, the lookup is
  incomplete (rule (b), a miss). This applies to all reader bindings, not
  only exclusive ones.
- (e) Input revalidation (review of batch 1, findings 1 and 2). A
  "derived" exclusive binding is the binding of a wrapper (`TeeReader`,
  `MaxBytesReader`, `MultiReader`, a guarded wrapper). A "root" exclusive
  binding is the body at entry or `request.BindReader`. A derived
  exclusive binding of R to O records its inputs: the entries of the
  input bindings in the binding table of O (at most 8, one fixed input
  set for each reader binding of the owner). A lookup of R reports it as
  effectively exclusive only when a complete lookup of each input finds
  exactly O (same slot and generation), with an effectively exclusive
  binding. This check is recursive, with a limit of 16 input lookups for
  each lookup of R. Over the limit, R is not effectively exclusive (a
  miss). Invariant: when an input gets a second owner, or stops being
  effectively exclusive, each wrapper over it stops being exclusive
  before the next attribution.
  The loss is sticky (follow-up review 1 of batch 1, finding 1). A check
  of the owners that are live now is not sufficient: if B binds an input
  X of a wrapper W of A, W can read or buffer bytes of B, and after B
  ends a lookup of X finds only A again. Rule (f) gives the sticky loss:
  each input X is a reader binding of A, and the bind of B makes X not
  effectively exclusive for good (the creation baseline). The lookup of
  W does a complete lookup of each input, thus W is not effectively
  exclusive either. The input set has no counter stamp of its own (it
  had one before review 2 of batch 1; appendix note 19).
  Cost: one complete lookup for each input of a derived binding at each
  revalidation (each with the one counter load of rule (f)). All only
  while a request is active.
  The `MultiReader` aspect makes one call:
  it looks up all the inputs, then makes one bind to the owner of the
  lookups, with all the inputs. There is no proof that is kept between
  two calls. If the owner ends after the lookups, the bind fails. A
  change of an input after the lookups is found by the revalidation. A
  rebind of a derived binding keeps the inputs of the old and of the new
  proof. A derived binding that gets no free input set is not exclusive.
- (f) Creation baseline and owner tokens (review of batch 1, the root
  gap; review 2 of batch 1, findings 1 and 2). A ROOT binding (the body
  at entry, `request.BindReader`) has no input to check. For a root
  reader X of A: B binds X while A is bound, the bytes of X are read or
  buffered, and B ends. A later lookup of X finds only A. Rule (f) makes
  this loss sticky for each reader binding, root or derived, with ONE
  invariant.
  - Counters. Each store has 4,096 reader bind counters
    (`Store.readerBinds`, `[4096]atomic.Uint64`, 32 KiB, no lock). The
    counter of a reader is selected by a hash of its type word and its
    address (rule (d)). Two readers can have the same counter. Each
    reader bind attempt of any owner adds 1 to the counter of its object
    (`addReaderBind`): under the table lock and BEFORE the table change,
    or with no lock when the bind fails before (a bind that cannot lock
    its table also counts, because no lookup can see it). A counter
    never decreases (64 bits: no wrap).
  - Creation baseline. Each reader binding b of owner O for reader X
    keeps `expect(b)` (`bindingTable.readerExpect`, one `uint64` for each
    of the 8 reader bindings, next to `bindingTable.readers`). The bind
    that makes b sets it to the value that its own counter add returned
    (the baseline). Each later reader bind of O that holds the table lock
    of O adds 1 to `expect` of each reader binding of O with the same
    counter, after its table change and before the unlock
    (`stampReaderBind`; at most 8 hash computations).
  - Invariant (I). Let C be the counter of X. At each time when the table
    lock of O is free or read-locked:
    `C - expect(b)` = the number of adds to C since b was made that are
    not stamped binds of O. Proof: when b is made, `expect(b) = C`
    (under the write lock of O, after the add of this bind). After that,
    each add changes C by 1. A stamped bind of O changes C and
    `expect(b)` by 1 each, and it holds the write lock of O from its add
    to its stamp, thus a reader of the table never sees one change
    without the other. No other operation changes `expect(b)`. Thus
    `C - expect(b)` only grows, and it is 0 only when no other owner (and
    no unstamped bind) added to C since b was made.
  - Effective exclusivity. A reader lookup reports b as effectively
    exclusive only when, in addition to rules (a), (a2), and (e),
    `C == expect(b)`, with C read UNDER the table read lock of O. The
    load must be under the lock (review 2 of batch 1, finding 1): if the
    lookup read C before the lock, a stamped rebind of O between the load
    and the lock adds 1 to `expect(b)` but not to the loaded C, and this
    cancels one add of another owner. By (I), `C == expect(b)` proves
    that no other owner started a reader bind with the counter of X
    since b was made. The loss is sticky (`C - expect(b)` never
    decreases), also after the other owner ends, and also when the other
    bind came before a token was taken (finding 2). A bind of O itself
    (a rebind of its root, a derived bind, a bind of another reader of O
    with the same counter) does not change the result. A bind of O that
    cannot lock its table, or a bind of another owner of a different
    reader with the same counter, is a safe miss (probability 1/4,096
    for one bind).
  - One reader binding for each entry. An entry that stops being a
    reader binding (a kind change, for example to URL) is "demoted"
    (`binding.demoted`): it never becomes exclusive again in this owner
    generation. The exclusive flag of a binding never comes back after a
    loss (`exclusive = old && new`). Thus in one generation, an entry
    index identifies at most one exclusive reader binding, from its
    creation to its first loss.
  - Tokens. A token (`store.ReaderToken`, `request.ReaderToken`,
    `iobridge.ReadToken`) keeps the owner slot, the generation, and the
    binding entry of an effectively exclusive binding. Revalidation
    (`ReaderToken.Revalidate`, `request.RevalidateReader`): a new complete
    lookup of X must find exactly one owner, with the same slot,
    generation, and entry, effectively exclusive (rules (a2), (e), and
    (f) at this lookup), and the owner is active.
  - Ordering assumption (A1), as before: a reader produces data of an
    owner only after the reader bind of that owner started (a bind comes
    at the construction of the wrapper, or before the bytes flow). The
    consumers take the token BEFORE the first byte and revalidate AFTER
    the last byte.
  - Root content assumption (A2) (step 3a review, finding 2). Rules (a)
    and (f) assume that a ROOT reader (the body at entry,
    `request.BindReader`) gives only data of its owner for all the time
    that it is bound, not only the data that it holds when it is bound. A
    reset of a bound mutable root to other data (for example
    `strings.Reader.Reset` on a reader of `request.BindReader`) keeps its
    address and its counter: no lookup and no revalidation can find it,
    and a decoder made before the reset gives the new bytes to the owner.
    This is outside the contract of `request.BindReader` (its doc comment
    says so). Production: the only root bind is the HTTP body at entry
    (`request/http.go`). The body types of the net/http server (HTTP/1
    `*http.body`; HTTP/2 `*http.http2requestBody` on Go 1.26,
    `*http2.requestBody` in `net/http/internal/http2` on Go 1.27) are not
    exported and have only `Read` and `Close`: user code cannot reset
    them. A body that a handler outside the application packages set
    before the first instrumented handler is bound as it is: (A2) is an
    assumption for that body, not a proof.
  - Proof of the token rule. The capture at T0 and the revalidation at
    T1 found the same entry e of the same generation, effectively
    exclusive. By the "one reader binding for each entry" rule, the same
    binding b was an exclusive reader binding of X for O during all of
    [T0, T1] (it did not change kind, and its flag did not change). At
    T1, `C == expect(b)`, thus no other owner started a reader bind of X
    between the creation of b and T1. A bind of another owner that
    starts after T1 starts after the last byte, thus (A1) none of its
    data flowed. The bytes flowed during [T0, T1] while b was exclusive,
    and by the proof sketch below every byte that X produced is data of
    O. For a derived X, the lookup at T1 also checks each input (rule
    (e)), and each input has its own baseline.
  - Consumers: each consumer takes the token BEFORE the first byte flows
    and calls the revalidation AFTER the bytes flowed, at attribution
    time: `io.ReadAll` (`iobridge.ReadAllBegin` / `ReadAllEnd`, done),
    `request.CloneReaderBytesForToken` (done), v1 `Document` (step 3a)
    and the v2 decoder (step 5): the token of `NewDecoder` must be
    revalidated at each `Decode`.
  Cost: the binding stays 32 bytes (`demoted` uses the padding);
  `OwnerRef` is 24 bytes (no counter value); `readerInputs` is 9 bytes
  (no stamp); each owner grows by 64 bytes for `readerExpect` and gets
  back 120 bytes from the input sets (owner 183,544 bytes, store
  14,084,296 bytes in `footprint_test.go`). One atomic add for each
  reader bind attempt, and one atomic load for each reader lookup that
  finds an exclusive binding, under the read lock that the lookup takes
  already, and one load of the test hook pointer for each active owner of
  a reader lookup (`hookLookupOwner`, nil in production). The revalidation is one more complete lookup, only when the
  token is OK.

Proof sketch (by induction over reader construction). Claim: while a
binding of R to O is effectively exclusive (rule (a2)), every byte that
R has produced since its construction is data of O. One exception is
accepted by user decision: residual R15 (a copied `bufio.Reader` value,
section 6.6, decision Q10).

- The body at entry produces only data of its owner.
- A wrapper that cannot be retargeted and has one input produces only
  bytes of that input.
- A `MultiReader` whose inputs are all exclusive to O produces only bytes
  of O.
- A guarded wrapper W with proven input I (section 6.6): each `W.Read`
  compares the current target with I (type + address, rule (d)) before
  any byte flows. On a mismatch it sets the retargeted bit of O first.
  From then on, W and every binding that depends on W (`viaGuard`) are
  not effectively exclusive. Thus every byte that W produced while it
  stayed effectively exclusive came from I. For `bufio`, buffered bytes
  also came from I: `reset` discards the buffer each time it changes
  `rd`, so the bytes in `b.buf[b.r:b.w]` always come from the current
  `b.rd`. This is false only for residual R15 (a value copy that shares
  `buf`, section 6.6).
- If I is itself guarded and gets retargeted, the same bit of O is set,
  and W has `viaGuard`, so W stops being exclusive too.
- After construction, an input of a wrapper can get a second owner (for
  example a later `request.BindReader` in another request). Then the
  input is not exclusive, and rule (e) makes each wrapper over it not
  exclusive too, before the next attribution. The bind of the second
  owner changes the counter of the input, thus the input and each
  wrapper over it stay not exclusive after the second owner ends (the
  creation baseline of rule (f)).
- A root reader can also get a second owner after its binding. A lookup
  after the second owner ended finds only the first owner, but the
  counter of the reader is larger than the baseline of the binding: the
  binding is not effectively exclusive any more. Each token of a
  consumer is a miss, also a token taken after the second owner ended,
  and a wrapper built after that gets no exclusive proof (rule (f)).
- No other construction gets the flag. A lookup that could hide a second
  owner is incomplete, so it cannot give the flag.

Each consumer captures one owner token BEFORE the first byte flows, and
checks effective exclusivity again AFTER the bytes flowed. The v2
decoder and v1 `Decode` capture at `NewDecoder` and check at each
`Decode` (after `ReadValue`, and at v1 `decodeState.init`). `io.ReadAll`
captures at entry and checks at return (section 6.7, decision Q11). Each
check is the revalidation of rule (f), not only a new lookup. The
bit is set before a foreign byte flows. Thus the consumer sees the bit
for every foreign byte that it received. The capture before the reads
makes sure that a binding made during the reads (for example a late
`BindReader`) cannot claim bytes that flowed before it: with no token
at capture, the result is a miss.

Changes:

1. `internal/taint/store/binding.go`:
   - `binding` gets `exclusive bool` and `viaGuard bool`. They use the
     padding after `kind`. `OwnerRef` gets `Exclusive bool` (the
     effective value of rule (a2)) after `Kind`. A test pins both sizes
     with `unsafe.Sizeof` (recompute them with the type word of rule (d)).
   - the owner record gets `retargeted atomic.Bool`. It is cleared when
     the slot gets a new generation (`store/owner.go:53`). New
     `MarkRetargeted(store, index uint8, generation uint64)` sets it only
     if the generation still matches. It takes no lock.
   - New `BindReaderValue(owner, object any, exclusive, viaGuard bool)
     bool`. `bind` sets the flags on a new entry, and does
     `exclusive = old && new` and `viaGuard = old || new` on an existing
     one. A kind change from URL to reader sets the new value.
     `BindObjectValue` keeps its signature (URL bindings; reader binds
     through it are non-exclusive).
   - `lookupObject` returns `(count int, complete bool)`. `complete` is
     false when, for an owner that is active at the first state check,
     `lifecycleMu.TryRLock` or `table.mu.TryRLock` fails, or when a found
     owner does not fit in `out`. New
     `LookupReaderValue(store, object any, out []OwnerRef) (int, bool)`.
     `LookupObject` and `LookupObjectValue` keep their signatures.
   - rule (e): new `BindDerivedReaderValue(owner, object any, viaGuard
     bool, inputs []any, refs []OwnerRef) bool`. It checks under the
     table lock that each ref refers to owner and to the current binding
     of its input, then records the input entries. `OwnerRef` gets the
     entry index (padding). The binding table gets 8 input sets
     (`[8]uint8` and a count each). Only `LookupReaderValue` computes
     `Exclusive`, with the revalidation of rule (e);
     `LookupObject` and `LookupObjectValue` set it to false.
   - rule (f): the store gets the reader bind counters
     (`[4096]atomic.Uint64`); `bindingTable.readers` and
     `bindingTable.readerExpect` (the creation baselines),
     `binding.demoted`, `ReaderToken`, `OwnerRef.ReaderToken()`, and
     `ReaderToken.Revalidate(OwnerRef)`.
2. `internal/taint/request/reader.go` and `http.go`:
   - the entry binding and `BindReader` use `exclusive = true`;
   - `PropagateReader(input, output)` (TeeReader, MaxBytesReader): when
     `complete && count == 1 && refs[0].Exclusive`, one derived bind
     (`store.BindDerivedReaderValue`, rule (e)) to that owner, with input
     as its input; else a non-exclusive bind to each found owner;
   - new `PropagateSharedReader(input, output)` (the manual helper
     `iast/bufio.Propagate` only): today's behavior, `exclusive = false`;
   - new `PropagateGuardedReader(input, output)` (bufio, LimitReader;
     section 6.6);
   - new `PropagateJoinedReader(inputs [8]any, count int, output)`
     (`io.MultiReader`, rule (e)): when `count` is 1 to 8 and a complete
     lookup of each input finds the same one owner, with an effectively
     exclusive binding, one derived bind with all the inputs; else a
     non-exclusive bind to each owner of the first 8 inputs;
   - new `ReaderOwner(input) ReaderToken` (rule (f); `OK()` and
     `Identity() (index uint8, generation uint64, ok bool)`) for
     `ReaderOwnerToken` (section 6.1), and for the `io.ReadAll` capture
     (section 6.7), and `RevalidateReader(token, input) bool`;
   - `ReadAllBytes(input, data)` becomes
     `ReadAllBytesForToken(token, input, data)` (section 6.7), and
     `CloneReaderBytesForToken(token, input, data)` is new. The old name
     `ReadAllBytes` stays as a test helper that calls `ReaderOwner`, then
     `ReadAllBytesForToken`;
   - the lookup function is a package variable, so that a request test can
     replace it with a stub that returns `complete = false`.
3. `internal/taint/iobridge/bridge.go` (stays at `sync/atomic` and
   `unsafe`):
   - the callbacks get `propagateShared`, `propagateJoin`, and
     (section 6.6) `propagateGuarded` and `retarget`; step 3a adds
     `owner` (for `ReadAllBegin`); the `readAll`
     callback gets the owner token:
     `readAll func(input any, data []byte, index uint8, generation uint64)`;
   - new `type ReadToken` (a copy of the fields of `store.ReaderToken`,
     rule (f): the store pointer as `any`, generation, slot, entry, `OK`;
     32 bytes, on the stack, no allocation), `ReadAllBegin(input any) ReadToken` (calls
     `owner`), and `ReadAllEnd(token ReadToken, input any, data []byte)`
     (returns at once when `!token.ok`; else calls `readAll`). They
     replace `ReadAll` in the `io.ReadAll` template (section 6.7);
   - section 6.6 adds the guard table, `CheckRead`, `PropagateGuarded`,
     `Guard`, `Unguard`, `Same`, and `ReleaseOwner`; rule (a2) adds
     `RetargetLost` (fail closed);
   - new `PropagateShared(input, output any)`, `MaxJoinInputs = 8`, and
     `PropagateJoin(inputs [MaxJoinInputs]any, count int, output any)`.
     The array is passed by value: no allocation.
4. Aspects:
   - `iast/bufio/bufio.go` (manual helper): `Propagate` →
     `PropagateShared`;
   - `iast/bufio/orchestrion.yml` (`NewReaderSize`) and
     `iast/io/orchestrion.yml` (`io.LimitReader`): `Propagate` →
     `PropagateGuarded`, plus the `Read` guard aspects (section 6.6);
   - `io.TeeReader` and `net/http.MaxBytesReader` are not changed
     (`Propagate` now computes the flag);
   - `io.MultiReader` template, one call (rule (e)):

```go
defer func() {
	var __dd_iast_inputs [iastiobridge.MaxJoinInputs]any
	for __dd_iast_index, __dd_iast_reader := range {{ $inputs }} {
		if __dd_iast_index >= len(__dd_iast_inputs) {
			break
		}
		__dd_iast_inputs[__dd_iast_index] = __dd_iast_reader
	}
	iastiobridge.PropagateJoin(__dd_iast_inputs, len({{ $inputs }}), {{ $result }})
}()
```

   A change of an input after the lookups (a second owner, the end of
   the owner) makes the output non-exclusive: the bind fails, or the
   revalidation of rule (e) finds the change.

All consumers read the effective flag in this change: the v2 decoder,
v1 `Document`, and `io.ReadAll` (section 6.7, decisions Q6 and Q9). The
owner fanout of `PropagateReader` stays: it only makes more
non-exclusive bindings, which no consumer attributes.

Cost: the binding (32 bytes) does not grow (padding). `OwnerRef` stays
24 bytes (the entry index uses the padding). Rule (e) adds 8 input sets
of 9 bytes to each binding table; rule (f) adds 8 reader entries and 8
baselines (72 bytes) to each binding table and 32 KiB of counters to the
store (see rule (f) for the measured sizes). One more bool test in
each lookup. A reader lookup of a derived exclusive binding does one more
lookup for each input, recursively, at most 16. For `io.MultiReader`: at
most 8 more lookups, only while a request is active (`LookupObject`
returns at once when no owner is in use, `request/http.go:43-49`).

### 6.6 Per-`Read` guard for retargetable wrappers (decision Q8)

Goal: `io.LimitReader(x, n)` and `bufio.NewReader(Size)(x)` keep an
exclusive binding. Then `json.NewDecoder(bufio.NewReader(r.Body))` and
`json.NewDecoder(io.LimitReader(r.Body, n))` propagate on every value. The
guard must detect each retarget before a byte of the new target flows.

Retarget paths (checked in the Go 1.27.1 source; Go 1.26.6 is the same):

- `*io.LimitedReader`: `l.R = other`, or `*l = io.LimitedReader{...}`. No
  method changes `R`. `LimitReader` (`io/io.go:461`) is the only
  constructor that the aspects see. A composite literal
  `&io.LimitedReader{R: r, N: n}` is unbound (miss).
- `*bufio.Reader`: `rd` is unexported. Only `reset`
  (`bufio/bufio.go:87-94`) writes it. `reset` has two callers: `Reset`
  (`:74-85`) and `NewReaderSize` (`:57`, on a new `Reader`). `Reset(b)`
  with `b == r` returns at once (`:78-80`). `NewReaderSize` returns its
  argument unchanged when it is already a `*Reader` with a large enough
  buffer (`:52-55`): no retarget. User code can also copy a whole value
  (`*p = *q`).
- Buffered bytes from before a `Reset`: `reset` writes
  `*b = Reader{buf: buf, rd: r, lastByte: -1, lastRuneSize: -1}`, so
  `r = w = 0`. The old buffered bytes are never produced again. (They stay
  in `buf` until the next `fill` writes over them.) Thus the bytes in
  `b.buf[b.r:b.w]` always come from the current `b.rd`.
- Residual A1 (R15), ACCEPTED by user decision Q10 (critic round 5,
  finding 1). The exact scenario, checked in the Go 1.27.1 source:
  1. `p` is a guarded `*bufio.Reader`, exclusive to owner A, over input
     I. It has buffered bytes: `p.r < p.w`.
  2. User code copies the value: `q := *p`. The slice header of `buf` is
     copied, so `q.buf` and `p.buf` share one backing array.
  3. `q.Reset(other)` calls `reset(q.buf, other)`, which keeps the same
     `buf` (`bufio/bufio.go:74-94`) and sets `q.r = q.w = 0`.
  4. A small `q.Read` (`len(p) < len(q.buf)`) calls
     `q.rd.Read(q.buf)` and fills `buf[0:n]` with bytes of `other`
     (`bufio/bufio.go:216-253`). `q` has no guard entry (its address is
     not `p`), so its `CheckRead` returns.
  5. `p.Read` returns bytes from `buf[p.r:p.w]`, which now hold bytes
     of `other`. `p.rd` is still I, so the guard of `p` sees no
     retarget.

  Effect: the bytes of `other` are attributed to A (a mis-attribution
  to the owner of `p`). It is never a crash (the guard only compares
  two words), and it never uses more memory (no new entry, no new
  binding). It needs customer code that copies a `bufio.Reader` by
  value and then resets and reads the copy. In that case the
  application itself already gets the wrong bytes from `p`: this is a
  program bug in the customer code. The standard library does no such
  copy (one-time scan, section 6.4). This residual goes against the
  rule "ALWAYS keep accurate provenance information" of `AGENTS.md`.
  Romain accepts it by decision Q10, to keep
  `json.NewDecoder(bufio.NewReader(r.Body))` tainted.

  Documentation (step 10): the README "Known limits" section and the
  package doc of `iast/bufio` get this note: "Do not copy a
  `bufio.Reader` by value. If code copies a `bufio.Reader`, then resets
  and reads the copy, the two values share one buffer. Then IAST can
  attribute the bytes of the new reader of the copy to the request of
  the original reader."

  Test (step 3a, all lanes, woven):
  `TestKnownLimitBufioValueCopySharesBuffer` in
  `iast/bufio/bufio_test.go`. It asserts the CURRENT behavior, so that
  a change is visible: in request A, `p := bufio.NewReaderSize(bodyA,
  16)` (body `aaaaaaaaaaaaaaaaaaaaaaaa`), `p.Peek(16)`, `q := *p`,
  `q.Reset(strings.NewReader("cccccccc"))`, `q.Read(make([]byte, 4))`,
  then `data, _ := io.ReadAll(p)`. Assert: `data` starts with
  `cccccccc` (the program bug); `data` is tainted with the source of A
  (the mis-attribution); the retargeted bit of A is not set; no panic.
  The test comment says: "Known limit R15. If this test fails because
  the bytes are not attributed to A, the limit is fixed: update R15, the
  README, and the `iast/bufio` package doc."

Why a check at `Read`, and no `Reset` hook: a `Reset` hook alone misses
`*p = *q` and `lr.R = x`. A target check at `Read` detects all retargets
(`Reset`, value copy, field write), because each one changes the target
field that `Read` uses. A `Reset` with no `Read` after it (for example
`br.Reset(nil)` before `pool.Put(br)`) keeps exclusivity. This is correct:
no foreign byte flowed. Thus the plan adds no `Reset` hook.

Why only `Read`: the consumers that attribute bytes (v2 `fetch`, v1
`refill`, `io.ReadAll`) and all wrappers that can be exclusive read their
input with `Read` only (section 6.4). Other `bufio` methods (`Peek`,
`ReadByte`, `WriteTo`, ...) fill the buffer from the current `rd` only,
and the next `Read` checks `rd`.

Guard table (in `internal/taint/iobridge`, fixed size):

```go
type guardEntry struct { // immutable after publication, 48 bytes
	self       any    // the wrapper (strong reference)
	input      any    // the proven input (strong reference)
	generation uint64 // owner generation
	index      uint8  // owner slot
}

var guardCount atomic.Int32
var guards [128]atomic.Pointer[guardEntry] // 1 KiB, static
```

- Key: the data word of `self`. Probe: 4 fixed slots from
  `(pointer >> 4) % 128` (the same probe as `jsonbridge.decoderStates`).
- Identity: the type word and the data word of each `any` (rule (d)),
  read with `unsafe` and compared as two words. No `==` on interfaces (it
  can panic on an uncomparable dynamic type). No allocation, no call.
  The template passes `b.rd` and `l.R` as `any`, so the type word is the
  dynamic type, not an `itab`.
- Strong references: the entry keeps `self` and `input` alive, so
  neither address can be reused while the entry exists.
- Bound: at most 128 entries (about 7 KiB with the static array). If the
  4 probe slots are full, there is no entry: the wrapper binding is
  non-exclusive (safe miss), and the owner counts a drop in telemetry.
- Lifetime: an entry is removed (a) when its check fails, after the
  retargeted bit is set, and (b) when its owner finishes: the request
  finish path calls `iobridge.ReleaseOwner(index, generation)` after the
  owner stops being active. It scans the 128 slots only when
  `guardCount != 0`. No entry lives after its owner finishes.
- Order at construction: the entry is published BEFORE the exclusive
  binding. Thus an effectively exclusive guarded binding never exists
  without its entry.

API (`iobridge`, stays at `sync/atomic` and `unsafe`):

```go
// CheckRead is inlinable. It is the only code on the Read hot path.
func CheckRead(self, target any) {
	if guardCount.Load() != 0 {
		checkRead(self, target) // direct call, not inlined
	}
}
```

- `checkRead` probes all 4 slots. For each entry of `self` with a
  different target: call the registered `retarget(index, generation)`
  callback (the only indirect call, on the rare path), then CAS the slot
  to nil and decrement `guardCount`.
- `Guard(self, input any, index uint8, generation uint64) bool` inserts
  an entry. Only `request` calls it. The duplicate check is atomic
  (review of batch 1, finding 3): after the insertion CAS, `Guard` scans
  the 4 probe slots again; if it finds another entry of `self`, it
  removes its own entry and returns false. The atomic operations are
  sequentially consistent, so of two concurrent calls, at least one sees
  the other (both can fail: a safe miss). `checkRead` checks all the
  matching probe slots, not only the first one. A test hook
  (`SetGuardHookForTest`) runs between the first duplicate check and the
  insertion, so that a test can stop two calls at this point.
- `PropagateGuarded(input, output any)` calls the registered
  `propagateGuarded` callback.
- `Same(a, b any) bool` compares two words.
- `Unguard(self any)` and `ReleaseOwner(index uint8, generation uint64)`.

Request side:

- `PropagateGuardedReader(input, output)`: a complete lookup of `input`.
  If it finds exactly one owner O, effectively exclusive, call
  `iobridge.Guard(output, input, O)`. If that returns true, bind `output`
  to O with `exclusive = true` and `viaGuard = true`. If the bind fails
  (for example the per-owner limit `MaxReaderBindings`), remove the entry
  at once (`iobridge.Unguard(output)`). In all other cases, do today's
  fanout with `exclusive = false`.
- The `retarget` callback calls `store.MarkRetargeted(index, generation)`
  and counts the event in owner telemetry.

Aspects:

```yaml
- id: io.LimitedReader.Read guard
  join-point:
    all-of:
      - import-path: io
      - function-body:
          function:
            - receiver: "*io.LimitedReader"
            - name: Read
  advice:
    - prepend-statements:
        imports:
          iastiobridge: github.com/DataDog/dd-iast-go/internal/taint/iobridge
        template: |-
          iastiobridge.CheckRead({{ .Function.Receiver }}, {{ .Function.Receiver }}.R)

- id: bufio.Reader.Read guard
  join-point:
    all-of:
      - import-path: bufio
      - function-body:
          function:
            - receiver: "*bufio.Reader"
            - name: Read
  advice:
    - prepend-statements:
        imports:
          iastiobridge: github.com/DataDog/dd-iast-go/internal/taint/iobridge
        template: |-
          iastiobridge.CheckRead({{ .Function.Receiver }}, {{ .Function.Receiver }}.rd)
```

The `NewReaderSize` template skips the reuse case, so the binding and the
entry of the returned reader stay as they are:

```go
defer func() {
	if {{ $result }} != nil && {{ $result }}.Size() <= iastiobridge.MaxBufferedReaderSize &&
		!iastiobridge.Same({{ $input }}, {{ $result }}) {
		iastiobridge.PropagateGuarded({{ $input }}, {{ $result }})
	}
}()
```

The `LimitReader` template calls `PropagateGuarded` instead of
`Propagate`.

Cost:

- No request active, or no guarded wrapper live: one atomic load and one
  branch in each `(*bufio.Reader).Read` and `(*io.LimitedReader).Read`
  of the process. No call, no allocation.
- A guarded wrapper is live: one direct call and at most 4 atomic loads
  in each of these `Read` calls of the process, also on readers that are
  not guarded (for example the `net/http` connection readers). No
  indirect call on the normal path.
- Construction: one allocation of 48 bytes for each guarded wrapper, only
  when the input proof holds. Owner finish: one scan of 128 slots, only
  when `guardCount != 0`.
- `(*io.LimitedReader).Read` is small. The prepend can stop the compiler
  from inlining it into its callers. Step 8 checks this with
  `-gcflags=-m` and records it.
- Gates: section 7.2.

A user retarget that runs at the same time as a `Read` on another
goroutine is a data race in user code. It is out of scope, as for the
other store rules.

### 6.7 v1 `Document` and `io.ReadAll` use the exclusive rule (decisions Q6, Q9)

Changes:

1. v1 `Decode`: the v1 `init` (section 4) sets `__dd_iast_decodeBind` to
   `BindDecoder(&dec.__dd_iast_binding, &dec.d)`. `NewDecoder` captured
   that binding (the same aspect as v2, section 6.3). `Document(state,
   data)` at `decodeState.init` reads the `*ReaderBinding` from the slot
   and calls `CloneForOwner` with the captured token. The checks are the
   same as v2: the token is valid, the lookup is complete, it finds
   exactly the captured owner, and the binding is effectively exclusive.
   A failed check closes the binding (sticky). An oversized value is a
   miss and does not close it. `Bind(nil, d)` stays for the
   `decodeState.unmarshal` lifetime aspect. v1 `json.Unmarshal` does not
   change (no reader, root lookup of the caller slice).
2. `io.ReadAll` (changed by decision Q11, critic round 5, finding 2):
   the template captures an exclusive owner token BEFORE the first read,
   and checks it again after the reads:

   ```go
   {{- $input := .Function.Argument 0 -}}
   {{- $result := .Function.Result 0 -}}
   __dd_iast_token := iastiobridge.ReadAllBegin({{ $input }})
   defer func() { iastiobridge.ReadAllEnd(__dd_iast_token, {{ $input }}, {{ $result }}) }()
   ```

   - `ReadAllBegin` calls `ReaderOwner(input)`. The token is `ok` only
     when a complete lookup finds exactly one owner, with an
     effectively exclusive binding. It returns at once when no owner is
     in use (`request/http.go:43-49`).
   - `ReadAllEnd` returns at once when the token is not `ok`: miss. Else
     `ReadAllBytesForToken(token, input, data)` revalidates the token
     (section 6.5, rule (f): index + generation + entry + active, a
     complete lookup of `input` again, which must find exactly this
     owner, with the same effectively exclusive binding, and no reader
     bind of another owner of `input` since that binding was made), and
     then adopts `data`
     into this owner only. If a check fails: miss.
   - The oversize drop count stays, for that one owner only, and only
     when the token is still valid.
   - Why: a binding that is made during `io.ReadAll` (for example a late
     `request.BindReader` on a reader that was unbound at entry) must
     not claim the bytes that flowed before it. With no token at entry,
     the result is a miss. A second owner that is added during the
     reads makes the second lookup find two owners: miss. A second owner
     that is added and ends during the reads, or before the token, changes
     the counter of the reader: miss (rule (f)).
   - Cost: one more lookup for each `io.ReadAll`, only while an owner is
     in use. No allocation (the token is on the stack).
3. `CloneReaderBytes` stays as a helper for tests (many tests use it as
   a probe), with the same exclusive single-owner rule. The token form
   `CloneReaderBytesForToken(token, input, data)` (rule (f), done) is the
   form for consumers.

User-visible behavior changes. "Before" is the current Phase 8 behavior.
Rows marked "v1" apply to `Decode` on lanes A and C. The other rows apply
to v1 `Decode` and to `io.ReadAll` on all lanes.

| Input | Before | After |
|---|---|---|
| Reader bound to two live owners (`io.MultiReader(bodyA, bodyB)`, `BindReader` in two requests) | adopted by both owners | miss |
| `io.MultiReader` with a clean or unbound input (`io.MultiReader(bytes.NewReader(peeked), r.Body)`, `io.MultiReader(strings.NewReader(""), r.Body)`) | adopted by the body owner | miss |
| `io.MultiReader` with more than 8 inputs | adopted by the owners of the first 8 (can be wrong) | miss |
| Contended lookup (lock busy, fanout overflow) | adopted by the owners that were found | miss |
| Retargeted `bufio.Reader` or `io.LimitedReader` (`Reset`, `lr.R = x`, value copy) | adopted by the first owner (wrong) | miss |
| Manual helper `iast/bufio.Propagate` (unwoven `bufio`) | adopted | miss (no `Read` guard) |
| `io.ReadAll` on a reader that gets its binding (or a second owner) after `io.ReadAll` started | adopted by the owners bound at the end | miss |
| v1: decoder made by `NewDecoder` while no request is active, or on a reader bound after `NewDecoder` | owners bound at `Decode` | miss |
| v1: later values of a decoder after one failed proof (for example one contended lookup) | adopted by the owners bound at each `Decode` | miss for the life of the decoder |

No change: `r.Body`, `http.MaxBytesReader`, `io.TeeReader`,
`io.LimitReader` and `bufio.NewReader(Size)` that are not retargeted,
`io.MultiReader` of at most 8 inputs that are all exclusive to one owner,
and decoder reuse across requests (first owner, or miss).

Tests to change:

- `iast/io/io_test.go` `TestMultiReaderInspectionBoundAndCleanup`: the
  8+1 composition is now a miss. Assert: `data` is not tainted;
  `includedAnalysis.SourceCount() == 0`;
  `excludedAnalysis.SourceCount() == 0`;
  `request.CloneReaderBytes(composed, ...)` is nil before and after
  `Finish`. Add a control: `io.MultiReader(included)` alone is tainted
  with `included-`, and gives nil after `includedScope.Finish()`.
- `iast/io/io_test.go` `TestReadAllThroughSupportedWrappers`: its chain
  has `io.MultiReader(strings.NewReader(""), tee)`, a clean input, so it
  becomes a miss. Split it: (a) `io.MultiReader(tee)`: tainted (keeps the
  coverage of the wrapper chain `LimitReader` → `TeeReader` →
  `MultiReader` → `bufio`); (b) with the clean input: miss.
- `internal/taint/request/internal_test.go`:
  `TestReadAllBytesPublishesEveryBoundOwner` becomes
  `TestReadAllBytesRequiresOneExclusiveOwner` (two owners: no source in
  either; one owner: one source).
  `TestCloneReaderBytesPublishesIndependentDocument` binds one owner, and
  gets a two-owner case that returns nil.
- `iast/bufio/bufio_test.go` `testPropagation` (manual case): expect a
  miss (the manual helper is non-exclusive).
- `iast/io/reader_limits_test.go`: must still pass (8 guarded
  `LimitReader` results use 8 of the 128 guard slots).

Tests to add (decision Q11, step 3a, all lanes):

- `TestReadAllLateBindIsMiss`: a reader that returns 7 bytes for each
  `Read` and that calls `request.BindReader(reader)` (exclusive, owner A)
  inside its second `Read`. `io.ReadAll(reader)`: the result is not
  tainted, and A has no new source. Control: the same reader bound
  before `io.ReadAll`: tainted with the source of A.
- `TestReadAllSecondOwnerDuringReadIsMiss`: a reader bound to A at entry;
  inside one `Read`, bind it also to a live owner B. The result is not
  tainted; no new source in A or B.
- Unit tests in `iobridge`: `ReadAllEnd` with a token that is not `ok`
  does not call `readAll`; `testing.AllocsPerRun` is 0 for
  `ReadAllBegin` + `ReadAllEnd` with no owner in use.

## 7. Steps

Each step lists its exit criteria and an estimate for one engineer.
"All lanes" means the three required lanes of section 7.1.

1. **Inventory Go 1.27 failures (1-2 h).** Run the full woven suite on
   1.27.1 with the v1 JSON `Decode` aspect disabled locally. List all other
   failures (other `orchestrion.yml` files). Exit: a written list; JSON is
   the only blocker, or new plans exist for the other items.

   **Result (done).** Go 1.27.1 (`jsonv2` default), darwin/arm64, a copy of
   the repository with the v1 `Decoder.Decode` aspect removed, own
   `GOCACHE`. Commands: `go tool orchestrion go test -count=1 ./...` in the
   root module and in the 5 other modules, and
   `.github/woven-runtime.sh default {linknames,test,g0,link}`. All
   packages build woven. The only failures are JSON failures:
   - root module, `iast/encoding/json`: `TestSourceShape` (the v1 targets
     `decodeState.*`, `Decoder.r`, `Decoder.d` do not exist: step 6) and
     `TestInstrumentedPropagationTelemetry` (a result of the removed
     aspect in the copy only);
   - `iast/integration/testapp`: 9 tests, all because JSON does not
     propagate on v2 (steps 4, 5, 7): `TestHTTPBodyReaderJSONWriterToSQL`,
     `TestJSONDecoderMoreThanEightDocuments`,
     `TestJSONDecoderPropagatesOwnerBoundBody`,
     `TestJSONDecoderReinitializedWithCleanReader`,
     `TestJSONDestinationClassesPreserveTheirContracts`,
     `TestJSONUnmarshalPropagatesNestedNamedStringTag`,
     `TestJSONUnmarshalPropagatesNestedStrings`,
     `TestJSONUnmarshalStringTagsInNestedAndMapValues`,
     `TestRepeatedJSONLiteralsKeepSeparateSourcesAndMarks`.
   - `iast/database/sql/testapp`, `iast/runtime/testapp`,
     `iast/os/exec/testapp`, `benchmarks/overhead`, and the four
     woven-runtime checks pass.
   JSON is the only blocker. No other plan is necessary (R8 closed).
2. **Dispatch variables for `Decode` (3-4 h).** Section 4. Exit: all Phase 8
   tests pass on lanes A and C; lane B compiles woven; a local build on
   Go 1.26.6 with `GOEXPERIMENT=jsonv2` compiles woven.

   2a. **Exclusive reader bindings (6-8 h).** Section 6.5. Store flag,
   complete lookup, and size test: 2-3 h. Request, iobridge, and the
   bufio, LimitReader, and MultiReader templates: 2-3 h. Unit tests: 2 h:
   entry binding is exclusive; TeeReader and MaxBytesReader of an exclusive
   input are exclusive; TeeReader of a bufio reader is not (until step
   2b); bufio and LimitReader results are not (until step 2b);
   MultiReader of one exclusive input is;
   MultiReader with 9 inputs, with one clean input, or with two owners is
   not; a new bind keeps `old && new`; `lookupObject` reports
   `complete = false` when a test in package `store` holds an owner's
   `lifecycleMu` or binding-table lock, and on fanout overflow;
   `unsafe.Sizeof(binding{}) == 32` and `unsafe.Sizeof(OwnerRef{}) == 24`
   (recompute both sizes with the new type word of rule (d); the
   baselines of rule (f) are in the binding table);
   type-plus-address identity (rule (d)): a custom `*Body` with an
   embedded first-field `bytes.Buffer`, bound exclusively to owner A, while
   owner B is also live; a lookup of `&body.Buffer` does not find A's
   binding, and `json.NewDecoder(&body.Buffer).Decode` attributes nothing
   to A (negative control: pointer-only lookup makes the test fail).
   Add 1 h to this step.
   Exit: all existing `iast/io`, `iast/bufio`, `iast/net/http`, and
   `internal/taint/...` tests pass on all lanes (including
   `TestMultiReaderInspectionBoundAndCleanup`, which changes only in step
   3a); section 7.1 commands 3, 6, 7 pass.

   2b. **Per-`Read` guard for `io.LimitReader` and `bufio` (5.5-7 h,
   decision Q8).** Section 6.6. Parts: `iobridge` guard table, `CheckRead`,
   `Guard`, `Unguard`, `ReleaseOwner`, `Same`: 2 h. Store `retargeted`
   bit, `viaGuard`, `MarkRetargeted`, `PropagateGuardedReader`, the
   finish-path release: 1.5-2 h. The two `Read` aspects and the
   `NewReaderSize`/`LimitReader` templates: 0.5-1 h.
   Tests (1.5-2 h). In this step the consumers (v1 `Decode`,
   `io.ReadAll`) still use the old rule, and the v2 decoder does not
   exist. Thus these tests check the BINDING only, with
   `request.ReaderOwner(w)` (`ok` means "effectively exclusive, one
   owner"). The consumer tests move to step 3a (v1 `Decode`, all
   `io.ReadAll` cases) and step 5 (v2 `Decode`), critic round 5,
   finding 3.
   - retarget after bind: `ReaderOwner(w)` is `ok` before and not `ok`
     after the next `w.Read`, and the retargeted bit of A is set, for:
     `lr.R = strings.NewReader(clean)`, `lr.R = bodyB` (B live),
     `*lr = io.LimitedReader{R: other, N: n}`, `br.Reset(clean)`,
     `br.Reset(bodyB)`, `*br = *bufio.NewReader(clean)`;
   - a retarget with no `Read` after it keeps `ok` (no byte flowed);
   - chain: `lr := io.LimitReader(br, n)`, then `br.Reset(clean)` and one
     `lr.Read`: `ReaderOwner(lr)` is not `ok` (`viaGuard`);
   - normal use: 100 `Read` calls through `bufio.NewReader(bodyA)`,
     `io.LimitReader(bodyA, n)`, and
     `io.LimitReader(bufio.NewReader(bodyA), n)` keep `ok`;
   - no false retarget: `br.Reset(nil)` sets no bit; `br.Reset(bodyA)`
     (same input) keeps `ok`; `bufio.NewReaderSize(br, 16)` returns
     `br` and keeps its binding and entry;
   - type + address (rule (d)): `lr.R` changed from `*Body` to
     `&body.Buffer` (same address) is a retarget;
   - bounds: when the 4 probe slots are full, the wrapper is not `ok`
     and a drop is counted; a failed bind removes the entry; owner
     finish sets `guardCount` back to 0 and all slots to nil;
   - `iobridge` unit tests: nil target, uncomparable dynamic type (no
     panic), `Guard`/`CheckRead`/`ReleaseOwner` under `-race`;
     `testing.AllocsPerRun` is 0 for `CheckRead` with and without live
     guards.
   Exit: all tests of step 2a and these tests pass on all lanes; section
   7.1 commands 3, 6, 7, 8 pass; the dependency test of `iobridge`
   passes; the one-time GOROOT scan of section 6.4 finds no
   `bufio.Reader` value copy.

   **Steps 2, 2a, and 2b: done.** See "Appendix: Implementation notes
   (steps 1 to 2b)" for the deviations. One-time GOROOT scan: a
   `go/packages` + `go/types` scan of `std` (Go 1.27.1: 381 packages;
   Go 1.26.6: 360 packages; `bufio` excluded) lists each value use of the
   type `bufio.Reader` (a dereference or a variable used as a value, a
   variable, field, or parameter of value type). It found 0 uses. A
   control package with `q := *p` and a value field gave 4 findings.
3. **Bridge and request helpers (4-5 h).** `Active`, `EnableV2`, `String`,
   `ReaderBinding.Capture`, `ReaderDocument`, `ReaderOwnerToken`,
   `CloneForOwner`. Unit tests: bad tokens, nil reader, length mismatch,
   v2 flag off, panic in callback, inactive fast path with 0 allocations;
   `Capture` with zero owners, one exclusive owner, one non-exclusive
   owner, two owners, and an incomplete lookup (only the exclusive case
   is "exclusive"; the others are "closed"); a finished owner and a reused
   owner slot (new generation) fail revalidation and close the decoder; a
   new owner at `Decode` closes it; the request lookup stub that returns
   `complete = false` closes it; `ReaderDocument` creates the clone when
   the owner is active and the indexed-root count is zero. Exit: section
   7.1 commands 3, 6, 7 pass; dependency test passes.

   3a. **v1 `Document` and `io.ReadAll` exclusive rule (6.5-9.5 h,
   decisions Q6, Q9, Q10, Q11).** Section 6.7. This step comes after
   step 2b, so the guarded wrappers are already exclusive. Parts:
   - `BindDecoder` and the v1 `Document` path through `CloneForOwner`:
     1.5-2 h.
   - `io.ReadAll` token (decision Q11): `ReadToken`, `ReadAllBegin`,
     `ReadAllEnd`, `ReadAllBytesForToken`, the new template, and the
     "Tests to add" of section 6.7: 1-1.5 h. **Done early** with rule
     (f) of section 6.5 (appendix note 18): the token is taken before the
     first read and REVALIDATED (rule (f)) after the reads, not only
     looked up again. `CloneReaderBytes` rule: 0.5-1 h (the token form
     `CloneReaderBytesForToken` is done; the one-shot `CloneReaderBytes`
     of the v1 `Document` callback still uses the fanout rule).
   - v1 `Document` must call the revalidation of rule (f)
     (`request.RevalidateReader`, through `CloneForOwner` or
     `CloneReaderBytesForToken`) with the token of `NewDecoder` at each
     `decodeState.init`. A check of the owner only is not sufficient.
     Test: B binds the reader of A after `NewDecoder` and ends before
     `Decode`: miss.
   - Change the tests of section 6.7 ("Tests to change"): 1.5-2 h.
   - New v1 tests (lanes A and C): two owners, `io.MultiReader` with a
     clean input, the contended-lookup stub, a decoder made while no
     request is active, a decoder closed by one failed proof: 0.5-1 h.
   - Consumer tests moved from step 2b (1-1.5 h), with
     `json.NewDecoder(w).Decode` on lanes A and C, and `io.ReadAll(w)` on
     all lanes:
     - retarget after bind is a miss (no new source in A, no source in
       B), for the six retargets of step 2b;
     - retarget between two `Decode` calls: the first value is tainted,
       all later values miss;
     - chain `io.LimitReader(br, n)`, then `br.Reset(clean)`: miss;
     - normal use keeps taint: a `More()` loop over 100 objects through
       `bufio.NewReader(r.Body)`, `io.LimitReader(r.Body, n)`, and
       `io.LimitReader(bufio.NewReader(r.Body), n)`: the string of EVERY
       item is tainted with the body source; `io.ReadAll` of each is
       tainted;
     - no false retarget: `br.Reset(nil)` after the last `Decode` keeps
       the earlier values tainted.
   - Known-limit test `TestKnownLimitBufioValueCopySharesBuffer`
     (section 6.6, residual R15, all lanes): 0.5 h.
   Exit: section 7.1 commands 2 to 8 pass on all lanes, with one
   exception on lane B, from the plan order: on lane B, `TestSourceShape`
   (`iast/encoding/json`) fails, because it pins the v1 symbols, and the
   variant-aware shape test is step 6; and command 4 fails in
   `iast/integration/testapp` with the 9 JSON tests of step 1 (JSON does
   not propagate on v2 until steps 4, 5, and 7). Thus at step 3a: lanes A
   and C run commands 1 to 8 with no failure; lane B runs commands 1, 6,
   and 7 with no failure, and commands 2 to 5 and 8 with no failure other
   than `TestSourceShape` and the 9 testapp JSON tests of step 1 (step 3a
   review, finding 3). The README lists the behavior changes of section
   6.7.
   Release requirements from the review of batch 1 (deferred to this
   step, not optional): `io.ReadAll` (`internal/taint/request/reader.go`,
   `ReadAllBytes`, today `LookupObject` ignores the `Exclusive` flag and
   incomplete lookups) must require a complete lookup with one
   effectively exclusive owner (rules (a2), (b), (e)). Tests: the
   `MultiReader` 8+1 composition, a saturated guard table, and retargeted
   wrappers, all through `io.ReadAll`. `iast/io/io_test.go` (about lines
   117-145) then changes. **Done** for `io.ReadAll` (appendix note 18):
   the `MultiReader` 8+1 composition and the clean-input chain of
   `iast/io/io_test.go` changed as section 6.7 says. The saturated guard
   table and the retargeted wrappers through `io.ReadAll` are done at
   step 3a (`iast/io/readall_exclusive_test.go`).
   Release requirement from review 2 of batch 1 (finding 6, known and
   deferred to this step, not optional): the v1 `Document` callback still
   uses the one-shot `CloneReaderBytes` with the old fanout rule
   (`internal/taint/request/reader.go`, `CloneReaderBytes`;
   `iast/encoding/json/json.go`, the `Document` callback). It gives the
   bytes to each bound owner, also for a non-exclusive binding. Step 3a
   must move it to the token of `NewDecoder` and the revalidation of rule
   (f). Exit tests (lanes A and C), each through
   `json.NewDecoder(r).Decode`: `io.MultiReader(bodyA, bodyB)` of two
   live requests A and B: miss for A and for B (no new source in either
   request); `io.MultiReader(clean, bodyA)`: miss; `io.MultiReader`
   with 9 inputs: miss; control `io.MultiReader(bodyA)`: tainted in A
   only. Until this step, the v1 decoder keeps the old behavior, and the
   README says so.

   **Steps 3 and 3a: done**, with the lane B exceptions of the exit list
   above (`TestSourceShape` until step 6; the 9 testapp JSON tests until
   steps 4, 5, and 7). See "Appendix: Implementation
   notes (steps 3 and 3a)" for the deviations and the review fixes.
4. **v2 string wrapper (3-4 h).** Section 6.2. Exit: woven `Unmarshal` tests
   pass on lane B for struct, slice, array, pointer, typed map value,
   `,string`, escapes, nested values.

   **Step 4: done.** See "Appendix: Implementation notes (step 4)" for the
   deviations (string cache guard, `EnableV2` moved to step 5).
5. **v2 decoder document (4.5-7 h).** Section 6.3, with the template guard.
   Add `iast/encoding/json/testdata/scopeprobe` and
   `TestV2ReadValueHookScope` (section 6.3; 1-2 h). Exit: the scope test
   passes on lane B (`checkValid` and `Number.UnmarshalJSONFrom` compile
   and have no `__dd_iast` code; `Decode` has one `ReaderDocument` call);
   woven `Decoder` tests pass on lane B: clean reader after tainted reader,
   a new decoder for each of ten documents, failure and panic then clean
   reader, oversized document, `bytes.Buffer` reader, several `Decode`
   calls on one decoder, `json.Number` through `Decode`; and the
   `Decode` consumer tests of step 3a (retargets, retarget between two
   `Decode` calls, chain, `More()` loop through `bufio` and
   `io.LimitReader`, `br.Reset(nil)`), on lane B (0.5-1 h, included in
   the estimate of this step, now 4.5-7 h).
   The decoder keeps the `request.ReaderToken` of `NewDecoder` (rule (f)
   of section 6.5), and `ReaderDocument` MUST revalidate it at each
   `Decode` (`request.RevalidateReader`, through `CloneForOwner`). A new
   lookup that finds the same owner is not sufficient. Test (lane B): B
   binds the reader of A (a root reader, and a `bufio` wrapper of it)
   after `NewDecoder` and ends before `Decode`: the value is a miss, and
   the decoder is closed; control: a rebind of the reader by A between
   `NewDecoder` and `Decode` keeps the value tainted.
   Also call `iastjsonbridge.EnableV2()` in the v2 `init` (the
   `errInvalidStringTag` aspect) in this step, with the `ReadValue`
   wrapper (step 4 did not call it). Then update
   `TestNewDecoderLooksUpOnlyForAConsumer`: on lane B, `NewDecoder` now
   does a lookup.

   **Step 5: done.** See "Appendix: Implementation notes (step 5)" for the
   deviations.
6. **Variant-aware shape and telemetry tests (3-4 h).** Section 6.4. Exit:
   tests pass on all lanes and fail when a pinned symbol is renamed (check
   with a patched copy of the GOROOT package directory).

   **Step 6: done.** See "Appendix: Implementation notes (step 6)" for the
   deviations and the rename evidence.
7. **Integration tests (7-10 h).** Make `json_destinations_test.go` and
   `json_controls_test.go` variant-aware (build-tagged expectation helpers).
   Add these cases, with the expected result for each variant:
   - map keys, `any`, `map[string]any` (decision Q1): tainted with the
     exact token on lane B; the v1 result (clean) on lanes A and C;
   - merge `null`; `,string` inner `null` in plain and escaped form
     (`"\u006eull"`); a `,string` value equal to a cached string that the
     destination already holds (must propagate);
   - string cache reuse across two requests (the second request must not
     see taint from the first);
   - custom unmarshalers stay clean;
   - a valid string member followed by a semantic error
     (`{"a":"x","b":1}` into two `string` fields): `a` is tainted, the error
     is returned, `b` is unchanged;
   - first source is the body: a request scope from `request.Begin` with
     only `BindReader` on the body (no `EagerHTTP`, no other tainted
     value). Assert that the indexed-root count is zero before `Decode`,
     and that the decoded string is tainted with the body source after it;
   - `More()` loop over a JSON array of 100 objects from one bound body:
     every item's string is tainted with the body source;
   - a value that spans buffer refills: one 20 KiB document from a reader
     that returns 7 bytes for each `Read`: tainted;
   - decoder reused across two requests: `NewDecoder` in request A on a
     reader bound to A, A decodes one value, the decoder has buffered a
     second one; then request B decodes it. Two variants: A finished (miss;
     B has no source and no vulnerability) and A still live (taint goes to
     A; B has no source). Never attributed to B;
   - two owners (all lanes, section 6.7): `io.MultiReader(bodyA, bodyB)`
     from two live requests: miss;
     a reader bound to a second owner after `NewDecoder`: later `Decode`
     calls miss;
   - `io.MultiReader` 8+1: 7 clean readers, A's body 8th, B's body 9th,
     both requests live, `Decode` in B and in A: miss; no source in A or B;
     no vulnerability. Control: `io.MultiReader(bodyA)` in A: tainted;
   - `io.MultiReader(bytes.NewReader(prefix), bodyA)`: miss (clean input);
   - contended lookup: the request lookup stub returns `complete = false`
     at `NewDecoder`, then at the second `Decode`: miss from that point;
   - pooled reader: in A, `br := bufio.NewReader(bodyA)`; while A is live,
     in B, `br.Reset(bodyB)` and, in a second case,
     `br.Reset(strings.NewReader(clean))`; `json.NewDecoder(br).Decode`
     in B: miss (the `Read` guard sets the bit of A); no new source in A;
     no source in B;
   - keep taint: `json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))`,
     `json.NewDecoder(io.TeeReader(r.Body, &log))`,
     `io.TeeReader(http.MaxBytesReader(...), &log)`,
     `json.NewDecoder(bufio.NewReader(r.Body))`, and
     `json.NewDecoder(io.LimitReader(r.Body, n))`: tainted with the body
     source (decision Q8);
   - documented misses: `gzip.NewReader(r.Body)`; on lane B,
     `jsonv2.UnmarshalRead(r.Body, &v)` and a `jsontext.Decoder` over
     `r.Body` (decision Q3);
   - source value: NDJSON body `{"a":"x"}\n{"a":"y"}` decoded with two
     `Decode` calls: on lane B, the second source value is exactly
     `{"a":"y"}`; on lanes A and C, record the v1 value (expected
     `\n{"a":"y"}`);
   - v1 lanes: all reader cases above have the same expected result as
     lane B (section 6.7). Only the source value whitespace differs.
   Exit: all pass on all lanes; no vulnerability is invented.

   **Step 7: done.** See "Appendix: Implementation notes (step 7)" for the
   deviations.
8. **Benchmarks (3-4 h).** Section 7.2. Exit: gates of section 7.2 pass.
9. **CI matrix (1-2 h).** Add lanes B and C to the unit-test job for every
   module (`go-version: 1.27.x`, `GOTOOLCHAIN=local`; lane C sets
   `GOEXPERIMENT=nojsonv2`). Exit: all lanes are green and required.
10. **Review and docs (2-3 h).** Run the multi-agent code review. Update the
    README support matrix (Go 1.26 v1, Go 1.27 default and `nojsonv2`;
    Go 1.26 + `jsonv2` unsupported), the Phase 8 notes, the v1 behavior
    changes of section 6.7, the documented misses (Q3, `gzip`, retargeted
    wrappers), and residual R15 (the README "Known limits" note and the
    `iast/bufio` package doc note of section 6.6). Exit: all review
    findings closed.

Step order: 1, 2, 2a, 2b, 3, 3a, 4, 5, 6, 7, 8, 9, 10. Step 3a needs
steps 2b and 3. The consumer tests of retargeted readers are in step 3a
(v1 `Decode`, `io.ReadAll`) and step 5 (v2 `Decode`), after the code
that makes them pass (critic round 5, finding 3).

Total: about 50.5-70.5 hours of work (7 to 10 working days of about 7
hours). The sum: steps 1 to 10 of revision 4 without step 5 are 34-47 h
(with the 1 h of rule (d) in step 2a); step 5 is 4.5-7 h (was 4-6 h);
step 2b is 5.5-7 h (was 6-8 h); step 3a is 6.5-9.5 h (was 4-6 h).
Revision 5 was 48-67 h. Decisions Q1, Q2, Q3, Q12, Q13, and Q14 add no
time.

### 7.1 Validation commands for each lane

Lanes: A = `GOTOOLCHAIN=go1.26.6`; B = `GOTOOLCHAIN=go1.27.1` (v2 default);
C = `GOTOOLCHAIN=go1.27.1 GOEXPERIMENT=nojsonv2`. Run every command on every
lane, from the repository root unless noted:

1. `gofmt -l .` (must print nothing) and `go vet ./...`.
2. `go test -shuffle=on -covermode=atomic -coverpkg=./... -coverprofile=coverage.ordinary.txt ./...`
3. `go tool orchestrion go test -shuffle=on -covermode=atomic -coverpkg=./... -coverprofile=coverage.txt ./...`
   (the woven coverage test of CONTRIBUTING.md "Testing" and `ci.yml`).
4. `go -C iast/integration/testapp tool orchestrion go test -shuffle=on ./...`
   (and every other module with an `orchestrion.tool.go`, as CI discovers).
5. `go -C benchmarks/overhead tool orchestrion go test -shuffle=on ./...`
   and `go -C benchmarks/overhead vet ./...`.
6. `go test -race -count=1 -shuffle=on ./internal/taint/...` and
   `go test -race -shuffle=on ./.github`.
7. `go tool checklocks ./...`.
8. checkptr (Phase 6/7a/8 practice):
   `go tool orchestrion go test -race -gcflags=all=-d=checkptr=2 -count=1 ./iast/encoding/json/... ./internal/taint/jsonbridge/... ./internal/taint/propagation/...`
   and the same flags for `iast/integration/testapp`.
9. The bounded fuzz campaigns of `ci.yml` (lane A only; they do not depend
   on the JSON variant).

### 7.2 Performance baseline and gates

- Measure v2 against v2. Do not use the Phase 8 +2.83 % number, which is a
  v1 measurement.
- On lane B, run `go -C benchmarks/overhead run ./runner -count=20` three
  ways: unwoven; woven with IAST inactive; woven with an active clean
  request. Add a JSON workload with 20 string fields for `Unmarshal` and for
  `Decoder` if the runner has none. Compare with `benchstat`.
- Repeat the unwoven run twice to get the noise band of the machine.
- Gates: inactive: time delta inside the noise band and zero extra
  allocations and bytes. Active clean: record the delta; the review
  decides. Lane A: inactive, the v1 numbers must not change by more than
  the noise band (the `Decode` indirect call and the `NewDecoder` defer).
  Active: record the delta of the new `NewDecoder` lookup (section 6.7).
- Also measure on lane B, with an active request: `NewDecoder` +
  `Decode` of a small body (two `LookupObject` scans), and a `More()` loop
  of 100 items (one scan for each item). Record the result for review.
- On lanes A and B, with an active request: `io.MultiReader` of 2 and of 8
  bound readers, before and after step 2a (at most 8 more lookups).
  Inactive: zero extra allocations (gate). Active: record for review.
- `Read` guard (section 6.6), all lanes. Benchmarks of
  `(*bufio.Reader).Read` and `(*io.LimitedReader).Read` with 1-byte,
  512-byte, and 4 KiB reads, against the unwoven build, in three states:
  (a) no live guard; (b) one live guard on another reader (the cost for
  `net/http` connection readers); (c) the reader itself is guarded.
  Gates: (a) delta inside the noise band and 0 extra allocations;
  (b) and (c) at most 5 ns/op more than unwoven and 0 extra allocations.
  If (b) or (c) fails, stop and report to the review (do not tune
  silently). Also record if `(*io.LimitedReader).Read` is still inlined
  (`-gcflags=-m`).
- `io.ReadAll` token (decision Q11), all lanes: `io.ReadAll` of a 1 KiB
  reader. Inactive: zero extra allocations and a delta inside the noise
  band (gate). Active: record the delta of the second lookup.
- Macro check on lane B: the `Decoder` workload of this section through
  `bufio.NewReader(r.Body)`, active clean request: record the delta for
  review.

## 8. Risks

- R1. Go patch releases can change `v2` internals (closure layout, names).
  Mitigation: variant shape tests; the dispatch rule turns a missing anchor
  into no propagation, not into a build failure. A changed internal that
  the injected code still names (for example `jsonflags.StringTag`) is
  still a build failure; the lane B shape test must catch it first.
- R2. `PreviousTokenOrValue` is correct only if the string closure performs
  no read after `ReadValue`. Mitigation: the shape test pins this; a woven
  test decodes `{"a":"x","b":"y"}` and checks each field's source window.
- R3. The Decoder clone is passed to user `UnmarshalJSON` methods. They now
  receive tainted bytes, as they already do for `Unmarshal` on tainted
  input. This is consistent, but it differs from v1 `Decoder` behavior.
- R4. Removed. The `,string` guard no longer uses destination identity.
- R5. The string cache survives across requests in pooled decoders. The
  wrapper never taints a cached string; it taints a clone. The runtime hooks
  can taint the string that `makeString` makes; the string cache guard
  (section 6.2) keeps such a string out of the cache. A test must prove
  that a later request does not inherit taint (step 4:
  `TestUnmarshalStringCacheKeepsRequestsApart`,
  `TestUnmarshalV2StringCacheKeepsRequestsApart`).
- R6. The 40-byte `__dd_iast_binding` field and one defer in `NewDecoder`
  also apply on v1 and on Go 1.26 + `jsonv2`. While a request is active,
  `NewDecoder` does one `LookupObject` scan (64 owner slots, `TryRLock`).
  `Capture` returns at once when no request is active.
- R7. v2 taints more values than v1 (keys, `any`). Existing tests assert that
  these stay clean. Decision Q1 keeps the extra coverage, so the tests
  become variant-aware (step 7). Reported vulnerabilities can differ
  between Go 1.26 and Go 1.27 for the same request.
- R8. Other `iast/*` aspects may also fail on 1.27 (step 1 finds out).
- R9. Coverage is narrower than Phase 8, on v1 and v2 (section 6.7):
  only readers with an effectively exclusive single-owner binding
  propagate. Misses: `gzip.Reader`, `io.MultiReader` with more than 8
  inputs, a clean input, or two owners; a retargeted `bufio.Reader` or
  `io.LimitedReader`; a `bufio.Reader` from a pool `Reset`; a contended
  lookup; a reader that is bound only after `NewDecoder`; a decoder
  created outside any active request. In exchange, no byte is attributed
  to an owner that did not produce it (section 6.3 invariant), except
  under R15. `bufio.NewReader(Size)` and `io.LimitReader` keep taint
  (decision Q8).
- R11. Each `Decode` does one lookup while a request is active, for check
  (2) of the invariant. v1 already scans once for each `Decode`.
- R12. Fixed in this change (decisions Q6 and Q9, section 6.7): `io.ReadAll`
  and v1 `Document` now require an effectively exclusive single-owner
  binding. The risk that remains is the list of user-visible behavior
  changes in section 6.7 (inputs that propagated before and now miss).
  `PropagateReader` fanout still makes non-exclusive bindings, which no
  consumer attributes (see "Appendix: User decisions applied", item 3).
- R13. The scope of the `ReadValue` hook depends on the template guard
  (`.Function.Name`, `if`/`else` in `text/template`), not on the join
  point. If a later Orchestrion changes template evaluation, lane B fails
  to build or `TestV2ReadValueHookScope` fails. Both run in CI.
- R14. The v2 decoder source value has no leading whitespace; the v1
  source value can have it (section 6.3, "Source value and offsets").
  Reported evidence can differ between Go versions for the same request.
- R10. Strings set before a semantic error stay tainted (per-string
  propagation). This matches v1 and is exact per token.
- R15. Residual A1, ACCEPTED by user decision Q10 (section 6.6). The
  exact scenario: `p` is a guarded `*bufio.Reader` exclusive to owner A,
  with buffered bytes. Customer code copies it by value (`q := *p`), so
  `q.buf` and `p.buf` share one backing array. `q.Reset(other)` keeps
  that `buf` (`bufio/bufio.go:74-94`). A small `q.Read` fills `buf[0:n]`
  with bytes of `other` (`bufio/bufio.go:216-253`). Then `p.Read`
  returns `buf[p.r:p.w]`, which holds those bytes, while `p.rd` is still
  the proven input, so the guard of `p` sees no retarget.
  Effect: a mis-attribution of the bytes of `other` to A. Never a crash,
  never more memory. It needs customer code that copies a
  `bufio.Reader` by value and then resets and reads the copy; in that
  case the application itself already gets the wrong bytes from `p`
  (a program bug). The standard library does no such copy (one-time
  scan in step 2b). This goes against the "accurate provenance" rule of
  `AGENTS.md`; Romain accepts it to keep `bufio` exclusive. The test
  `TestKnownLimitBufioValueCopySharesBuffer` (step 3a) pins the current
  behavior. The README and the `iast/bufio` package doc state the limit
  (step 10).
- R16. The `Read` guard adds one atomic load to every
  `(*bufio.Reader).Read` and `(*io.LimitedReader).Read` of the process,
  and one direct call while a guarded wrapper is live (section 6.6).
  These are hot paths (`net/http` connection reads). Mitigation: the
  gates of section 7.2.
- R17. The `Read` guard uses a fixed table of 128 entries. Under load
  (many live requests, each with several guarded wrappers), new wrappers
  get no entry and are safe misses. Telemetry counts these drops.

## 9. User decisions

Romain answered the open questions of revision 4. One line each, with the
places where the decision is applied:

- Q1. KEEP the extra v2 coverage (typed map keys, `interface{}` strings,
  `map[string]any` keys and values get exact-token taint); tests are
  version-aware. Applied: section 3 (coverage), step 7, R7.
- Q2. Keep one coarse range for each decoded string (Phase 8 parity).
  Applied: section 3 (coverage), section 6.3 ("Source value and offsets").
- Q3. Direct `encoding/json/v2` streaming APIs (`UnmarshalRead`,
  `UnmarshalDecode`, `jsontext.Decoder`) are out of scope, a documented
  miss. Applied: section 3 (coverage), step 7 (documented misses), step 10
  (README).
- Q4. Closed by critic round 1: Go 1.26 + `GOEXPERIMENT=jsonv2` is
  unsupported (compiles, no propagation). Applied: section 4.
- Q5. Closed by critic round 2: binding snapshot in an added `Decoder`
  field, no `jsontext` weaving. Applied: section 6.3.
- Q6 + Q9. IN THIS CHANGE, v1 `Document` and `io.ReadAll` require an
  exclusive single-owner binding (exclusive flag, complete lookup, type +
  address identity). Applied: sections 1, 4, 6.1, 6.5, 6.7 (with the list
  of v1 behavior changes), step 3a (6.5-9.5 h in revision 6), step 7,
  R9, R12.
- Q7. Closed by critic round 3: the `Decode` check is a miss when the
  owner set changes. Applied: section 6.3.
- Q8. IN THIS CHANGE, add a bounded, allocation-free per-`Read` guard so
  that `io.LimitReader` and `bufio.NewReader(Size)` keep an exclusive
  binding. Applied: sections 1, 3, 5, 6.3, 6.4, 6.5 (rules (a), (a2),
  (c), proof sketch), 6.6, step 2b (5.5-7 h), steps 7 and 8, section 7.2,
  R9, R15, R16, R17.

Romain answered the questions of revision 5 and critic round 5:

- Q10. Keep `bufio` EXCLUSIVE (guarded), with the value-copy shared
  buffer (critic round 5, finding 1) as a DOCUMENTED RESIDUAL, accepted
  despite the accurate-provenance rule. The effect is a mis-attribution
  to the owner of the original reader, never a crash and never more
  memory. Applied: sections 1, 6.3 (invariant, cases), 6.5 (proof
  sketch), 6.6 ("Residual A1"), step 3a
  (`TestKnownLimitBufioValueCopySharesBuffer`), step 10 (README and
  `iast/bufio` package doc), R15.
- Q11. `io.ReadAll` captures an exclusive owner token BEFORE it reads,
  and checks it again after; else miss (critic round 5, finding 2).
  Applied: sections 1, 6.5 (consumer checks, request and `iobridge`
  changes), 6.7 (item 2, table, tests to add), step 3a, section 7.2.
- Q12. Keep making non-exclusive reader bindings (no consumer reads
  them). Applied: section 6.5 ("Changes"), R12.
- Q13. The unwoven manual helper `iast/bufio.Propagate` gives a miss (no
  `Read` guard). Applied: sections 6.5 (rule (a)), 6.7 (table and tests
  to change).
- Q14. The retargeted bit is per owner: one retarget removes exclusivity
  from all guarded readers of that owner. Applied: section 6.5 (rule
  (a2)), section 6.6.

## Appendix: Critic round 1 responses

1. BLOCKER, read-ahead gives the wrong owner. **Fixed.** Verified:
   `fetch` fills the buffer with all bytes that one `Read` returns
   (`jsontext/decode.go:175-256`); `More` calls `PeekKind`, which can fetch
   (`v2_stream.go:270-285`); ownership is looked up only in
   `CloneReaderBytes` (`request/reader.go:45-63`), called after `ReadValue`
   (`v2_stream.go:78-90`). A reader can be bound to several owners over time
   (`BindReader`, `PropagateReader`, `request/reader.go:18-39`). Fix: the
   simplest sound rule of section 6.3 (propagate only values whose bytes
   were all read during this `ReadValue`; else safe miss). The invariant is
   stated there. Tests are in step 7. The same exposure exists in v1
   (`stream.go:160` `refill`, Phase 8 `Document` at `init`); see Q6.
   **Superseded in round 2**: the offset rule is replaced by the binding
   snapshot of section 6.3.
2. MAJOR, `,string` identity compare. **Fixed.** Verified: `makeString`
   returns a cached string on a hit (`v2/intern.go:48-50`), so a new token
   can produce the same allocation that the destination already holds. The
   skip decision in `arshal_default.go:283-290` depends only on the options
   and on the first unquote of the raw token. The wrapper now repeats that
   exact test (`__dd_iast_innerNull`, section 6.2). R4 is removed. A test
   for the cache case is in step 7.
3. MAJOR, "failed decodes stay clean" is too broad. **Fixed.** Verified:
   semantic errors do not stop earlier stores (`v2/arshal.go:467-483`); map
   entries are stored before the error returns
   (`v2/arshal_default.go:1052-1074`); syntax errors stop before any store
   under legacy semantics (`v2/arshal.go:456-463`). Section 3 now states
   per-string semantics without staging; R10 and a step 7 test were added.
   Staging was rejected: it needs pending state for each decode, which adds
   memory and work on the hot path.
4. MAJOR, Go 1.26 + `jsonv2` guard. **Fixed (declared unsupported).**
   Verified: Go 1.26.6 uses `StringifyBoolsAndStrings` and tests the value
   after the second unquote (Go 1.26.6 `v2/arshal_default.go:256-269`);
   Go 1.26.6 `jsonflags` has no `StringTag`. The injected wrapper would not
   compile there. The dispatch rule (section 4) anchors the wrapper on
   `errInvalidStringTag` (absent in 1.26.6), so the lane compiles and
   propagates nothing. The bridge v2 flag also turns off the `Decode` clone.
5. MINOR, validation and baseline. **Fixed.** Section 7.1 lists commands for
   each lane, including the woven coverage run, the benchmark module test
   and vet, race, checklocks, and checkptr. Section 7.2 sets a v2-only
   baseline from repeated runs and a measured noise band.

## Appendix: Critic round 2 responses

1. NEW BLOCKER, `ReaderDocument` gated by indexed roots. **Fixed.**
   Verified: `hasValues()` reads the process indexed-root counter
   (`jsonbridge/bridge.go:57-58`, bound at `request/scope.go:54`);
   `BindReader` and `EagerHTTP` only add a reader binding
   (`request/reader.go:18-26`, `request/http.go:74-77`,
   `store/binding.go:95-110`), not a root; v1 `Document` checks `active()`
   only (`jsonbridge/bridge.go:92-106`). A request whose first source is
   its JSON body therefore had zero roots, and the round-1 design never
   created the clone. Now `Capture` and `ReaderDocument` gate on `active()`
   only; the string wrapper keeps `Active()` (section 6.1). The clone is
   adopted before `jsonv2.Unmarshal` runs, so the root count is not zero
   when strings are decoded. Test added (step 7, "first source is the
   body"; step 3 unit test).
2. Read-ahead rule too strict; no protection during `ReadValue`.
   **Fixed with the preferred redesign.** Verified: `More` calls
   `PeekKind`, which can `fetch` the next item's first byte
   (`v2_stream.go:270-285`, `jsontext/decode.go:175-256`), so the round-1
   rule missed every item of a `More()` loop. Soundness of the binding
   snapshot was checked against the store: reader bindings are only added
   while an owner lives and are cleared only when it finishes
   (`store/binding.go:166-202`, `:232-239`; `store/owner.go:207`); owner
   slots get a new generation on reuse (`store/owner.go:53`); refs are
   revalidated by index, generation, and state (`store/binding.go:55-64`,
   `request/http.go:15-35`); the binding and the decoder keep the reader
   alive, so its address is not reused. Thus a snapshot owner that is
   still live was bound during every read, and attribution to it is sound
   at any time, including during `ReadValue` (section 6.3 invariant). The
   current request is never used. Handled cases: unbound reader (miss),
   more than one owner or a new owner later (bounded "mixed" bit, miss),
   finished owner (miss). The per-read range recorder is described as the
   fallback. The `InputOffset`/`UnreadBuffer` rule is removed, because it
   is no longer needed. Tests updated in step 7: `More()` loop over 100
   objects, value across refills, decoder reuse across two requests (first
   owner or miss, never the second), mixed readers. Two corrections to the
   critic's proposal: (a) the snapshot is taken in `NewDecoder` only, not at
   the "first Read", because no byte can be read before `NewDecoder`
   returns, and a later snapshot would need a read hook; (b) the "grew"
   check is not needed for soundness, only for conservative coverage (Q7).
   **Partly superseded in round 3**: "bound" does not mean "every byte
   comes from this owner". The snapshot now needs one exclusive owner and
   complete lookups (sections 6.3 and 6.5).

## Appendix: Critic round 3 responses

1. NEW BLOCKER, `ReadValue` aspect too broad. **Fixed.** Verified: Go
   1.27.1 `encoding/json` has three `(*jsontext.Decoder).ReadValue` calls:
   `v2_stream.go:78` (`Decode`), `v2_scanner.go:32` (`checkValid`), and
   `v2_decode.go:243` (`Number.UnmarshalJSONFrom`); Go 1.26.6 has the same
   three. `method-call` checks only the receiver type of the call
   (`join/method_call.go:61-107`). Section 6.4's "exactly one" was false.
   Search for a join-point combination in Orchestrion v1.13.1 (and the
   pinned version, same files): none can limit a call to its enclosing
   function. `all-of` tests all points on the same node
   (`join/all-of.go:53-62`); `function` matches only `FuncDecl`/`FuncLit`
   nodes, `function-body` only their body block
   (`join/function.go:90-114`, `:372-390`); the other join points
   (`directive`, `declaration-of`, `struct-*`, `package-*`) do not help
   (`directive` needs a comment in the source). The `function-body`
   alternative on `(*Decoder).Decode` was rejected: a prepended statement
   cannot change the local `b` that `ReadValue` returns, and the join point
   also matches the v1 `Decode`, so a template that names `dec.dec` breaks
   the v1 build. Chosen fix: the template guard
   `{{ if eq .Function.Name "Decode" }} ... {{ else }}{{ . }}{{ end }}`.
   `.Function` walks up to the enclosing function
   (`advice/code/dot_function.go:70-80`); the branch that is not taken is
   not evaluated, so `.Function.Receiver` is never called in `checkValid`;
   Orchestrion's own test uses this pattern
   (`testdata/injector/selector-expr-fun-name/config.yml`). Section 6.3
   has the template and `TestV2ReadValueHookScope`: a woven build of a
   probe proves that `checkValid` and `Number.UnmarshalJSONFrom` compile,
   and a parse of the woven files under `$WORK/b*/orchestrion/src/encoding/json/`
   proves that they contain no `__dd_iast` code. Section 6.4 now pins three
   calls, one in `Decode`. Step 5 and R13 are updated.
2. NEW MAJOR, a binding does not prove ownership of every byte.
   **Fixed.** Verified each case: `io.MultiReader` propagates only its
   first 8 inputs (`iast/io/orchestrion.yml:46-68`), and
   `iast/io/io_test.go:120-149` pins that the 9th input's bytes go to the
   8th input's owner; `bufio.NewReaderSize` binds its result
   (`iast/bufio/orchestrion.yml:15-36`) and `Reset` has no hook;
   `io.LimitedReader.R` is exported; `lookupObject` skips contended
   owners and fanout overflow with telemetry only
   (`store/binding.go:129-160`); `http.MaxBytesReader`
   (`iast/net/http/orchestrion.yml:123-138`) and `io.TeeReader`
   (`iast/io/orchestrion.yml:29-44`) propagate; `compress/gzip` has no
   aspect. Rules picked (section 6.5): (a) an "exclusive" flag on reader
   bindings, set only by a proof; `MultiReader` with more than 8 inputs,
   or with an unbound, unknown, or non-exclusive input, gives a
   non-exclusive binding; (b) an incomplete lookup is unknown, and unknown
   is a miss; (c) **changed**: a `Read`-time record of the binding
   identity cannot detect `bufio.Reader.Reset` onto an unbound reader,
   because `Reset` changes no binding. The simpler sound rule is: wrappers
   that user code can retarget (`bufio`, `io.LimitReader`) never get the
   flag. `gzip` is a safe miss. The decoder now keeps one owner (40 bytes,
   not 88) and closes on any failed proof (section 6.3). Changes to
   `store/binding.go`, `request`, `iobridge`, and the `io`/`bufio`
   aspects are step 2a (6-8 h). Tests in steps 2a, 3, and 7: 8+1
   `MultiReader` (miss), contended lookup (miss), pooled `bufio` reader
   reset for B while A is live (miss), `MaxBytesReader` and `TeeReader`
   (taint kept). Q7 is closed; Q8, Q9, R12 are new; R9 is rewritten.
   The critic's remark on partial reads before `NewDecoder` is accepted:
   the proof uses only the bytes that the decoder reads.
   **Partly superseded in revision 5** (decision Q8): `bufio` and
   `io.LimitReader` now get the flag with a per-`Read` guard (section 6.6).
3. NOTE, offsets. **Documented.** Verified: `ReadValue` consumes
   whitespace and returns one contiguous value slice
   (`jsontext/decode.go:700-706`, `:773-775`), also after refills. The
   clone keeps exact offsets relative to the value through
   `jsonv2.Unmarshal`; the body source is the copied value, not the full
   body. Correction to the request text: v1 does not clone the whole
   decoder stream either. It clones the one value that `Decode` gives to
   `decodeState.init` (`stream.go:69`,
   `iast/encoding/json/orchestrion.yml:99`). The user-visible difference is
   leading whitespace: v1 `readValue` starts directly after the previous
   value (`stream.go:106`), so a v1 source value can start with `\n`; the
   v2 source value cannot. String ranges do not change (one coarse range).
   Section 6.3 "Source value and offsets", R14, and a step 7 test record
   this.

## Appendix: Critic round 4 responses

| # | Finding | Response |
|---|---|---|
| 1 | Pointer-only binding identity: `*Body` and `&body.Buffer` share one address, so a lookup of the embedded buffer can find the exclusive binding of the body | Accepted. Section 6.5 rule (d): bindings record the dynamic type, and lookups match type plus address; a same-address, different-type collision that the table cannot hold is an incomplete lookup (miss). Section 7 adds the test. |

## Appendix: Critic round 5 responses

1. BLOCKER, `bufio` value copy shares the buffer. **Verified; kept as a
   documented residual by user decision Q10.** Verified in the Go 1.27.1
   source: `Reset` calls `reset(b.buf, r)`, which keeps the same `buf`
   (`bufio/bufio.go:74-94`); a small `Read` on an empty buffer calls
   `b.rd.Read(b.buf)` and fills `buf[0:n]` (`bufio/bufio.go:216-253`).
   After `q := *p`, `q.Reset(other)` and a small `q.Read` write bytes of
   `other` into the array that `p` reads next. `p.rd` does not change,
   so the guard of `p` sees no retarget, and the bytes go to the owner
   of `p`. Romain's decision: keep `bufio` exclusive. The residual needs
   customer code that copies a `bufio.Reader` by value and then resets
   and reads the copy; then the application already gets the wrong
   bytes from `p` (a program bug). The effect is a mis-attribution to
   the owner of `p`, never a crash, never unbounded memory. It is
   accepted despite the accurate-provenance rule. Changes: section 6.6
   ("Residual A1": exact scenario, effect, documentation text, test),
   R15, "Appendix: User decisions applied" item 1, step 3a
   (`TestKnownLimitBufioValueCopySharesBuffer`, named as a known limit,
   asserts the current behavior), step 10 (README "Known limits" and
   `iast/bufio` package doc).
2. MAJOR, `io.ReadAll` has no capture before the reads. **Fixed
   (decision Q11).** A binding that is made during `io.ReadAll` (for
   example a late `request.BindReader`) could claim the bytes that
   flowed before it. Now the `io.ReadAll` template calls `ReadAllBegin`
   at entry (exclusive owner token, or none) and `ReadAllEnd` at return
   (revalidate the token, complete lookup again, same one owner,
   effectively exclusive). No token, or a failed check: miss. Changes:
   sections 1, 6.5 (consumer checks; `request` and `iobridge` API),
   6.7 (item 2, behavior table, tests to add:
   `TestReadAllLateBindIsMiss`, `TestReadAllSecondOwnerDuringReadIsMiss`,
   `iobridge` unit and allocation tests), step 3a (+1-1.5 h), section
   7.2 (benchmark of the second lookup).
3. MAJOR, step order. **Fixed.** The step 2b tests needed retargeted
   readers to miss in v1 `Decode` and `io.ReadAll`, but those consumers
   use the old rule until step 3a (and the v2 decoder exists only after
   step 5). Now step 2b tests the binding only (`request.ReaderOwner`,
   the retargeted bit); the consumer tests move to step 3a (v1 `Decode`
   on lanes A and C, `io.ReadAll` on all lanes) and to step 5 (v2
   `Decode` on lane B). Section 7 states the step order. Estimates:
   step 2b 5.5-7 h (was 6-8 h); step 3a 6.5-9.5 h (was 4-6 h; includes
   finding 2 and the known-limit test); step 5 4.5-7 h (was 4-6 h).
   Total: 50.5-70.5 h (was 48-67 h).
4. Other defaults. **Decided by Romain**: keep making non-exclusive
   bindings (Q12); the unwoven `iast/bufio.Propagate` helper gives a
   miss (Q13); the retargeted bit is per owner (Q14). Recorded in
   section 9.

## Appendix: User decisions applied

Revision 5 listed seven points with defaults. Status in revision 6:

1. Residual A1 / R15 (copied `bufio.Reader` value shares its buffer).
   DECIDED (Q10): keep `bufio` exclusive; the residual is documented and
   accepted by user decision, despite the accurate-provenance rule of
   `AGENTS.md`. The exact scenario (critic round 5, finding 1): after
   `q := *p`, `q.Reset(other)` keeps the same backing buffer
   (`bufio/bufio.go:74-94`); a small `q.Read` fills `buf[0:n]` with bytes
   of `other` (`bufio/bufio.go:216-253`); `p.Read` then returns
   `buf[p.r:p.w]`, which holds those bytes, while `p.rd` is still the
   proven input. The per-`Read` guard sees no retarget and attributes
   the foreign bytes to the owner of `p`. It requires customer code that
   copies a `bufio.Reader` by value and then resets and reads the copy;
   then the application itself already gets the wrong bytes from `p` (a
   program bug). The effect is a mis-attribution to the owner of `p`,
   never a crash, never unbounded memory. Applied: section 6.6, R15,
   step 3a (known-limit test), step 10 (README and package doc note).
2. No `Reset` hook. The check of `b.rd` at each `(*bufio.Reader).Read`
   covers `Reset`, value copies (other than residual R15), and
   `NewReaderSize` reuse. A `Reset` hook would not fix R15 either (the
   reset is on the copy `q`, which has no binding). DECIDED at the user
   review of revision 6: no `Reset` hook.
3. Keep making non-exclusive reader bindings. DECIDED (Q12): keep.
4. The unwoven manual helper `iast/bufio.Propagate` gives a miss.
   DECIDED (Q13): accept.
5. The retargeted bit is per owner. DECIDED (Q14): accept.
6. `io.ReadAll` checks only after the reads. REPLACED (Q11, critic round
   5, finding 2): `io.ReadAll` captures an exclusive owner token before
   the reads and checks it again after; else miss (section 6.7).
7. Process: critic round 5 is done (see "Appendix: Critic round 5
   responses"). The changes of revision 6 go to the user review.

## Appendix: Implementation notes (steps 1 to 2b)

Deviations from the text of the plan, with the reason for each:

1. Rule (d). The binding gets no new type field. The lookup reads the
   type word of the `object` interface that the binding keeps already.
   Thus `unsafe.Sizeof(binding{})` stays 32 and `OwnerRef` stays 24
   (`OwnerRef` also gets `ViaGuard`, in the padding). A different-type
   binding at the same address is a second entry. If the table cannot
   hold it, the bind fails and the lookup finds no binding: a miss, the
   same result as "incomplete".
2. The lookup stub of section 6.5 is a test flag
   (`request.SetIncompleteReaderLookupsForTest`), not a function
   variable. A function variable is an indirect call, and the compiler
   then moves the `[MaxSnapshotOwners]OwnerRef` arrays of the callers to
   the heap (3 allocations for each call, measured).
3. `iobridge.Register` takes one `iobridge.Callbacks` struct (7
   callbacks), not a list of arguments. It ignores a set with a nil
   callback.
4. Telemetry of section 6.6: two new owner counters, `GuardFull` (no
   guard entry) and `Retargets` (a guard found a new target). The owner
   record grows by 16 bytes and the store by 1,040 bytes
   (`footprint_test.go` updated). The `retargeted` bit uses padding.
5. `iobridge.ReleaseOwner` is called only for owners of the process
   manager. Guards refer only to owners of the process store, and another
   store can have an owner with the same slot and generation.
6. `Guard` returns false when the wrapper has a guard already (the
   binding is then not exclusive). The `retarget` callback runs under
   `recover`.
7. Step 2: the v1 `init` sets the dispatch variables to the Phase 8
   calls `Bind(dec.r, &dec.d)` and `Unbind(&dec.d)`. `BindDecoder` is
   step 3a (section 6.7). The v1 dispatch aspect has only a
   `struct-definition` join point, so the telemetry count stays 5. Only
   the two new aspect ids have a variant tag; step 6 tags the others.
8. Steps 2a and 2b are in one change. Thus the interim 2a tests ("bufio
   and `LimitReader` results are not exclusive until step 2b") are
   replaced by the 2b tests.
9. Still open by the plan order: `TestSourceShape` fails on lane B
   (step 6); `CloneReaderBytes` and v1 `Document` use the old fanout rule
   (step 3a), but their lookups use the type-plus-address identity.
   `io.ReadAll` uses the exclusive rule with an owner token (note 18).
10. Review of batch 1, finding 1 (`MultiReader` two passes). The first
    pass proved owner A, but the second pass did not check A again. If
    A ended between the passes and one input got a new owner B, the
    result was exclusive to B, with bytes of A. Fix: one call
    (`iobridge.PropagateJoin`, `request.PropagateJoinedReader`) does all
    the lookups and then one bind to A with all the inputs (rule (e)).
    `iobridge.Join`, `iobridge.PropagateWith`, and
    `request.PropagateReaderWith` are removed. The `owner` callback is
    removed until step 3a (`ReadAllBegin`) needs it. Test:
    `TestPropagateJoinedReaderOwnerChangeAfterLookup` (a test hook runs
    between the lookups and the bind). With the old two-pass logic, it
    fails ("the reader has an exclusive owner").
11. Review of batch 1, finding 2 (an input that gets a second owner after
    the construction of its wrapper). Fix: rule (e), input
    revalidation at each reader lookup (section 6.5). The option
    "invalidate the dependent proofs when an input gets another owner"
    was not used: the bind of B cannot find A's bindings when a lookup
    is contended. Tests: `TestDerivedBindingLosesExclusivityWhenInputGetsSecondOwner`
    (request), `TestDerivedReaderBindingRevalidatesInputs` and the other
    rule (e) tests (store), `TestWrapperLosesExclusivityWhenInputGetsSecondOwner`
    (woven: `TeeReader`, `MultiReader`, `LimitReader`, `bufio`), and
    `TestMaxBytesReaderOfExclusiveInputIsExclusive` (woven). With no
    revalidation, all of them fail. Memory: +72 bytes for each owner,
    +4,608 bytes for the store (`footprint_test.go`).
12. Review of batch 1, finding 3 (`Guard` duplicate check before the
    insertion). Fix: section 6.6, `Guard`. Test:
    `TestGuardConcurrentSameWrapper` (8 goroutines, 2,000 rounds, under
    `-race`). With the check before the insertion only, it fails
    ("2 calls returned true, the table has 2 entries of the wrapper").
13. Review of batch 1, finding 4. (a) `TestMultiReaderEightInputsOfAAndNinthOfB`:
    owner A in the first 8 inputs, live owner B in the ninth: not
    exclusive (control: the first 8 alone are exclusive to A). (b)
    Negative control of `TestDecoderOfEmbeddedBufferIsNotAttributedToBody`
    (rule (d)): with a pointer-only `bindingTable.find`, the woven test
    on Go 1.26.6 fails with "the bytes of the embedded buffer were
    attributed to the body owner"; with the type-plus-address lookup, it
    passes. (c) The guard release tests also check that each slot of the
    guard table is empty (`iobridge.GuardEntriesForTest`).
14. Follow-up review 1 of batch 1, finding 1 (rule (e) checked only the
    owners that are live now). If B bound an input X of a wrapper W of A
    and then ended, a lookup of W was exclusive to A again, although W
    could have bytes of B. Fix: the reader bind counters of rule (e)
    (section 6.5), a sticky loss. Changes: `Store.readerBinds` (4,096
    `atomic.Uint64`), `OwnerRef.binds`, `readerInputs.stamp`,
    `bindingTable.countReaderBind` (the binds of the owner itself do not
    count), and a count for each bind attempt, also a failed one. Memory:
    `OwnerRef` 24 to 32 bytes, +128 bytes for each owner (input sets of
    24 bytes), +40,960 bytes for the store (`footprint_test.go`: owner
    183,592, store 14,087,368; the plan budget is 14,180,537). Tests:
    `TestDerivedReaderBindingStaysNotExclusiveAfterSecondOwnerEnds`
    (bind, non-exclusive bind, and contended bind of B),
    `TestDerivedReaderBindingProofUsesTheCounterOfTheLookup` (B binds
    between the lookup and the derived bind), `TestReaderBindCounterSlots`
    (binds of the owner and of other owners with the same counter)
    (store); `TestDerivedBindingStaysNotExclusiveAfterSecondOwnerEnds`
    (request); `TestWrapperStaysNotExclusiveAfterSecondOwnerEnds` (woven:
    `TeeReader`, `MultiReader`, `LimitReader`, `bufio`, and two chains)
    and `TestMaxBytesReaderOfExclusiveInputIsExclusive` (woven). With a
    check of the live owners only (no counter comparison), all of them
    fail. Known limit: the counters protect the inputs of derived
    bindings only. A direct lookup of X after B ended finds only A (a
    root binding has no input to check). Note 18 closes this limit for
    the consumers.
15. Follow-up review 1 of batch 1, finding 2
    (`TestGuardConcurrentSameWrapper` was not deterministic). New
    `TestGuardSameWrapperAfterDuplicateCheck`: the test hook
    `iobridge.SetGuardHookForTest` stops two `Guard` calls for the same
    wrapper after the first duplicate check, until both arrive. With the
    check before the insertion only, it fails at each run ("2 calls
    returned true, the table has 2 entries of the wrapper").
    `TestGuardConcurrentSameWrapper` stays as a stress test.
16. Follow-up review 1 of batch 1, finding 3: section 6.5 shows the
    `viaGuard` parameter of `BindReaderValue`.
17. Follow-up review 2 of batch 1 (HIGH, bind order of rule (e)). A
    reader bind changed the table BEFORE it added 1 to the counter. A
    lookup of a wrapper W of A could read the old counter of input X
    while X was bound to B, and see only A after B ended: W was
    exclusive. Fix: each bind adds 1 to the counter (`addReaderBind`)
    under the table lock BEFORE the table change, and the stamps of the
    owner itself change after it (`stampReaderBind`, was
    `countReaderBind`). The invariant is in section 6.5, rule (e), and in
    the comment of `addReaderBind`. Test:
    `TestWrapperLookupSeesBindThatStartedBeforeTheCounterRead` (store):
    test hooks `hookReaderBind` (between the counter add and the table
    change) and `hookInputCounters` (after the lookup of W read the
    input counters) stop B and the lookup, so that the lookup reads the
    counters while B is bound, and continues after B ended. With the old
    order, it fails ("the lookup read the counter while B was bound to
    the input").
18. Review of batch 1, the root gap (HIGH). Only derived bindings had a
    sticky loss (note 14). For a ROOT reader X of A: B binds X while A is
    bound, the bytes of X are read or buffered, and B ends. A later
    lookup of X finds only A. A consumer that captured A at one point and
    found A again later attributed the bytes to A. Fix: rule (f) of
    section 6.5. The token keeps the counter value of X that the lookup
    read before the owner scan, and the own-bind count of the binding
    (`binding.own`, `uint32` in the padding; `bindingTable.readers`, the
    list of reader entries). `stampReaderBind` adds 1 to the own-bind
    count of each reader binding of the owner with the counter of the
    bind. `ReaderToken.Revalidate` accepts a new complete lookup only
    when the counter changed by the same value as the own-bind count.
    Consumers in this batch: `request.ReaderOwner` (now returns a
    `ReaderToken`) with `request.RevalidateReader`;
    `ReadAllBytesForToken` and the `io.ReadAll` template
    (`iobridge.ReadAllBegin` before the first read, `ReadAllEnd` after
    the reads: the capture-before / check-after rule of section 6.7 is
    done early); `CloneReaderBytesForToken`. The one-shot
    `CloneReaderBytes` (the v1 `Document` callback) is not changed
    (step 3a). Memory: `OwnerRef` 32 to 40 bytes, +8 bytes for each
    owner, +512 bytes for the store (`footprint_test.go`: owner 183,600,
    store 14,087,880). Changed tests: `iast/io/io_test.go`
    `TestReadAllThroughSupportedWrappers` (split: `MultiReader(tee)` is
    tainted, `MultiReader(clean, tee)` is a miss) and
    `TestMultiReaderInspectionBoundAndCleanup` (the 8+1 composition is a
    miss for A and B, control `MultiReader(bodyA)` is tainted), as section
    6.7 says; `internal_test.go` `TestReadAllBytesPublishesEveryBoundOwner`
    became `TestReadAllBytesRequiresOneExclusiveOwner`. New tests:
    `store/reader_token_test.go` (B binds X with an exclusive, a
    non-exclusive, and a contended bind, then ends: miss; a direct bind
    of a derived reader: miss; own rebind, own derived bind, and own bind
    of a reader with the same counter: valid; own contended bind: safe
    miss; other owner, other entry, other store, new generation: miss;
    B in its bind at the capture: no token; the reader entry list follows
    kind changes), `request/reader_token_test.go`
    (the same sequence, and a bind of B between the capture and the
    revalidation with the test hook `revalidateHookForTest`, for
    `RevalidateReader`, `ReadAllBytesForToken`, and
    `CloneReaderBytesForToken`; own rebind keeps exclusivity),
    `iast/io/readall_token_test.go` (woven: B binds and ends during the
    reads of `io.ReadAll` on the root, through `bufio` and `TeeReader`;
    late bind; second owner that stays live; own rebind during the
    reads), `iobridge` `TestReadAllEndWithTokenThatIsNotOK`, and two
    zero-allocation checks (gate off, active request). With no counter
    comparison in `Revalidate`, the store, request, and woven root tests
    fail; with no own-bind count, the own rebind tests fail.
19. Review 2 of batch 1 (findings 1 to 6). One invariant replaces the
    counter stamps of notes 14, 17, and 18: the creation baseline of rule
    (f) (section 6.5, with invariant (I) and its proof).
    - Finding 1 (HIGH, snapshot race). The lookup read the counter
      BEFORE the owner scan, and `binding.own` later under the lock. A
      token of A; B binds X and ends; the revalidation loads the counter
      (with B); A rebinds X before the lookup locks A (own +1, counter +1
      not loaded): the two changes were equal, and the bytes of B were
      accepted. Fix: the counter is read UNDER the table read lock of the
      owner, with the baseline. No retry is necessary: a stamped bind of
      the owner holds the write lock from its add to its stamp. Test:
      `TestReaderLookupReadsCounterUnderTableLock` (store, root and
      derived; new test hook `hookLookupOwner` before the lookup locks an
      owner, where A rebinds X; control with no bind of B: valid).
    - Finding 2 (HIGH, bind of B before the capture). A binds X, B binds
      X and ends, A takes a NEW token: the token compared only the
      changes after the capture, thus it was valid. Fix: the baseline is
      taken when the binding is made, not at the capture.
      `bindingTable.readerExpect` replaces `binding.own`,
      `OwnerRef.binds`, `OwnerRef.own`, `ReaderToken.Binds`,
      `ReaderToken.Own`, `readerInputs.stamp`, and `inputProof`. New
      `binding.demoted`: an entry that stops being a reader binding is
      never exclusive again, so that a token or an input set that refers
      to the entry cannot see a new binding with a new baseline. Tests:
      `TestForeignBindBeforeCaptureIsSticky` (store: new token not OK,
      wrapper built after B ended gets no exclusive proof, own rebinds
      before B keep exclusivity, own rebind after B does not restore it),
      `TestConcurrentOwnAndForeignRebindIsSticky` (store, barriers: A
      stops in its rebind after its counter add, B binds X and ends in
      this window; root and derived),
      `TestWrapperBuiltAfterSecondOwnerEndedIsNotExclusive` (request, the
      four propagation functions and the three token consumers). Changed
      tests (they asserted the old behavior): the "new token after B
      ended is valid" controls of `store/reader_token_test.go` and
      `request/reader_token_test.go`, `TestDerivedBindingStaysNotExclusiveAfterSecondOwnerEnds`
      (request: the input itself is not exclusive now),
      `TestDerivedReaderRebindKeepsBothProofs` (a demoted entry is not
      exclusive), `TestReaderBindCounterSlots` (a collision of B with a
      root is a safe miss for the root too), `TestBindingSizes`, and the
      footprint (owner 183,544, store 14,084,296).
    - Finding 3 (MEDIUM, retarget callback panic). `retarget` recovered
      the panic, and `CheckRead` removed the guard with no bit set. Fix:
      the sticky `iobridge.RetargetLost` bit (rule (a2)), checked in
      `request.lookupReader` for each ref with `ViaGuard`. Tests:
      `TestRetargetCallbackFailureFailsClosed` (request; test hook
      `retargetHookForTest` panics; the guarded wrapper and a `TeeReader`
      over it are a miss for the three consumers; the body is not
      changed) and `TestRetargetCallbackPanicDoesNotEscape` (iobridge:
      the bit is set only after a failure).
    - Finding 4 (test). `TestContentionDuringRevalidationIsMiss`
      (request): the test seam `store.HoldBindingTableForTest` locks the
      binding table of the owner, or of another active owner, during the
      revalidation of a valid token: each consumer misses; the same token
      is valid after the release.
    - Finding 5 (docs). `iast/bufio/bufio.go` describes the current v1
      behavior; the README lists the `io.ReadAll` misses.
    - Finding 6 (known, deferred). Step 3a release requirement: the v1
      `Document` callback (`CloneReaderBytes`, old fanout rule), with the
      `io.MultiReader(bodyA, bodyB)` decoder exit test.
    Revert evidence: with the counter load moved back before the owner
    scan, `TestReaderLookupReadsCounterUnderTableLock` fails (all four
    cases); with the old `binding.go` (token deltas), the item 1 and 2
    store tests and the request test fail; with the old `retarget` and no
    lookup check, the two item 3 tests fail.

## Appendix: Implementation notes (steps 3 and 3a)

Changed files: `internal/taint/jsonbridge/bridge.go` (and
`bridgetests`), `internal/taint/request/reader.go` (and
`json_token_test.go`, `internal_test.go`), `iast/encoding/json/json.go`,
`iast/encoding/json/orchestrion.yml` (and the tests), `iast/io` and
`iast/bufio` tests, `iast/bufio/bufio.go` (doc), `README.md`,
`iast/integration/testapp/json_chain.go`.

Deviations from the text of the plan, with the reason for each:

1. Section 6.1, `OwnerToken` and `ReaderBinding`. Rule (f) needs the
   store and the binding entry of the token, thus `OwnerToken` is
   `{Store any; Generation uint64; Index, Entry uint8; OK bool}` (a copy
   of `store.ReaderToken`, as `iobridge.ReadToken`). `ReaderBinding` keeps
   the reader, the store, the generation, the slot, the entry, and the
   state: 48 bytes, not 40 (`TestReaderBindingSize`).
2. Section 6.1, request helpers. `request.ReaderOwnerToken` returns the
   bridge form `jsonbridge.OwnerToken`, not `request.ReaderToken`: the
   bridge keeps the token in the `Decoder`, and it cannot import
   `request`. `request.ReaderOwner` stays the request form. Both use the
   same lookup.
3. `jsonbridge.Register` takes one `jsonbridge.Callbacks` struct
   (`Literal`, `Owner`, `Clone`), as `iobridge.Register`. It ignores a set
   with a nil callback. The old `Document` callback is removed:
   `jsonbridge.Document` (v1) and `ReaderDocument` (v2) both call `Clone`
   through `ReaderBinding`. `Bind(reader, state)` becomes `Bind(state)`
   (the `decodeState.unmarshal` lifetime aspect; a decoder slot keeps a
   `*ReaderBinding`, not a reader).
4. `BindDecoder` returns false, and takes no slot, when the binding is
   not exclusive: `Document` cannot propagate then. `decodeState.unmarshal`
   still takes its own slot for `Quoted`.
5. `CloneForOwner` details: a value shorter than 2 bytes is
   `(nil, true)` with no lookup; an oversized value is revalidated, and
   a valid token counts one bytes drop for its owner only (as
   `ReadAllBytesForToken`), then `(nil, true)`; a failed adoption (source
   table full, lock contention) is `(nil, true)`; an owner that the
   request directory does not find any more is `(nil, false)`. A panic in
   a callback is recovered: `Owner` gives a closed binding, `Clone` gives
   `proven = false` (closed, fail closed).
6. Telemetry: the `[shared]` `NewDecoder` capture aspect needs an
   `import-path: encoding/json` clause (a `function-body` join point has
   no package-qualified function name), thus
   `instrumentedPropagationPoints` is 6 on all variants. Step 6 counts the
   aspects by variant tag.
7. The `NewDecoder` capture and the `__dd_iast_binding` field are
   `[shared]` aspects, added in this step (v1 `Document` needs them).
   `Capture` looks up the reader only when a consumer of the token is
   installed: the v1 dispatch `init` calls `jsonbridge.EnableV1`, and the
   v2 `init` of step 5 calls `EnableV2`. Thus on the v2 variant before
   step 5, `NewDecoder` does no lookup (one atomic load), and the state
   stays "none" (step 3a review, finding 1;
   `TestNewDecoderLooksUpOnlyForAConsumer`, `TestCaptureNeedsAConsumer`).
8. `SetV2ForTest` (jsonbridge) is a test hook, so that the bridge and
   request tests can run `ReaderDocument` on the v1 variant.
9. `iast/integration/testapp/json_chain.go`: `BuildJSONChain` used
   `io.MultiReader(bytes.NewReader(nil), buffered)`, a clean input. It is
   now `io.MultiReader(buffered)`, so that
   `TestHTTPBodyReaderJSONWriterToSQL` keeps the wrapper chain coverage
   (the clean-input case is a miss, section 6.7; the woven test
   `TestDecoderMultiReaderInputs` covers it).
10. Residual R15: the README "Known limit" note and the `iast/bufio`
    package doc note of section 6.6 are added in this step (step 10
    lists them), because `TestKnownLimitBufioValueCopySharesBuffer` pins
    the behavior now.
11. `TestReadAllWrapperWithNoReadGuardIsMiss` (woven) fills the 128 slots
    of the guard table and does not check the `GuardFull` counter:
    `request.Analysis` does not export the owner counters. The request
    unit test `TestPropagateGuardedReaderFullGuardTableIsNotExclusive`
    checks the counter.
12. The `Decode` consumer tests are in `iast/encoding/json`
    (`decoder_exclusive_test.go`). They build on all lanes. On lane B
    the decoder does not propagate yet (`decoderPropagates` is false):
    the miss checks pass, and the controls expect no taint. Step 5 sets
    `decoderPropagates` to true on lane B.

Review fixes (step 3a review):

13. Finding 1: the consumer gate of note 7. Revert evidence (lane B,
    woven): with `Capture` gated by `active()` only,
    `TestNewDecoderLooksUpOnlyForAConsumer` fails ("Should be zero, but
    was 1"), and `TestCaptureNeedsAConsumer` (lane A) fails ("Should be
    zero, but was 101").
14. Finding 2: assumption (A2) of section 6.5, and the contract on the
    doc comment of `request.BindReader`. No code change: the only
    production root bind is the HTTP body at entry, and user code cannot
    reset the body types of the net/http server.
15. Finding 3: the step 3a exit list states the lane B exceptions
    (`TestSourceShape` until step 6; the 9 `iast/integration/testapp`
    JSON tests of step 1 until steps 4, 5, and 7).
16. Finding 4: new woven v1 tests (all lanes; on lane B the controls
    expect no taint): `TestDecoderHandedToAnotherRequest` (a decoder of
    A given to the goroutine of B through a channel: tainted in A only
    while A owns the bytes; a miss after A ends, or after B binds the
    reader), `TestDecoderOversizedValueThenValidValue` (one bytes drop
    for the owner, then the next valid value is tainted), and the request
    test `TestCloneForOwnerFailedAdoptionKeepsBindingOpen` (a full source
    table and a contended source lock: `CloneForOwner` returns
    `(nil, true)`, the binding stays open, and a later value propagates
    when the lock is free).
17. Finding 5: `TestReaderDocumentWithNoIndexedRoot` asserts that the
    process has no indexed root, and does not skip.

Revert evidence (lane A, woven): with `CloneForOwner` that does a new
lookup and no token revalidation, `TestDecoderContendedLookupIsMiss`,
`TestDecoderBoundAfterNewDecoderIsMiss` (second owner ended before
`Decode`), and `TestDecoderRetargetBetweenTwoDecodes` fail. With, in
addition, a `ReaderOwnerToken` that accepts any found owner (the old
fanout proof), also `TestDecoderMultiReaderOfTwoRequestsIsMiss`,
`TestDecoderMultiReaderInputs` (clean input, 9 inputs),
`TestDecoderRetargetAfterBindIsMiss`, and
`TestDecoderLimitReaderOfRetargetedBufioIsMiss` fail.

## Appendix: Implementation notes (step 4)

Changed files: `iast/encoding/json/orchestrion.yml` (three `[v2]`
aspects: string arshaler wrap, string cache guard, string unmarshal
source), `iast/encoding/json/json.go` (`MayBeTainted` callback, telemetry
count), `internal/taint/jsonbridge/bridge.go` (`Callbacks.MayBeTainted`,
`SkipCache`), `internal/taint/propagation/json.go` (`JSONMayBeTainted`),
and the tests (`iast/encoding/json/unmarshal_test.go`,
`unmarshal_v2_test.go`, `variant_v1_test.go`, `variant_v2_test.go`,
`race_on_test.go`, `race_off_test.go`, `bridgetests/bridge_test.go`,
`propagation/json_test.go`, `request/json_token_test.go`).

Deviations from the text of the plan, with the reason for each:

1. Section 2.4 is not correct with the runtime hooks (plan
   runtime-operator-hooks). `makeString` (`v2/intern.go:20-54`) converts
   the unquoted bytes with `string(b)`. For a verbatim string, `b` is an
   alias of the input (`jsonwire.UnquoteMayCopy`), thus the
   `slicebytetostring` hook taints the result, and `makeString` puts that
   tainted string in the string cache of the pooled decoder. A later
   `Unmarshal` of clean bytes with the same string, in the same request or
   in another request while the first request is live, then gets the
   tainted string: a false source. This happens on lane B also without
   the wrapper, and also on the `any` fast path of direct
   `jsonv2.Unmarshal` (`unmarshalValueAny`), which has no wrapper. Fix:
   the string cache guard in `makeString` (section 6.2, "String cache").
   The first step 4 code removed the string from the cache in the wrapper
   (a scan of 256 entries); the step 4 review (finding 1) showed that it
   does not cover the `any` fast path. The guard replaces it, thus the
   `Literal` callback and `jsonbridge.String` have no result again.
   Tests: `TestUnmarshalStringCacheKeepsRequestsApart` (json.Unmarshal of
   a struct) and `TestUnmarshalV2StringCacheKeepsRequestsApart` (lane B:
   request A decodes tainted bytes with direct v2 `any`, `map[string]any`,
   `[]any`, a struct, or json.Unmarshal of a struct; then request B decodes
   clean bytes with direct v2 `any` or json.Unmarshal). Each attempt
   proves that its three decodes used one cache (the probe string of the
   last decode is the string of the first decode, with one P and the GC
   off: `sync.Pool.Get` then gives the decoder of the previous decode), and tries
   again with new strings when not (at most 50 attempts; sync.Pool can drop
   the decoder). With the guard removed, all 11 cases fail
   (`the value "cached-N" is tainted`).
2. Section 6.2, `init`. The v2 `init` sets `__dd_iast_stringWrap` only.
   `jsonbridge.EnableV2` stays for step 5 (appendix of steps 3 and 3a,
   note 7): with `EnableV2` and no `ReadValue` wrapper, `NewDecoder` does
   a lookup that no `Decode` uses (`TestNewDecoderLooksUpOnlyForAConsumer`
   pins this rule on lane B). Step 5 has an explicit item for it.
3. Section 6.2, `,string` test. The guard also tests
   `uo.Flags.Has(jsonflags.TagFlags)`, as the closure does
   (`arshal_default.go:260-261`). `__dd_iast_innerNull` ignores a token
   shorter than 6 bytes and a token that does not start with a quote, and
   it needs `AppendUnquote` to succeed.
4. Telemetry. The two new aspects with `import-path: encoding/json/v2` are
   also counted by the substring count of
   `TestInstrumentedPropagationTelemetry`. Thus
   `instrumentedPropagationPoints` is 8 on all variants, until step 6
   counts the aspects by variant tag. Step 6 must not count the string
   cache guard as a propagation point (it propagates nothing).
5. Runtime hooks and test expectations (for step 7). On all lanes, the
   runtime hooks taint a verbatim string that a decoder converts from
   tainted input bytes. On v1, `json.Unmarshal` of tainted bytes thus
   taints verbatim map keys and `interface{}` strings, with no JSON
   aspect. Only escaped keys and `interface{}` strings show decision Q1
   (`TestUnmarshalKeysAndInterfaceValues` uses escapes, and
   `TestUnmarshalKeysAndInterfaceValuesUseTheirOwnToken` taints one escaped
   token at a time: only that key or string gets taint on lane B). The v1
   `Decoder` decodes its clean buffer, thus its keys stay clean. A custom
   `UnmarshalJSON` or `UnmarshalText` that converts its input bytes gets
   the taint of the input from the runtime hooks; the tests use methods
   that set a constant.
6. Allocations (clean bytes). Unwoven baseline (`unmarshalCleanAllocations`,
   `TestUnmarshalAllocationBaseline`, runs unwoven and woven, not with
   `-race`): 16 allocations on v1 (Go 1.26.6 and Go 1.27.1 `nojsonv2`), 5
   on v2 (Go 1.27.1). With the gate off, the woven count is the same
   (`TestUnmarshalCleanAllocations`). With the gate open, the v2 wrapper
   and the string cache guard add none; the v1 `Quoted` aspect adds one for
   each `,string` field (existing Phase 8 behavior,
   `activeStringTagAllocations`).

Not done in this step (by the plan order or out of scope): provenance for
the direct `encoding/json/v2` `any` fast path (escaped object names and
escaped strings, section 6.2, "String cache"; decision Q3). The cost of the
guard while an indexed root exists (one filter check for each decoded
string of 2 bytes or more) is not benchmarked; step 8 measures it.

## Appendix: Implementation notes (step 5)

Changed files: `iast/encoding/json/orchestrion.yml` (new aspect
`[v2] encoding/json Decoder.Decode value document`; the v2 `init` calls
`jsonbridge.EnableV2`), `iast/encoding/json/json.go` (telemetry count),
`iast/encoding/json/testdata/scopeprobe/main.go`, and the tests
(`scope_v2_test.go`, `decoder_test.go`, `decoder_exclusive_test.go`,
`variant_v1_test.go`, `variant_v2_test.go`, `iast/runtime/c4_test.go`).
No change in `jsonbridge` or `request`: `ReaderDocument` and
`CloneForOwner` of step 3 already revalidate the token of `NewDecoder` at
each `Decode` (rule (f)).

Deviations from the text of the plan, with the reason for each:

1. Section 6.3, join point. Orchestrion v1.13.1 rejects a pointer sigil in
   the `method-call` receiver. The aspect uses
   `receiver: encoding/json/jsontext.Decoder` with `match: pointer-only`.
   The three calls have a `*jsontext.Decoder` receiver.
2. `TestV2ReadValueHookScope` has the build tags
   `go1.27 && goexperiment.jsonv2` (as `unmarshal_v2_test.go`): on Go 1.26
   with `jsonv2`, no `init` calls `EnableV2`, thus the taint control of the
   probe does not apply. The test runs only in a woven test binary
   (`requireWoven`), so that the unwoven run of lane B does not do a second
   `-a` build. The builds use `-buildvcs=false`: in the agent sandbox, the
   VCS stamping of a nested build can fail (`exit status 126`). The probe
   prints `result` lines (compared with the unwoven build) and `taint`
   lines (control: the woven `Decode` taints, the unwoven does not).
3. The step 5 `Decoder` tests (`decoder_test.go`) run on all lanes, with
   two new variant constants: `decoderSourceHasLeadingWhitespace` (the v1
   source value starts after the previous value, section 6.3) and
   `decoderTaintsNumberTokens`. On v2, a `json.Number` from a number
   token has taint: `(*Number).UnmarshalJSONFrom` converts the tainted
   clone, and the runtime hooks taint the conversion (accurate: the bytes
   come from the body). On v1, it is clean. A quoted number is tainted on
   all lanes. Steps 7 and 10 must list this difference.
4. `TestDecoderClosedAfterForeignBind` is the rule (f) test of this step
   (root and `bufio` wrapper; control: own rebind). It also shows that the
   decoder is closed: the next `Decode` does not call the `Clone`
   callback. `decoderPropagates` is true on all variants now; the step 3a
   tests run with propagation on lane B and pass.
5. `TestNewDecoderLooksUpOnlyForAConsumer` expects one lookup on all
   variants, and checks the consumer gate with both consumer bits cleared
   (`SetV1ForTest(false)`, `SetV2ForTest(false)`): no lookup, no
   allocation.
6. Telemetry: the new aspect has `import-path: encoding/json`, thus
   `instrumentedPropagationPoints` is 9 until step 6.
   `TestWrapExpressionAspectsWrapOnlyCalls` (`iast/runtime`) pins the
   wrap-expression aspects: it now counts 1 in `iast/encoding/json`.

Revert evidence (lane B, woven): with a `CloneForOwner` that accepts any
complete lookup with one owner (no token revalidation),
`TestDecoderClosedAfterForeignBind` (root, `bufio`) and
`TestDecoderBoundAfterNewDecoderIsMiss` (second owner ended before
`Decode`, root and `bufio`) fail ("the value is tainted").

Cost (lane B, darwin/arm64, woven): with no request, `NewDecoder` has the
same number of allocations as unwoven (2), and `EnableV2` adds no
measurable time (about 101 ns/op with the consumer bits, 99 ns/op with
none). With an active request, `NewDecoder` on a bound reader takes about
131 ns/op, against 113 ns/op on an unbound reader (the lookup and the
token), with no allocation. `NewDecoder` + `Decode` of a small bound body
adds one allocation (the clone). The woven `NewDecoder` with no request is
slower than the unwoven one (about 100 ns/op against 60 ns/op; 416 B
against 368 B). This was so before step 5 (the binding field and the
defer of step 3a). Step 8 measures it with the gates of section 7.2.

Lane B status after step 5: `TestSourceShape` (step 6) fails. In
`iast/integration/testapp`, only `TestJSONDecoderPropagatesOwnerBoundBody`
(the v1 source value with leading whitespace, step 7) and
`TestJSONDestinationClassesPreserveTheirContracts` (decision Q1, step 7)
fail. The other 7 JSON tests of step 1 pass.

## Appendix: Implementation notes (step 6)

Changed files: `internal/sourceshape/sourceshape.go` (new, used by tests
only), `iast/encoding/json/points_v1.go`, `points_v2.go` (new),
`json.go` (constant removed), `orchestrion.yml` (tags of 5 ids),
`json_test.go` (telemetry test), `shape_v1_test.go`, `shape_v2_test.go`
(new, `TestSourceShape` moved out of `json_test.go`), `variant_v1_test.go`,
`variant_v2_test.go` (`variantTag`, `variantJSONv2`),
`iast/io/source_shape_test.go` (new), and the ids in
`_docs/plans/propagation-coverage-matrix.md`.

Deviations from the text of the plan, with the reason for each:

1. Telemetry counts. A propagation point of a variant is an aspect with
   the tag of the variant or `[shared]`, with a join point clause
   `import-path: encoding/json` or `encoding/json/v2` (exact values, not a
   substring count), and not in the list `notPropagationPoints` of the
   test. The list has `[shared] encoding/json Decoder reader binding` on v2
   (only the v1 `init` sets its dispatch variables) and `[v2] ... string
   cache guard` (it propagates nothing, step 4 note 4). Thus v1 is 6 (as
   at step 3a) and v2 is 3, not 2: the `[shared]` `NewDecoder` capture of
   step 3a is a v2 point too (the v2 `Decode` uses its token). The test
   also requires a known tag on each id, and unique ids. The untagged ids
   now have a tag: `[shared] application JSON propagation bootstrap`, and
   `[v1]` on the four `decodeState` aspects.
2. Go 1.26 with `GOEXPERIMENT=jsonv2` (not supported) reports the v2 count.
   `shape_v2_test.go` has the tags `go1.27 && goexperiment.jsonv2`, as
   `unmarshal_v2_test.go`.
3. The shape tests parse the files of the variant of the test binary: the
   build context of `sourceshape.Load` sets or removes the tag
   `goexperiment.jsonv2` from `variantJSONv2`, not from the environment.
4. The `.ReadValue()` calls are found by syntax, not with `go/types`: three
   calls, in `(*Decoder).Decode` (receiver `dec.dec`, the field of type
   `*jsontext.Decoder`), `checkValid`, and `(*Number).UnmarshalJSONFrom`.
   A type check of `encoding/json` from source needs all its dependencies.
5. Added pins (used by the aspects or the Read rule): the signatures of
   all targets and of `makeString`; `addressableValue` embeds
   `reflect.Value`; `export` is
   `jsontext.Internal.Export(&internal.AllowInternalUse)`; the `stringify`
   rule of the closure; v2 `NewDecoder` wraps a `*bytes.Buffer` in
   `struct{ io.Reader }` (else `jsontext.fetch` reads it with `Next`, not
   `Read`); `jsontext.fetch` calls only `Read` on `d.rd`; jsonflags
   `Flags.Has`/`Get` and jsonopts `Struct.Flags`. "No package-level
   initializer calls `lookupArshaler`" is transitive and conservative (by
   name, review finding of step 6): a function or a package-level
   variable "reaches" `lookupArshaler` when its body or initializer
   refers to a name that reaches it, as a call or as a value, also in a
   function literal. An initializer or an `init` body must not refer to a
   name that reaches it. Only a function literal that is all the
   initializer of a variable is not examined (it does not run at
   initialization); a later reference to the variable is examined.
6. The io side: `TestReaderWrapperShape` uses `reflect` (the compiled
   standard library), thus a GOROOT copy cannot change it.
   `TestReadGuardShape` parses `bufio`, `io`, and `net/http`.

Rename evidence. The test binaries were built once for each lane (`go test
-c`), then run with `GOROOT` set to a copy of GOROOT (`src/<top>` copied,
the other `src` entries are symbolic links) with one change for each run.
`runtime.GOROOT()` returns the `GOROOT` of the environment. Control (no
change): pass on lanes A, B, C. Each change below fails (exit 1) with the
message of the pin:
- v1 (lanes A and C, same results): `decodeState.literalStore` renamed;
  `type decodeState` renamed; field `Decoder.r` renamed to `rd`;
  `valueQuoted` returns `(any, bool)`; `refill` calls `dec.r.ReadByte`.
- v2 (lane B): `makeStringArshaler`, `errInvalidStringTag`,
  `PreviousTokenOrValue`, `jsonflags.StringTag`, and the field
  `arshaler.unmarshal` renamed; `makeString` gets a third parameter;
  `InputOffset` returns `int`; `decoderState` has a named field `buffer
  decodeBuffer` in place of the embedded `decodeBuffer`; `Decoder.dec` is a
  `*jsontext.Encoder`; a fourth `dec.dec.ReadValue()` call in `Decode`;
  `NewDecoder` does not wrap `*bytes.Buffer`; `fetch` calls `d.rd.ReadAt`;
  the null test is `len(val) == 4 && string(val) == "null"`;
  `xd.SkipValue()` after `va.SetString(str)`; `var _ =
  lookupArshaler(nil)`; `var _ = func() int { makeStructFields(nil); ...
  }()` (transitive); after the review fix, also `var __shapeInit = func()
  *arshaler { return lookupArshaler(reflect.TypeOf("")) }; var _ =
  __shapeInit()` (passed before the fix), `var __f = lookupArshaler; var
  _ = __f(nil)`, an `init` that calls a local function literal that calls
  `lookupArshaler`, a function literal argument of a called function, and
  a function literal in a struct field that an initializer calls, and
  (second review fix) a method named `init` with a receiver that an
  initializer calls (`var _ = (__shapeCarrier{}).init()`).
  Negative controls: `var _ = func() int { lookupArshaler(nil); ... }`
  and `var __shapeInit = func() ... ` alone (not called) pass.
- io (lane A; the `reset` rename also on lanes B and C): `(*Reader).reset`
  renamed; `Reset` assigns `b.rd`; `reset` sets `w: 1`; `NewReaderSize`
  returns `b` for each `*Reader` (no size check); a third `reset` call;
  `Read` copies `b.buf[b.r:]`; `LimitReader` returns
  `&LimitedReader{r, 0}`; `l.R.Close()` in `(*LimitedReader).Read`;
  `r.WriteTo(nil)` in `io.ReadAll`; `mr.readers[0].Close()` in
  `(*multiReader).Read` (lane B); `l.r.Close()` in `(*maxBytesReader).Read`
  (lanes A and C).

Validation (darwin/arm64, own `GOCACHE` for each lane and flag set,
`GOFLAGS=-buildvcs=false`): `gofmt -l .` empty; `go vet ./...`,
`go vet ./.github`, and `go tool checklocks ./...` clean on lanes A, B, C;
plain and woven `go test -count=1 -shuffle=on ./...` pass on lanes A, B,
C (lane B woven: no failure); lane A woven with `-race` and coverage
(the CI command), `go test -race ./.github`, and `go test -race
./internal/taint/...` pass; the 5 other modules (CI command, lane A,
with `go vet`) pass. `iast/integration/testapp` on lane B: only
`TestJSONDecoderPropagatesOwnerBoundBody` and
`TestJSONDestinationClassesPreserveTheirContracts` fail (step 7); lane C
passes.

## Appendix: Implementation notes (step 7)

Changed files (all in `iast/integration/testapp`): `json_variant_v1_test.go`
and `json_variant_v2_test.go` (new, build-tagged expectations:
`jsonV2`, `jsonTaintsKeysAndAny`, `decoderSourcePrefix`,
`decoderTaintsNumberTokens`, `unmarshalHasStringCache`),
`live_request_test.go` (new: a server whose requests stay live, with the
steps of each request in its handler goroutine), `json_readers_test.go`
(new: the reader cases), `json_v2_misses_test.go` (new, tags
`go1.27 && goexperiment.jsonv2`: `jsonv2.UnmarshalRead`,
`jsontext.Decoder`), `json_destinations_test.go`, `json_controls_test.go`,
`e2e_test.go` (`TestJSONDecoderPropagatesOwnerBoundBody`), and `chains.go`
(`BuildTableQuery`).

Deviations from the text of the plan, with the reason for each:

1. NDJSON and semantic error: the strings have 2 bytes or more (`x1`,
   `y1`, `x_value`). The store does not taint a value of less than 2 bytes
   (`internal/taint/store/root.go`), on all lanes.
2. The sink queries use `BuildTableQuery` (`SELECT id FROM <value>`): the
   SQL analyzer redacts the source of a value in a literal, thus the
   event keeps the source value only for an identifier. The values have
   `_`, not `-`. The `json.Number` case sends a number, thus its source is
   redacted: the test checks the origin only.
3. Decision Q1 with the exact token: `TestJSONKeysAndInterfaceStringsUseTheirOwnToken`
   puts one escaped request parameter in each token of a `json.Unmarshal`
   document (string concatenation keeps the ranges). On lane B each key and
   `interface{}` string has the source of its own parameter (5 findings);
   on lanes A and C only the typed map value (1 finding).
4. The second-owner cases use `request.BindReader(ctxB, rA.Body)` (the bind
   of a second owner). The 20 KiB refill case binds its 7-byte custom
   reader with `request.PropagateReader` (a custom reader has no binding).
5. Added `TestJSONDecoderNumberTokens` (step 5, note 3): tainted on lane
   B, clean on lanes A and C.
6. The string cache test runs across two live HTTP requests, with one P,
   no GC, and the probe proof of step 4 (note 1). Revert evidence (lane
   B): with the string cache guard disabled (`if false && ...` in the
   `makeString` aspect), `TestJSONStringCacheKeepsRequestsApart` fails
   ("Should be false": request B got the tainted string of request A).

No bug found: every case has the expected result of the plan on each
lane. Validation (darwin/arm64, own `GOCACHE` for each lane, module, and
flag set, `GOFLAGS=-buildvcs=false`): `gofmt -l` empty; `go vet ./...`
(root, `./.github`, testapp) and `go tool checklocks ./...` clean on lanes
A, B, C; woven testapp `go test -count=1 -shuffle=on ./...` pass on lanes
A, B, C, and with `-race` on lane A; JSON tests with `-count=10` (lane B)
and `-race -count=3` (lane A) pass; woven root `./...` pass on lanes A,
B, C; the CI command (lane A, with coverage, and `go vet`) passes for the
5 other modules.


## Appendix: Implementation notes (step 8)

**Result: step 8 is closed by user decision.** The `Read` guard gate
(b)/(c) was <= +5 ns/op; it passed only when the CPU ran at full speed.
Romain accepted <= +6 ns/op (0 allocations), the +48 B / +32 B for each
`NewDecoder`, about +40 ns of inactive time for each `NewDecoder` (Go 1.27),
and waived the "before step 2a" `MultiReader` measurement. No code was
tuned. The verdicts are point estimates on a loaded machine (95 % CIs of
the paired guard rounds reach about +7.5 ns).
The first measurements failed in some cases. The user then asked for a
re-measure (Table 4). The machine was not quiet during the re-measure
(load average 10 to 60, median 32). All other gates are listed below.

Changed files: `benchmarks/overhead/jsonio_test.go` (new: the workloads of
section 7.2) and `benchmarks/overhead/README.md` (the new workloads).

### Environment and method

- darwin/arm64, Apple M5 Pro (18 CPUs), Orchestrion v1.13.1. Lanes: A
  go1.26.6; B go1.27.1 (v2 default); C go1.27.1 `GOEXPERIMENT=nojsonv2`.
  Own `GOCACHE` under `/tmp/t81` for each lane and flag set.
- **The machine was loaded by other processes during all the runs (load
  average 15 to 31).** The unwoven-to-unwoven noise is 5 % to 25 % for
  most workloads. Thus the time gates of small deltas are not precise.
  The byte and allocation gates are exact (equal in all samples).
- Runner runs (interleaved processes, the runner's alternate order):
  `go -C benchmarks/overhead run ./runner -count=20 -benchtime=300ms`:
  - B-s0: lane B, `-sampling=0`, all workloads ("woven inactive" for the
    HTTP workloads);
  - B-s100: lane B, `-sampling=100`, all workloads ("woven active");
  - A and C: lanes A and C, `-sampling=0`,
    `-bench='^Benchmark(JSON|IO|ReadGuard)'`.
  The sub-benchmarks of `jsonio_test.go` set their own state (`inactive`,
  `active`, `request`), thus B-s100 is a second independent measurement
  of them. The noise band is the control (unwoven) of B-s0 against the
  control of B-s100: the same unwoven binary source, two runs (the
  sampling flag has no effect on the control build).
- Focused runs (after the runner runs): control and IAST test binaries
  of the 3 lanes (6 binaries, built as the runner does), 20 rounds of
  `-test.bench='^BenchmarkReadGuard$' -test.benchtime=300ms`, then 15
  rounds of `-test.bench='^Benchmark(JSON|IO)'`; in each round each
  binary runs once, and the order rotates each round.
- Code placements (step 5 method of runtime-operator-hooks) were not
  used: the noise comes from the machine load, not from one code
  placement, and the gate (b)/(c) says to stop.
- States: `inactive` = no request active; `active` = one clean active
  request, the readers have no binding (no taint); `request` = each
  iteration begins a request, binds the readers (`request.BindReader`),
  runs the workload, and finishes the request (the control build does the
  same calls, thus the delta is the cost of the aspects, with taint).

### Table 1: lane B, runner (median, delta = woven - unwoven)

"Noise" = unwoven run 2 - unwoven run 1. "Run 1" = B-s0, "run 2" =
B-s100.

| Workload | Unwoven ns | Noise | Run 1 delta | Run 2 delta | Delta B/op | Delta allocs |
|---|---:|---:|---:|---:|---:|---:|
| JSONUnmarshal20/inactive | 1612 | +18.4 % | -44 ns (-2.7 %) | -230 ns (-12.0 %) | 0 | 0 |
| JSONUnmarshal20/active | 1552 | +17.0 % | +81 ns (+5.2 %) | -190 ns (-10.4 %) | 0 | 0 |
| JSONDecoder20/inactive | 2281 | +19.0 % | +79 ns (+3.5 %) | -233 ns (-8.6 %) | **+48** | 0 |
| JSONDecoder20/active | 2206 | +21.0 % | +388 ns (+17.6 %) | -119 ns (-4.4 %) | +48 | 0 |
| JSONDecoder20/inactive-bufio | 2758 | +14.1 % | +250 ns (+9.1 %) | +123 ns (+3.9 %) | **+48** | 0 |
| JSONDecoder20/active-bufio (macro) | 2998 | +6.3 % | +99 ns (+3.3 %) | +299 ns (+9.4 %) | +48 | 0 |
| JSONDecoder20/request-bufio (macro, bound body) | 5955 | +4.7 % | +619 ns (+10.4 %) | +307 ns (+4.9 %) | +96 | +1 |
| JSONDecoderSmall/inactive | 312 | +5.2 % | +47 ns (+15.1 %) | +37 ns (+11.2 %) | **+48** | 0 |
| JSONDecoderSmall/active | 328 | +0.9 % | +40 ns (+12.2 %) | +28 ns (+8.4 %) | +48 | 0 |
| JSONDecoderSmall/request | 2305 | +10.5 % | +291 ns (+12.6 %) | -134 ns (-5.3 %) | +48 | 0 |
| JSONDecoderMore100/inactive | 18860 | +1.0 % | +1456 ns (+7.7 %) | -113 ns (-0.6 %) | **+48** | 0 |
| JSONDecoderMore100/active | 19850 | -1.7 % | -15 ns (-0.1 %) | -847 ns (-4.3 %) | +48 | 0 |
| IOMultiReader/2/inactive | 32.6 | +6.2 % | +9.9 ns (+30.5 %) | +6.3 ns (+18.3 %) | 0 | 0 |
| IOMultiReader/2/request | 1812 | +10.6 % | +340 ns (+18.7 %) | +121 ns (+6.0 %) | 0 | 0 |
| IOMultiReader/8/inactive | 54.5 | +26.5 % | +26.3 ns (+48.3 %) | +3.7 ns (+5.4 %) | 0 | 0 |
| IOMultiReader/8/request | 2230 | +17.1 % | +1799 ns (+80.7 %) | +1224 ns (+46.9 %) | 0 | 0 |
| IOReadAll1KiB/inactive | 317 | +23.8 % | +75 ns (+23.7 %) | +11 ns (+2.7 %) | 0 | 0 |
| IOReadAll1KiB/active | 362 | +8.1 % | +83 ns (+23.0 %) | +90 ns (+23.1 %) | 0 | 0 |
| IOReadAll1KiB/request | 2890 | +1.5 % | +1134 ns (+39.2 %) | +1255 ns (+42.8 %) | +1024 | +1 |

The other runner workloads (B-s0, sampling 0): all string, bytes, `fmt`,
`url`, `strconv`, `Health`, `RequestProcessing`, `HTTPRoundTrip` deltas
are inside the noise band, with 0 extra bytes and allocations (except
`HTTPRoundTrip`: +416 B, +5 allocations at sampling 0). `WeakHash*`,
`WeakCipher*` (sinks that report) and `BytesBufferCopies` (a woven fixture
with an active tainted request) are slower by design; they are not JSON
paths. Sampling 100: `HTTPRoundTrip` +74 % (+97 allocations),
`WeakHashActiveSpan` and `WeakCipherActiveSpan` +266 % to +311 % (the
vulnerability report); not changed by this plan.

### Table 2: lanes A and C, runner (median, delta = woven - unwoven)

| Workload | A unwoven ns | A delta | A B/op | C unwoven ns | C delta | C B/op |
|---|---:|---:|---:|---:|---:|---:|
| JSONUnmarshal20/inactive | 2916 | +46 ns (+1.6 %) | 0 | 3138 | +580 ns (+18.5 %) | 0 |
| JSONUnmarshal20/active | 2605 | +88 ns (+3.4 %) | 0 | 2968 | +277 ns (+9.3 %) | 0 |
| JSONDecoder20/inactive | 2848 | +122 ns (+4.3 %) | **+32** | 3310 | +117 ns (+3.5 %) | **+32** |
| JSONDecoder20/active | 2793 | +121 ns (+4.3 %) | +32 | 3512 | -25 ns (-0.7 %) | +32 |
| JSONDecoder20/active-bufio | 3446 | +104 ns (+3.0 %) | +32 | 3848 | +446 ns (+11.6 %) | +32 |
| JSONDecoder20/request-bufio | 5866 | +217 ns (+3.7 %) | +80 (+1 alloc) | 6496 | +959 ns (+14.8 %) | +80 (+1 alloc) |
| JSONDecoderSmall/inactive | 394 | +14 ns (+3.5 %) | **+32** | 444 | +51 ns (+11.6 %) | **+32** |
| JSONDecoderSmall/active | 399 | +15 ns (+3.7 %) | +32 | 419 | +119 ns (+28.3 %) | +32 |
| JSONDecoderMore100/inactive | 15730 | +1046 ns (+6.6 %) | **+32** | 18420 | +3004 ns (+16.3 %) | **+32** |
| JSONDecoderMore100/active | 15900 | +3139 ns (+19.7 %) | +32 | 18530 | +4429 ns (+23.9 %) | +32 |
| IOMultiReader/2/inactive | 32.5 | +7.2 ns | 0 | 31.5 | +11.1 ns | 0 |
| IOMultiReader/8/inactive | 52.2 | +7.4 ns | 0 | 59.1 | +17.1 ns | 0 |
| IOMultiReader/2/request | 1684 | +68 ns (+4.0 %) | 0 | 1894 | +259 ns (+13.7 %) | 0 |
| IOMultiReader/8/request | 1859 | +1159 ns (+62.3 %) | 0 | 2159 | +1710 ns (+79.2 %) | 0 |
| IOReadAll1KiB/inactive | 270 | +5 ns (+1.8 %) | 0 | 305 | +98 ns (+32.1 %) | 0 |
| IOReadAll1KiB/active | 278 | +51 ns (+18.2 %) | 0 | 333 | +132 ns (+39.8 %) | 0 |
| IOReadAll1KiB/request | 2548 | +823 ns (+32.3 %) | +1024 (+1 alloc) | 2762 | +1635 ns (+59.2 %) | +1024 (+1 alloc) |

Allocation counts: equal in all `inactive` and `active` rows of all lanes.
Lane C ran last, with the highest machine load: its unwoven times are
higher, and its deltas are less reliable.

### Table 3: `Read` guard (section 6.6), delta ns/op = woven - unwoven

"Focused" = 20 interleaved rounds of the 6 binaries (the most reliable
numbers). "Runner" = the runner runs (B-s0 / B-s100 for lane B). Allocations:
0 in all rows, all lanes (gate pass). Unwoven: 2.0 to 3.5 ns (9 ns for
`bufio` 512 B).

| Case | Focused A | Focused B | Focused C | Runner A | Runner B (run 1 / run 2) | Runner C |
|---|---:|---:|---:|---:|---:|---:|
| bufio/1B/a-none | +0.33 | +0.40 | +0.44 | +0.33 | +0.80 / +1.05 | +1.27 |
| bufio/1B/b-other | +3.84 | +3.40 | +3.78 | +3.11 | +4.39 / +4.87 | +5.00 |
| bufio/1B/c-self | +4.34 | +3.59 | +4.29 | +3.55 | **+5.25 / +5.37** | **+5.64** |
| bufio/512B/a-none | +0.90 | -0.75 | +0.55 | -0.05 | +0.99 / +0.57 | +1.00 |
| bufio/512B/b-other | +3.05 | +1.57 | +3.48 | +2.72 | +3.32 / +3.88 | +4.12 |
| bufio/512B/c-self | **+5.56** | +3.12 | +4.92 | +3.91 | +4.06 / +4.77 | **+6.26** |
| bufio/4096B/a-none | +0.17 | -0.03 | +0.53 | +0.11 | +0.07 / +0.72 | +0.68 |
| bufio/4096B/b-other | +3.23 | +2.95 | +3.31 | +2.91 | +2.70 / +4.08 | +3.73 |
| bufio/4096B/c-self | +3.80 | +3.44 | +3.91 | +3.39 | +3.74 / +4.48 | +4.98 |
| limited/1B/a-none | +0.34 | -0.07 | +0.11 | +0.06 | +0.14 / +0.41 | +0.61 |
| limited/1B/b-other | +3.80 | +3.92 | +3.90 | +3.47 | +4.65 / **+5.05** | +4.84 |
| limited/1B/c-self | +3.80 | +3.54 | +3.79 | +3.34 | +4.30 / +4.62 | **+5.79** |
| limited/512B/a-none | +0.52 | +0.03 | +0.11 | +0.17 | +0.33 / +0.23 | +1.11 |
| limited/512B/b-other | +3.43 | +3.11 | +3.44 | +2.80 | +4.84 / +4.39 | **+5.24** |
| limited/512B/c-self | +4.10 | +3.63 | +3.77 | +3.24 | **+5.83** / +4.14 | **+5.85** |
| limited/4096B/a-none | +0.33 | +0.02 | +0.20 | +0.22 | +0.65 / +0.04 | +0.92 |
| limited/4096B/b-other | +3.74 | +3.72 | +4.17 | +3.44 | +4.82 / +3.98 | **+5.40** |
| limited/4096B/c-self | +3.81 | +3.61 | +3.91 | +3.32 | +4.87 / +3.84 | **+5.65** |

The cost of a live guard is approximately +3 to +4 ns for each `Read`
(focused medians), and it does not depend on the read size. It is the
call of `checkRead` (not inlined), the `words` of `self`, and 4 probe
loads with `Same` checks. Under load, it goes up to +5.2 to +6.3 ns. The
5 ns limit is inside the measured range.

`(*io.LimitedReader).Read` inlining (`-gcflags='io=-m -m'`, lanes A and
B): it is NOT inlined in the unwoven build ("function too complex: cost 90
exceeds budget 80") and NOT inlined in the woven build (cost 168). Thus
the guard does not remove an inlining. `iobridge.CheckRead` is inlined
into the woven `Read` (one atomic load and a branch in state (a)).

### Table 4: `Read` guard re-measure (paired rounds)

Method: the 6 binaries of the focused run, 40 rounds,
`-test.bench='^BenchmarkReadGuard$' -test.benchtime=200ms`. In each round
and lane, the unwoven and the woven binary run back to back (the order
alternates each round). Thus each pair has almost the same machine load.
Delta = woven - unwoven of the same pair, in ns/op. "Paired median" = the
median of the 40 pair deltas, with a 95 % bootstrap confidence interval.
"Quiet median" = the median of the pairs where both binaries are within
15 % of their fastest round (the CPU ran at full speed for both). The load
average was 10 to 60 (median 32) during all the rounds, thus no round was
on a quiet machine.

| Case | A paired median [95% CI] (n) | A quiet median (n) | B paired median [95% CI] (n) | B quiet median (n) | C paired median [95% CI] (n) | C quiet median (n) |
|---|---:|---:|---:|---:|---:|---:|
| bufio/1B/a-none | +0.45 [+0.18, +1.26] (40) | +0.04 (6) | +0.74 [+0.45, +0.99] (40) | +0.61 (6) | +0.55 [+0.23, +1.00] (40) | +0.29 (5) |
| bufio/1B/b-other | +4.51 [+3.71, +5.49] (40) | +3.44 (5) | +4.58 [+3.85, +5.09] (40) | +3.65 (4) | +3.92 [+2.93, +4.51] (40) | +3.05 (6) |
| bufio/1B/c-self | +5.64 [+4.59, +7.04] (40) | +3.97 (8) | +5.40 [+4.67, +6.29] (40) | +4.29 (4) | +4.90 [+4.08, +5.93] (40) | +3.68 (4) |
| bufio/512B/a-none | +0.61 [-0.24, +1.61] (40) | -0.03 (7) | -0.07 [-1.18, +1.19] (40) | +0.26 (5) | +0.33 [-1.11, +0.91] (40) | +0.43 (6) |
| bufio/512B/b-other | +3.70 [+2.95, +5.77] (40) | +3.06 (7) | +3.53 [+2.54, +4.31] (40) | +2.65 (5) | +2.85 [+1.93, +4.12] (40) | +3.00 (4) |
| bufio/512B/c-self | +5.30 [+4.69, +7.50] (40) | +4.77 (8) | +5.81 [+4.50, +6.45] (40) | +4.50 (6) | +4.52 [+3.59, +5.50] (40) | +4.52 (6) |
| bufio/4096B/a-none | +0.17 [+0.08, +0.48] (40) | +0.09 (8) | +0.03 [-0.55, +0.35] (40) | +0.13 (4) | +0.45 [+0.02, +0.65] (40) | +0.43 (5) |
| bufio/4096B/b-other | +3.68 [+3.10, +4.02] (40) | +3.04 (9) | +3.29 [+2.83, +3.80] (40) | +2.89 (6) | +3.39 [+3.10, +4.01] (40) | +3.00 (6) |
| bufio/4096B/c-self | +4.29 [+3.85, +5.45] (40) | +3.73 (7) | +4.48 [+3.78, +4.95] (40) | +3.49 (6) | +4.74 [+3.75, +5.24] (40) | +3.58 (5) |
| limited/1B/a-none | +0.10 [-0.03, +0.33] (40) | +0.10 (7) | +0.16 [-0.03, +0.33] (40) | -0.01 (5) | +0.14 [+0.00, +0.39] (40) | +0.07 (5) |
| limited/1B/b-other | +4.27 [+3.75, +5.56] (40) | +3.48 (7) | +4.16 [+3.70, +4.68] (40) | +3.54 (5) | +4.19 [+3.89, +4.69] (40) | +3.64 (5) |
| limited/1B/c-self | +4.05 [+3.46, +5.06] (40) | +3.39 (7) | +4.38 [+3.69, +5.22] (40) | +3.22 (5) | +4.09 [+3.67, +4.65] (40) | +3.51 (5) |
| limited/512B/a-none | +0.20 [+0.03, +0.42] (40) | +0.18 (6) | +0.10 [-0.14, +0.60] (40) | -0.08 (6) | -0.03 [-0.36, +0.16] (40) | +0.05 (5) |
| limited/512B/b-other | +3.47 [+2.95, +4.03] (40) | +2.80 (8) | +3.72 [+3.21, +4.46] (40) | +2.74 (5) | +3.61 [+3.16, +4.02] (40) | +3.10 (5) |
| limited/512B/c-self | +4.27 [+3.37, +4.96] (40) | +3.36 (8) | +4.39 [+3.59, +5.52] (40) | +3.56 (6) | +4.38 [+3.66, +4.68] (40) | +3.47 (5) |
| limited/4096B/a-none | +0.12 [-0.34, +0.28] (40) | +0.12 (8) | +0.12 [-0.14, +0.50] (40) | +0.08 (8) | +0.10 [-0.08, +0.40] (40) | +0.09 (7) |
| limited/4096B/b-other | +3.89 [+3.50, +4.87] (40) | +3.41 (8) | +4.26 [+4.03, +5.17] (40) | +3.83 (7) | +4.10 [+3.71, +4.62] (40) | +3.58 (6) |
| limited/4096B/c-self | +4.18 [+3.58, +4.88] (40) | +3.52 (8) | +4.93 [+3.96, +5.49] (40) | +3.39 (6) | +4.06 [+3.61, +4.72] (40) | +3.49 (6) |

Verdict:

- (a): pass on all lanes (paired medians -0.07 to +0.74 ns; 0
  allocations).
- (b) and (c) at full CPU speed ("quiet median"): **pass** on all lanes,
  +2.6 to +4.8 ns. The smallest margin is `bufio/512B/c-self` on lane A:
  +4.77 ns (n = 8), 0.23 ns below the limit.
- (b) and (c) for all pairs (under load): **fail** in 4 cases (+5.30 to
  +5.81 ns, `bufio` `c-self` on lanes A and B). Under load, the unwoven
  time is also 2 to 5 times larger. Thus the extra instructions take more
  ns, not more instructions.
- Allocations: 0 in all rows (pass).
- Code placements (step 5 method of runtime-operator-hooks) were not
  used: the noise of this machine load (+-1 to +-10 ns) is larger than a
  placement effect. A run on a quiet machine is still necessary for a
  final number.

### Focused JSON and IO run

The 15 focused rounds of `^Benchmark(JSON|IO)` had a noise of +-30 % to
+-500 % (benchstat confidence intervals; peak machine load), and no delta
is significant (p >= 0.16 for all rows on lane B). The byte and
allocation deltas are the same as in Tables 1 and 2. This run does not
change a verdict.

### Gates (section 7.2)

**User decision (Romain, after step 8):** accept the `Read` guard gate
(b)/(c) at <= +6 ns/op with 0 allocations (was <= +5 ns), and accept the
+48 B (v2) / +32 B (v1) for each `NewDecoder` (the `ReaderBinding` field;
no extra allocation). The measurements below meet these gates.

| Gate | Result |
|---|---|
| Inactive, lane B: time inside the noise band | Pass for `Unmarshal20`, `Decoder20`, `More100`, `ReadAll1KiB` (both runs inside or near the band). `JSONDecoderSmall/inactive`: +47 ns and +37 ns in the 2 runs (+11 % to +15 %), noise +5 %: **accepted by user decision** (about +40 ns for each `NewDecoder`: the `ReaderBinding` field and the defer of step 3a; step 5 notes). |
| Inactive, lane B: 0 extra allocations | Pass (all rows). |
| Inactive, lane B: 0 extra bytes | **FAIL for each `NewDecoder`: +48 B/op** (one allocation larger: the `__dd_iast_binding` field, `jsonbridge.ReaderBinding`, 48 bytes, appendix steps 1 to 2b, note 1). `Unmarshal`, `MultiReader`, `ReadAll`: 0 B. By design; the review decides. |
| Lane A, inactive v1: inside the noise band | Time: pass (+1.6 % to +6.6 %). Bytes: **+32 B/op for each `NewDecoder`** (the same field, in the v1 `Decoder` size class). Allocations: equal. |
| Lane A, active: `NewDecoder` lookup delta | Recorded: `JSONDecoderSmall/active` +15 ns (+3.7 %), `JSONDecoder20/active` +121 ns (+4.3 %), `More100/active` +3.1 us (+19.7 %). |
| Lane B, active: `NewDecoder` + `Decode` small body; `More()` loop of 100 | Recorded: small +28 to +40 ns (+8 % to +12 %), +48 B; `More100` inside noise (-0.1 % / -4.3 %), +48 B. |
| `MultiReader` 2 and 8, lanes A and B, inactive: 0 extra allocations | Pass. (Time: +6 to +26 ns on all lanes: the defer, the 8-input array, and one callback that returns at once.) |
| `MultiReader`, active: record | Recorded (request state, 2 / 8 bound inputs): B +121 to +340 ns / +1.2 to +1.8 us; A +68 ns / +1.16 us. "Before step 2a" was not measured: there is no build of the code before step 2a; the comparison is with the unwoven build (waived by user decision). |
| `Read` guard (a): inside noise, 0 allocations | Pass (focused: -0.75 to +0.90 ns; runner: up to +1.27 ns; 0 allocations). |
| **`Read` guard (b) and (c): <= +6 ns (user decision; was +5 ns), 0 allocations** | **Pass (point estimates; 95 % CIs up to about +7.5 ns).** Allocations: pass. Re-measure (Table 4): at full CPU speed +2.6 to +4.8 ns on all lanes (smallest margin: lane A `bufio/512B/c-self` +4.77 ns); median of all pairs +2.9 to +5.8 ns, 4 cases above +5 ns (`bufio` `c-self`, lanes A and B). First runs: focused medians +1.6 to +5.56 ns; runner runs up to +6.26 ns (lane C). |
| `io.ReadAll` 1 KiB, inactive: 0 allocations, inside noise | Allocations: pass (all lanes). Time: pass on A (+1.8 %) and B (+23.7 % / +2.7 %, noise +23.8 %); lane C +32 % (highest load, unclear). |
| `io.ReadAll`, active: record the second lookup | Recorded. Unbound reader (first lookup only): +51 to +132 ns. Bound reader (`request`: token, revalidation, adoption): +0.8 to +1.6 us, +1 allocation, +1024 B (the adopted copy of the 1 KiB result). |
| Macro check lane B: `Decoder` through `bufio.NewReader(body)`, active clean | Recorded: +99 ns / +299 ns (+3.3 % / +9.4 %), +48 B, 0 allocations. With a bound body (`request-bufio`, taint of 20 strings): +307 to +619 ns (+5 % to +10 %), +96 B, +1 allocation. |

### Validation

`gofmt -l .` is empty. `go vet ./...` in the root (lane A) and
`go -C benchmarks/overhead vet ./...` (lanes A, B, C) pass.
`go test -count=1 ./...` (root, lane A) passes. Woven
`go -C benchmarks/overhead tool orchestrion go test -shuffle=on -count=1`
with `-bench='^Benchmark(JSON|IO|ReadGuard)' -benchtime=1x` passes on lanes
A, B, C (the woven runs check the guard state of each `ReadGuard` case),
and the unwoven run passes on lane A.
