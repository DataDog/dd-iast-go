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

## 3. Hook candidates and what each one observes

| Candidate | Join point | Observes | Verdict |
|---|---|---|---|
| String unmarshal closure | `function-body` + `signature` on a `FuncLit` | `dec`, `va`, `uo` | Rejected: the signature is shared by every unmarshal closure in `v2` (bool, int, struct, map, methods, ...). Too broad. |
| `makeStringArshaler` result | `function-body` on `FuncDecl`, defer on `Result 0` | the `*arshaler`, once per type | Selected: wrap `r.unmarshal` with an injected wrapper. Runs once per type. |
| `makeString` | `function-body` on `FuncDecl` | unquoted bytes, result | Rejected: no destination; cache hits skip the conversion; escaped strings have no link to input. |
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
| v2 `init` sets `__dd_iast_stringWrap`, enables bridge v2 flag (`errInvalidStringTag` anchor) | no match | match | no match |
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
  it.
- `func String(raw []byte, value reflect.Value)` — returns at once unless
  `Active()`, `len(raw) >= 2`, `raw[0] == '"'`. Then it calls the registered
  literal callback as `literal(raw, raw, value, nil)` under `shield`.
- `type OwnerToken struct{ Index uint8; Generation uint64 }` and
  `type ReaderBinding struct { reader any; owner OwnerToken; state uint8 }`
  (`state`: none, exclusive, or closed; about 40 bytes). ONE owner only:
  attribution needs exactly one exclusive owner (section 6.5). Plain
  integers only, so the bridge keeps its dependency rule.
- `func (b *ReaderBinding) Capture(reader any)` — returns at once unless
  `active()` (owners only, NOT `hasValues()`). Then it stores `reader` and
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
  - `ReaderOwnerToken(reader) (index uint8, generation uint64, ok bool)`.
    `ok` is true only when `store.LookupReaderValue` (section 6.5) is
    complete, finds exactly one owner, and that binding is exclusive.
  - `CloneForOwner(reader, index, generation, data) (clone []byte, proven bool)`.
    It revalidates the token (index + generation + active, as
    `OwnerRef.Handle` and `analysisForOwner` do). Then it does a complete
    lookup of `reader` again, which must find exactly this owner, with an
    exclusive binding. If a check fails, `proven` is false. Else it adopts
    the clone into this owner only. An oversized value returns
    `(nil, true)`: a miss for this value, but the decoder stays open.
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
	iastjsonbridge.EnableV2()
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
  `CloneForOwner`. It revalidates the token and does a complete lookup
  again. If a check fails, the state becomes "closed".

Invariant:

> A `Decode` value is attributed only to owner O, and only when (1) at
> `NewDecoder`, a complete lookup found exactly one owner O, with an
> exclusive binding of the reader; and (2) at this `Decode`, the token of O
> is still valid (same generation, active), and a complete lookup still
> finds exactly O, with an exclusive binding. By (1) and section 6.5, every
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
  this effective value.
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
- No other construction gets the flag. A lookup that could hide a second
  owner is incomplete, so it cannot give the flag.

Each consumer captures one owner token BEFORE the first byte flows, and
checks effective exclusivity again AFTER the bytes flowed. The v2
decoder and v1 `Decode` capture at `NewDecoder` and check at each
`Decode` (after `ReadValue`, and at v1 `decodeState.init`). `io.ReadAll`
captures at entry and checks at return (section 6.7, decision Q11). The
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
   - New `BindReaderValue(owner, object any, exclusive bool) bool`. `bind`
     sets the flag on a new entry, and does `exclusive = old && new` on an
     existing one. A kind change from URL to reader sets the new value.
     `BindObjectValue` keeps its signature (URL bindings; reader binds
     through it are non-exclusive).
   - `lookupObject` returns `(count int, complete bool)`. `complete` is
     false when, for an owner that is active at the first state check,
     `lifecycleMu.TryRLock` or `table.mu.TryRLock` fails, or when a found
     owner does not fit in `out`. New
     `LookupReaderValue(store, object any, out []OwnerRef) (int, bool)`.
     `LookupObject` and `LookupObjectValue` keep their signatures.
2. `internal/taint/request/reader.go` and `http.go`:
   - the entry binding and `BindReader` use `exclusive = true`;
   - `PropagateReader(input, output)` (TeeReader, MaxBytesReader) computes
     `exclusive = complete && count == 1 && refs[0].Exclusive`, and binds
     the output to each found owner with that value;
   - new `PropagateSharedReader(input, output)` (the manual helper
     `iast/bufio.Propagate` only): today's behavior, `exclusive = false`;
   - new `PropagateGuardedReader(input, output)` (bufio, LimitReader;
     section 6.6);
   - new `PropagateReaderWith(input, output, allow bool)`: as
     `PropagateReader`, with `exclusive = allow && ...`;
   - new `ReaderOwner(input) (index uint8, generation uint64, ok bool)`
     for the `MultiReader` join, for `ReaderOwnerToken` (section 6.1),
     and for the `io.ReadAll` capture (section 6.7);
   - `ReadAllBytes(input, data)` becomes
     `ReadAllBytesForOwner(input, index, generation, data)` (section 6.7).
     The old name stays as a test helper that calls `ReaderOwner`, then
     `ReadAllBytesForOwner`;
   - the lookup function is a package variable, so that a request test can
     replace it with a stub that returns `complete = false`.
3. `internal/taint/iobridge/bridge.go` (stays at `sync/atomic` and
   `unsafe`):
   - the callbacks get `propagateShared`, `propagateWith`, `owner`, and
     (section 6.6) `propagateGuarded` and `retarget`; the `readAll`
     callback gets the owner token:
     `readAll func(input any, data []byte, index uint8, generation uint64)`;
   - new `type ReadToken struct{ generation uint64; index uint8; ok bool }`
     (16 bytes, on the stack), `ReadAllBegin(input any) ReadToken` (calls
     `owner`), and `ReadAllEnd(token ReadToken, input any, data []byte)`
     (returns at once when `!token.ok`; else calls `readAll`). They
     replace `ReadAll` in the `io.ReadAll` template (section 6.7);
   - section 6.6 adds the guard table, `CheckRead`, `PropagateGuarded`,
     `Guard`, `Unguard`, `Same`, and `ReleaseOwner`;
   - new `PropagateShared(input, output any)` and
     `PropagateWith(input, output any, allow bool)`;
   - new `type Join struct{ index uint8; generation uint64; count uint8; failed bool }`
     with `Add(input any)`, `Fail()`, and `Exclusive() bool`. `Add` fails
     the join if `owner` returns `ok = false` or a different owner.
     `Exclusive` is `!failed && count > 0`.
4. Aspects:
   - `iast/bufio/bufio.go` (manual helper): `Propagate` →
     `PropagateShared`;
   - `iast/bufio/orchestrion.yml` (`NewReaderSize`) and
     `iast/io/orchestrion.yml` (`io.LimitReader`): `Propagate` →
     `PropagateGuarded`, plus the `Read` guard aspects (section 6.6);
   - `io.TeeReader` and `net/http.MaxBytesReader` are not changed
     (`Propagate` now computes the flag);
   - `io.MultiReader` template, two passes, at most 8 inputs each:

```go
defer func() {
	var __dd_iast_join iastiobridge.Join
	for __dd_iast_index, __dd_iast_reader := range {{ $inputs }} {
		if __dd_iast_index >= 8 {
			__dd_iast_join.Fail()
			break
		}
		__dd_iast_join.Add(__dd_iast_reader)
	}
	__dd_iast_exclusive := __dd_iast_join.Exclusive()
	for __dd_iast_index, __dd_iast_reader := range {{ $inputs }} {
		if __dd_iast_index >= 8 {
			break
		}
		iastiobridge.PropagateWith(__dd_iast_reader, {{ $result }}, __dd_iast_exclusive)
	}
}()
```

   An owner can be added to an input between the two passes. Then the
   second pass finds two owners, and the output is non-exclusive (safe).

All consumers read the effective flag in this change: the v2 decoder,
v1 `Document`, and `io.ReadAll` (section 6.7, decisions Q6 and Q9). The
owner fanout of `PropagateReader` stays: it only makes more
non-exclusive bindings, which no consumer attributes.

Cost: no memory change (padding). One more bool test in each lookup. For
`io.MultiReader`: at most 8 more lookups, only while a request is active
(`LookupObject` returns at once when no owner is in use,
`request/http.go:43-49`).

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

- `checkRead` probes 4 slots. Not found, or same target: return. Found
  and a different target: call the registered `retarget(index,
  generation)` callback (the only indirect call, on the rare path), then
  CAS the slot to nil and decrement `guardCount`.
- `Guard(self, input any, index uint8, generation uint64) bool` inserts
  an entry. Only `request` calls it.
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
     `ReadAllBytesForOwner(input, index, generation, data)` revalidates
     the token (index + generation + active), does a complete lookup of
     `input` again, which must find exactly this owner, with an
     effectively exclusive binding, and then adopts `data` into this
     owner only. If a check fails: miss.
   - The oversize drop count stays, for that one owner only, and only
     when the token is still valid.
   - Why: a binding that is made during `io.ReadAll` (for example a late
     `request.BindReader` on a reader that was unbound at entry) must
     not claim the bytes that flowed before it. With no token at entry,
     the result is a miss. A second owner that is added during the
     reads makes the second lookup find two owners: miss.
   - Cost: one more lookup for each `io.ReadAll`, only while an owner is
     in use. No allocation (the token is on the stack).
3. `CloneReaderBytes` stays as a helper for tests (many tests use it as
   a probe), with the same exclusive single-owner rule.

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
   (recompute both sizes with the new type word of rule (d));
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
     `ReadAllEnd`, `ReadAllBytesForOwner`, the new template, and the
     "Tests to add" of section 6.7: 1-1.5 h. `CloneReaderBytes` rule:
     0.5-1 h.
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
   Exit: section 7.1 commands 2 to 8 pass on all lanes; the README lists
   the behavior changes of section 6.7.
4. **v2 string wrapper (3-4 h).** Section 6.2. Exit: woven `Unmarshal` tests
   pass on lane B for struct, slice, array, pointer, typed map value,
   `,string`, escapes, nested values.
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
6. **Variant-aware shape and telemetry tests (3-4 h).** Section 6.4. Exit:
   tests pass on all lanes and fail when a pinned symbol is renamed (check
   with a patched copy of the GOROOT package directory).
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
  wrapper never taints a cached string; it taints a clone. A test must prove
  that a later request does not inherit taint.
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
