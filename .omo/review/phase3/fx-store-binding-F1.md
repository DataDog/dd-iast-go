# fx-store-binding-F1: verification of store-binding-F1

## Verdict per finding
- **store-binding-F1: CONFIRMED on mechanism, severity downgraded High -> Low.** The binding table really does key on the numeric address alone, and a later `BindingReader` bind overwrites an earlier `BindingURL` bind at the same address. Once that happens, `URL.Query()` results come back untainted. However, the only way to get that shared address is for customer code to build an `*http.Request` by hand where the body's type embeds `url.URL` as its first field and `req.URL` points at that embedded field. No net/http server path produces this, so it is not ordinary customer code.

## Reproduction
Independent woven reproducer: `evidence/fx-store-binding-F1/fx_store_binding_f1_review_test.go`. It goes through the real surfaces: the `application.http.Handler` fallback advice (which calls `EagerHTTP`), the `net/url.URL.Query` advice, and a real `httptest.NewServer` entered through `serverHandler`.

Command: `In a private copy with evidence/fx-store-binding-F1/fx_store_binding_f1_review_test.go installed as iast/net/http/fx_store_binding_f1_review_test.go: GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -run TestFxURLReaderAlias -count=1 -v -timeout=20m ./iast/net/http`

Key output (`evidence/fx-store-binding-F1/woven-alias-go1.26.6.out.txt`), exit=1, peak RSS about 373 MB:
```
control-fallback-nonaliased: {RawQueryTainted:true QueryValueTainted:true URLBound:1 BodyBound:1 Aliased:false}
control-real-server:         {RawQueryTainted:true QueryValueTainted:true URLBound:1 BodyBound:0 Aliased:false}
aliased-fallback:            {RawQueryTainted:true QueryValueTainted:false URLBound:0 BodyBound:1 Aliased:true}
--- FAIL: TestFxURLReaderAlias ... URL.Query taint lost when body aliases URL (store-binding-F1)
```
`RawQuery` is still tainted because `EagerHTTP` taints it directly. Only the object-binding-driven `URL.Query` source is lost. The URL binding is gone (`URLBound:0`) and the reader binding took its slot.

I also re-ran the finder's reproducer (`evidence/fx-store-binding-F1/finder-repro-rerun.out.txt`) and got the same result: `URL bindings=0 reader bindings=1 query tainted=false`.

## Reachability
- **Default configuration and Go 1.26.6: technically yes, practically no.** The trigger needs three things at once. First, the request enters through the fallback handler advice, meaning customer code calls a `(ResponseWriter, *Request)` function directly with no server scope (the `serverHandler` advice passes server-built requests). Second, the `Body` has a pointer type whose first field (at any nesting depth) is `url.URL`. Third, `req.URL = &body.URL`.
- **Server paths cannot alias.** On HTTP/1, TLS HTTP/2, and h2c, `req.URL` comes from its own `url.ParseRequestURI` allocation and `Body` is `*http.body`, `*http2requestBody`, or `http.NoBody`. NoBody is zero-sized and is rejected by `dynamicPointer` at `binding.go:210`. The real-server control keeps taint.
- **No other collision source.** Bindings hold strong pointers, so a live bound object's address cannot be reused. Zero-sized objects are rejected. Derived readers bound by `reader.go:37` are fresh stdlib allocations. Two live objects can therefore share an address only through offset-0 embedding.
- **Go 1.27.0 not re-run in this pass.** The collision comes from Go's memory layout, where a struct's first field shares the struct's address, and that holds on every toolchain. Artifacts from an earlier attempt of this node (16:47, not produced by this run) sit in the same evidence dir and agree: `plain-url-reader-alias.go1.27.0.out.txt` fails the same way on Go 1.27.0, and `woven-url-reader-alias.go1.26.6.out.txt` with `fx_alias_review_test.go` fail the same way woven.
- **Documentation.** This is not in README or `01-design-intent.md`. It is, however, a deliberate decision recorded in a code comment at `binding.go:93-94`: "One address can have one binding kind; rebinding replaces its prior kind." That comment does not cover the embedded-field case, where two distinct typed objects share an address. Strictly, the case breaks product rule 4 (lost taint on a supported source), but only for artificially built inputs.

## Adjusted severity
**Low** (original: High). The effect is a false negative only: no crash, no false positive, and no cross-request bleed. It needs a hand-crafted request type layout that no stdlib, server, or `httptest` path produces, and real traffic cannot reach it. It rates above Info because the replacement also changes `readerCount` accounting and could matter if more binding kinds are added later.

## Root cause (file:line)
- `internal/taint/store/binding.go:186-198`: on a probe hit, `bind` compares only `entry.pointer == pointer`, then overwrites `entry.object` and `entry.kind`.
- `binding.go:217-228`: `find` also matches on the pointer alone and returns that single kind. `lookupObject` (`binding.go:147-150`) then discards the match when the kinds differ.
- Trigger order: `internal/taint/request/http.go:75-76` binds the URL first, then the reader.

## Minimal fix
Key entries on `(pointer, kind)`:
- In `bind`, treat an entry as a match only when `entry.pointer == pointer && entry.kind == kind`, and keep probing otherwise. The replace branch then reduces to `entry.object = object`, and the `readerCount` adjustments go away.
- In `find`, take `requiredKind` and match on both fields.
- Mix `kind` into `bindingHash`, or keep probing past pointer-only matches.
- For the generic `LookupObject` (kind `BindingInvalid`), return the first match or count the owner once, so no owner is attributed twice.

The cost is at most one extra entry per aliased address, and the existing `MaxBindings` and `MaxReaderBindings` bounds are unchanged.
