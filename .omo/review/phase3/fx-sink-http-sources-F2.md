# fx-sink-http-sources-F2: independent verification

## Verdict per finding
- **sink-http-sources-F2: CONFIRMED.** Adjusted severity: **High** (unchanged).

The lazy `URL.Query` hook marks every value of the returned map as an HTTP parameter. It checks only that the `*url.URL` object is bound to a live request owner, and never looks at the value's content. If application code rewrites `req.URL.RawQuery` and reads the query again, its own literals are reported as `http.request.parameter` sources, and anything concatenated from them is tainted. My reproducer also shows that `Request.FormValue`/`ParseForm` has the same flaw through the context-based `ManageForm`/`ManageParameter` path, so the false provenance is not limited to `URL.Query`.

## Reproduction
Reproducer: `.omo/review/evidence/fx-sink-http-sources-F2/fx_f2_review_test.go`, written independently of the finder's test. It runs through the most realistic surface: a real `httptest.NewServer` (server-handler advice, not the direct-handler fallback) with mocktracer, and a top-level handler that either (a) replaces `RawQuery` with the literal `sort=created_at`, or (b) applies a default: `q := req.URL.Query(); if q.Get("sort")=="" { q.Set("sort","created_at") }; req.URL.RawQuery = q.Encode()`. It then reads `req.URL.Query().Get("sort")` and `req.FormValue("sort")` and builds `"SELECT * FROM items ORDER BY " + sort`. Output: `.omo/review/evidence/fx-sink-http-sources-F2/fx_f2_review.out.txt`.

```
$ GOTOOLCHAIN=go1.26.6 go test -timeout 12m -count=1 -run '^TestFxF2_' -v ./iast/net/http
--- PASS  (plain: all values clean, identical strings)
$ GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 12m -count=1 -run '^TestFxF2_' -v ./iast/net/http
/items?mode=literal&sort=attacker_col => sort="created_at" origin="http.request.parameter" ranges=1 statement_tainted=true | FormValue="created_at" origin="http.request.parameter" ranges=1
FALSE PROVENANCE: application literal "created_at" attributed to "http.request.parameter" via URL.Query
FALSE PROVENANCE: application literal "created_at" attributed to "http.request.parameter" via FormValue
/items?mode=default => sort="created_at" origin="http.request.parameter" ranges=1 statement_tainted=true | FormValue="created_at" ...
/items?mode=default&sort=attacker_col => sort="attacker_col" origin="http.request.parameter" ranges=1   (control: true positive, correct)
--- FAIL
```
The finder's own test (`.omo/review/evidence/sink-http-sources/review_alias.out.txt`) shows the same result through the direct-handler fallback. The plain run proves the strings are unchanged. Only the provenance differs.

## Reachability
- **Default configuration, Go 1.26.6: reachable.** It needs only a sampled request and ordinary handler code that mutates `req.URL.RawQuery` in place and then calls `req.URL.Query()` or `req.FormValue`/`ParseForm`. Examples are default-injection or normalization middleware, pagination rewrites, and legacy parameter aliasing. The trigger is uncommon but not exotic. Reads through a copied URL (`u := *req.URL`, `req.Clone`, `http.StripPrefix`) are not bound by identity and so are not affected.
- **Go 1.27.0: could not test.** The woven build fails first with the known `encoding/json` compile break (`dec.r undefined`, see `phase1/base-test-127.md`). The lazy query code does not depend on the Go version, so the same behavior is expected once that break is fixed.
- **Not a documented limitation.** README and `phase1/01-design-intent.md` list query/form values as sources but say nothing about attributing app-mutated values. It breaks product rule 4 (accurate provenance, no false taint). No sibling tracer has an equivalent: Java's `getParameter` values are immutable request data.

## Adjusted severity
**High.** The brief's scale defines High as a false-positive vulnerability on a supported source path (`URL.Query` and `FormValue`). A literal the application controls, which then reaches an SQL or command sink, is reported as an injection from an HTTP parameter. This sits at the lower edge of High because the trigger (rewriting the request's own query in place) is uncommon. The `FormValue`/`ParseForm` path, which the finder did not mention, widens the exposure.

## Root cause (file:line)
- `internal/taint/request/lazy.go:31-45`: `ManageURLQuery` gates only on `LookupObject(urlObject, store.BindingURL, ...) == 1`, meaning object identity. It then calls `manageMap`, which calls `ManageString` on every name and value (`lazy.go:179-203`). Nothing checks that the values came from the request's original `RawQuery`.
- `internal/taint/request/http.go:71-76`: `EagerHTTP` binds the `*url.URL` object for the lifetime of the request, so the binding survives later `RawQuery` writes.
- Same root cause, sibling path: `lazy.go:48-72` (`ManageForm`, `ManageParameter`) is gated only on the request context and taints whatever `r.Form`/`r.PostForm` holds after `ParseForm`. That includes values parsed from a rewritten `RawQuery`, and would also include an application-pre-populated `r.Form` (not reproduced here). The advice is at `iast/net/http/orchestrion.yml:140-162,189-221`.
- The eager `RawQuery` clone itself is already correctly tainted (`http.go:72`, origin `http.request.query`). Values parsed from it would carry propagated taint anyway, so value-agnostic re-management is not needed for true positives. It only re-labels them with parameter origin and name.

## Minimal fix
Attribute lazy query and form results only when the input still matches the request:
1. In `ManageURLQuery`, pass the URL's current `RawQuery` from the advice (the receiver is available) and manage only if it is still the eager managed clone, via `sameStringBacking` or a stored pointer/length identity. Otherwise return `values` unchanged. For the "default" case, where the app re-encodes the request values, a cheaper per-value option is to manage a value only if it is already tainted, i.e. derived from the managed `RawQuery`: `IsTaintedString(value)` or range lookup. Untainted values would stay clean.
2. Apply the same rule in `ManageForm`/`ManageParameter`: re-label only values that already carry request taint (from the tainted `RawQuery`/body), and never add a fresh source to an untainted string. Where either check is too expensive, dropping the attribution is acceptable. Missing a relabel is preferable to false taint.
3. Add a woven regression test modeled on `fx_f2_review_test.go` covering literal replacement, default injection, and a control.
