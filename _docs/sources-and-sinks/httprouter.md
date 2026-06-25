# httprouter — IAST Sources & Sinks

- **Module:** `github.com/julienschmidt/httprouter`
- **Version researched:** `v1.3.0`
- **Reference:** https://pkg.go.dev/github.com/julienschmidt/httprouter
- **Built on `net/http`:** yes — underlying `*http.Request` sources apply (see `net-http.md`). httprouter adds route params (via the `Params` handler argument / context).

## Overview

`httprouter.Router` is a trie-based `http.Handler`. Routes are registered with a
`httprouter.Handle func(http.ResponseWriter, *http.Request, httprouter.Params)`, a
signature like `http.HandlerFunc` plus a third `Params` argument carrying the
matched named (`:name`) and catch-all (`*name`) path segments. When routes are
wrapped via `Router.Handler`/`Router.HandlerFunc` (adapting a plain
`http.Handler`), `Params` are instead stashed in the request `Context` under
`ParamsKey` and retrieved with `ParamsFromContext`. All other request data
(query, headers, cookies, body, form, host, etc.) is read from the `*http.Request`
exactly as in stdlib `net/http`.

## Sources

### Route (path) parameters — httprouter-specific

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `Param` | `type Param struct { Key, Value string }` | One matched path segment's name/value | Element type of `Params`; `Value` is attacker-controlled (from URL path) | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#Param |
| `Params` | `type Params []Param` | Slice of all matched path params for the request | Passed as 3rd arg to every `Handle`; index access `ps[i].Value` also exposes tainted data | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#Params |
| `Params.ByName` | `func (ps Params) ByName(name string) string` | Value of named/catch-all param (`:user`, `*filepath`) or `""` if absent | Primary getter used in handler bodies | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#Params.ByName |
| `ParamsFromContext` | `func ParamsFromContext(ctx context.Context) Params` | Same `Params` slice, retrieved from `context.Context` | Used when routes are registered via `Router.Handler`/`Router.HandlerFunc`, which store params under `ParamsKey` instead of passing them as an argument | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#ParamsFromContext |
| `ParamsKey` | `var ParamsKey = paramsKey{}` (unexported key type) | N/A (context key) | Only relevant to know where `Params` live in `req.Context()`; not itself a data-bearing API | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#ParamsKey |
| `Router.Lookup` | `func (r *Router) Lookup(method, path string) (Handle, Params, bool)` | Returns matched `Handle` + `Params` for manual routing | Used by frameworks built atop httprouter; if instrumented directly, taint the returned `Params` the same way | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#Router.Lookup |

### Inherited from `net/http`

Query string, headers, cookies, raw body, form/`PostForm`, multipart form, `Host`,
`RequestURI`, `URL`, TLS info, etc. are all read off the `*http.Request` value
passed to every `Handle`/`http.Handler` — see `net-http.md` for the full catalog.
httprouter does not wrap or re-expose any of these; it only adds routing.

## Sinks (framework surface)

| API | Signature | Vulnerability class | Notes | Reference |
|---|---|---|---|---|
| `Router.ServeFiles` | `func (r *Router) ServeFiles(path string, root http.FileSystem)` | Path traversal | Registers a `GET` handler for `path` (must end `/*filepath`) that sets `req.URL.Path = ps.ByName("filepath")` (attacker-controlled) and delegates to `http.FileServer(root)`. `http.FileServer`/`http.Dir` already clean `..` segments, but any custom `http.FileSystem` passed as `root` inherits the raw, tainted catch-all value | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#Router.ServeFiles |
| `Router.ServeHTTP` (internal `RedirectTrailingSlash`/`RedirectFixedPath`) | `http.Redirect(w, req, req.URL.String(), code)` | Open redirect (framework-initiated) | Target is built from the router's own cleaned/matched path, not directly from attacker-supplied redirect targets (e.g. no `Location` header echoing untrusted input) — low risk, informational only | https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#Router.ServeHTTP |

All other response sinks (header injection via `ResponseWriter.Header().Set`,
cookie setting via `http.SetCookie`, body writes/reflected XSS via
`ResponseWriter.Write`/`fmt.Fprint*`, generic `http.Redirect` calls made by user
handlers) are stdlib `net/http` APIs — see `net-http.md`; httprouter does not add
its own variants.

## Propagators / Binders

httprouter has no request-binding/decoding helpers (no struct-tag binding, no
type coercion of params). The only "propagation" concern is passing `Params`
values (or `Params.ByName` results) into other code — plain Go string handling,
no framework-specific propagator API exists.

| API | Signature | Notes | Reference |
|---|---|---|---|
| — | — | Not applicable: no binder/propagator surface in this module | — |

## Instrumentation notes

- Route params are delivered as the **3rd argument** to `httprouter.Handle`, not
  via a getter call at the join point where the handler executes — instrumenting
  `Router.ServeHTTP`'s call to `handle(w, req, ps)` (or equivalently the
  `node.getValue` result inside `tree.go`) is the natural point to taint every
  `Param.Value` in `ps` before the user handler runs.
- Alternative/complementary join point: taint on construction inside
  `tree.go`'s `getValue` (where `Param{Key: ..., Value: path[...]}` values are
  built from the raw request path) — this covers `Router.Lookup` callers too,
  which bypass `ServeHTTP`.
  - Reference: https://pkg.go.dev/github.com/julienschmidt/httprouter@v1.3.0#Router.Lookup
- `Params.ByName` (`func (ps Params) ByName(name string) string`,
  import path `github.com/julienschmidt/httprouter`) is a good, low-frequency
  aspect target if per-slice tainting at match time is undesired: hook the
  **return value** and mark it tainted with source "path parameter" + `name`.
  Cheaper to source-taint the whole `Params` slice once per request than to
  instrument every `ByName` call (hot path: called once per handler per
  parameter, but slice construction happens once per request regardless).
- `ParamsFromContext` (return value) must be treated identically to the 3rd
  `Handle` argument — same underlying `Params` slice, only the retrieval path
  differs (via `context.Context` set up by `Router.Handler`/`HandlerFunc`).
- `Router.ServeFiles`'s injected closure `req.URL.Path = ps.ByName("filepath")`
  is worth a dedicated sink/propagation check: it feeds a tainted catch-all
  param straight into `http.FileServer.ServeHTTP`, which is the httprouter
  equivalent of a path-traversal sink even though the underlying I/O is stdlib.
- No struct decoding/binding exists in this module, so no propagator aspects
  are needed beyond taint-preserving string operations already covered by
  generic Go string propagation rules.

## References

- Package docs: https://pkg.go.dev/github.com/julienschmidt/httprouter
- Source (v1.3.0): `router.go`, `path.go`, `tree.go` in
  `github.com/julienschmidt/httprouter@v1.3.0`
- `net-http.md` — canonical catalog for all `*http.Request`/`http.ResponseWriter`
  sources and sinks reused by this framework
