# chi (v5) — IAST Sources & Sinks

- **Module:** `github.com/go-chi/chi/v5`
- **Version researched:** `v5.2.4`
- **Reference:** https://pkg.go.dev/github.com/go-chi/chi/v5
- **Built on `net/http`:** yes — handlers are plain `http.HandlerFunc(w http.ResponseWriter, r *http.Request)`; the underlying `*http.Request` sources (query, headers, cookies, body, form, multipart, host, etc.) apply unchanged — see `net-http.md`. chi's own additive surface is route/path parameters.

## Overview

chi is a lightweight router built directly on `net/http`; it does not wrap `http.ResponseWriter` or `*http.Request` with its own types for request data access, so nearly all request-derived sources come from the standard library. chi's primary new attacker-controlled data is the set of **route/path parameters** captured while matching a URL pattern (e.g. `{id}` in `/users/{id}`), exposed via `chi.URLParam`/`chi.Context`. Notably, chi also calls `r.SetPathValue` (Go ≥1.22) during routing, so `net/http`'s own `r.PathValue(key)` becomes populated with chi-tainted values too. Beyond the core router, the optional `middleware` subpackage adds a few more request-derived sources when installed: `middleware.URLFormat` (path-suffix extraction into context), `middleware.RequestID` (attacker-suppliable `X-Request-Id` header copied into context), and `middleware.RealIP` (overwrites `r.RemoteAddr` from spoofable client-IP headers). chi has essentially no sinks or binders of its own; it delegates entirely to `net/http` and user code.

## Sources

### chi-specific: route/path parameters

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `chi.URLParam` | `func URLParam(r *http.Request, key string) string` | Value of a matched route placeholder (e.g. `{id}`) from the request path | Convenience wrapper around `RouteContext(r.Context()).URLParam(key)`; returns `""` if no route context or key not found. Primary chi taint source — return value must be tainted. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#URLParam |
| `chi.URLParamFromCtx` | `func URLParamFromCtx(ctx context.Context, key string) string` | Same as above, from a bare `context.Context` | Used when only a `context.Context` (not `*http.Request`) is available, e.g. deeper in call stacks. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#URLParamFromCtx |
| `(*chi.Context).URLParam` | `func (x *Context) URLParam(key string) string` | Route param value, searched from `Context.URLParams` (last match wins, supports sub-router overrides) | Underlying implementation used by both functions above. Obtain `*Context` via `chi.RouteContext(ctx)`. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#Context.URLParam |
| `chi.RouteContext` | `func RouteContext(ctx context.Context) *Context` | Returns the `*chi.Context` stored in the request context (`RouteCtxKey`) | Entry point to reach `URLParams`, `RoutePath`, `RoutePattern()` directly; returns `nil` if absent. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#RouteContext |
| `chi.Context.URLParams` (field) | `URLParams RouteParams` where `type RouteParams struct{ Keys, Values []string }` | Full stack of matched route param keys/values across the router chain | Exported field; a handler/middleware can iterate `URLParams.Keys`/`.Values` directly instead of calling `URLParam`. Each `Values[i]` element is a taint source. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#RouteParams |
| `chi.Context.RoutePath` (field) | `RoutePath string` | The routing path being matched (normally derived from `r.URL.RawPath`/`r.URL.Path`, occasionally overridden, e.g. for `Mount`) | Request-derived (attacker-controlled) but rarely read by user code directly; low priority. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#Context |
| `(*chi.Context).RoutePattern` | `func (x *Context) RoutePattern() string` | The **matched pattern** (e.g. `/users/{id}`), not raw attacker input | NOT a taint source — it's the static route template, not attacker-controlled data. Listed for completeness only. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#Context.RoutePattern |

### `middleware` subpackage: additional context/header-derived sources (opt-in)

These only apply when the corresponding middleware is installed with `r.Use(...)`.

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `middleware.URLFormat` (middleware) + `middleware.URLFormatCtxKey` (context key) | `func URLFormat(next http.Handler) http.Handler`; read via `r.Context().Value(middleware.URLFormatCtxKey).(string)` | Suffix of the (possibly chi-`RoutePath`-adjusted) request path after the last `.`, e.g. `json` from `/articles/1.json` | Path-derived source, same trust level as the raw URL path; trims the matched suffix from `chi.Context.RoutePath` as a side effect. Only present when `URLFormat` middleware is used. | https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#URLFormat |
| `middleware.RequestID` (middleware) + `middleware.GetReqID` | `func RequestID(next http.Handler) http.Handler`; `func GetReqID(ctx context.Context) string` | Value of the inbound `X-Request-Id` header (`middleware.RequestIDHeader`), stored under `middleware.RequestIDKey` and echoed back by `GetReqID` | Header-derived source: if the client supplies `X-Request-Id`, it is used verbatim as the request ID instead of generating one; falls back to a locally-generated ID only when the header is absent/empty. Commonly logged/propagated downstream, so treat `GetReqID`'s return value as tainted. | https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#GetReqID |
| `middleware.RealIP` | `func RealIP(h http.Handler) http.Handler` | Overwrites `r.RemoteAddr` with the first non-empty, IP-parseable value from `True-Client-IP`, `X-Real-IP`, or `X-Forwarded-For` (in that order) | Trust-dependent source/propagator: after this middleware runs, `r.RemoteAddr` is no longer the TCP peer address but attacker-spoofable header data, unless a trusted reverse proxy strips/sets these headers upstream. chi's own doc comment explicitly warns of this risk. Any code (including logging/authorization) reading `r.RemoteAddr` downstream of this middleware should treat it as tainted, consistent with client-IP trust caveats documented for echo/gin/fiber. | https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#RealIP |

Additionally, chi's `Mux.routeHTTP` (`mux.go`) calls `r.SetPathValue(key, value)` for every matched route param when compiled with Go ≥1.22 (guarded by `supportsPattern`/build tags in `pattern.go` / `pattern_fallback.go`). This means the standard library sink `(*http.Request).PathValue(name string) string` is transitively populated with the **same tainted values** as `chi.URLParam`, even though chi does not define `PathValue` itself. Any IAST source instrumentation of `net/http`'s `PathValue` will therefore also need chi-originated taint to flow correctly (or chi's `SetPathValue` call site should itself be treated as a taint-propagation point, tainting the value already written into `r`'s internal path-value storage).

### Inherited from `net/http` (not re-detailed here)

chi handlers receive an ordinary `*http.Request`; all of the following remain valid sources exactly as in `net/http` — see `net-http.md` for full signatures:
- Raw URL / request line: `r.URL`, `r.RequestURI`, `r.Method`.
- Query parameters: `r.URL.Query()`, `r.URL.RawQuery`.
- Headers: `r.Header`, `r.Header.Get(...)`, `r.Referer()`, `r.UserAgent()`.
- Cookies: `r.Cookie(...)`, `r.Cookies()`.
- Body: `r.Body`. (`r.GetBody` is a client-request-only field; for server requests it is unused/nil, so it is not a source here.)
- Form / POST form / multipart: `r.Form`, `r.PostForm`, `r.MultipartForm`, `r.FormValue`, `r.FormFile`, `r.ParseForm`, `r.ParseMultipartForm`.
- Host/authority: `r.Host`, `r.URL.Host`.
- Other: `r.RemoteAddr`, `r.TLS.ServerName`, `r.Trailer`.

## Sinks (framework surface)

chi does not introduce new response-writing types; sinks are the same `net/http` ones (`http.Redirect`, `http.ServeFile`, `http.ServeContent`, `(*http.Response Writer).Header().Set`, `http.SetCookie`, `html/template`) applied to a plain `http.ResponseWriter`/`*http.Request` — see `net-http.md` for the canonical catalog. chi's own package/`middleware` subpackage only contains two call sites worth flagging, both internal (not user-facing APIs to instrument as generic sinks, but relevant context if request-derived paths flow through them):

| API | Signature | Vulnerability class | Notes | Reference |
|---|---|---|---|---|
| `middleware.RedirectSlashes` | `func RedirectSlashes(next http.Handler) http.Handler` | Open redirect (low risk) | Internally builds a redirect target from `r.URL.Path` and calls `http.Redirect(w, r, path, 301)`; the path is trimmed/derived from the current request's own path only (not attacker-suppliable to a different host), so exploitability is minimal. Not a priority sink. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4/middleware#RedirectSlashes |
| `middleware.Profiler` (pprof mount) | internal handler in `profiler.go` | Open redirect (low risk) | Calls `http.Redirect(w, r, r.RequestURI+"/pprof/", http.StatusMovedPermanently)`; `r.RequestURI` is attacker-controlled but the sink is only reachable if pprof is deliberately mounted — not a generic app-facing sink. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4/middleware#Profiler |

No chi-specific static-file-serving, HTML-rendering, or cookie-setting APIs exist; use the generic `net/http` / `html/template` sink catalogs when a chi handler calls into those.

## Propagators / Binders

chi has no request-body/struct binding helpers (unlike frameworks such as gin or echo) and no dedicated param-parsing/coercion utilities beyond string extraction. The only "propagation" concern is structural:

| API | Signature | Notes | Reference |
|---|---|---|---|
| `(*chi.Context).URLParam` / `chi.URLParam` | see Sources above | Values are plain `string`; any typed conversion (e.g. `strconv.Atoi(chi.URLParam(r, "id"))`) is done by user code with stdlib `strconv`, which must already be covered by generic propagator instrumentation for numeric taint loss/whitelisting. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#URLParam |
| `(*chi.Mux).routeHTTP` → `r.SetPathValue` | internal, `mux.go` | Copies each matched `URLParams.Values[i]` into the request's Go 1.22+ path-value storage; effectively a same-value propagation from chi's route context into `net/http`'s `PathValue` mechanism. Not a public API but relevant for taint-flow completeness. | https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#Mux |

## Instrumentation notes

- Primary join point: `func chi.URLParam(r *http.Request, key string) string` — instrument the **return value** as tainted, sourced from category "path parameter", with `key` as metadata (parameter name). This is a plain free function, easy to wrap via orchestrion aspect on `github.com/go-chi/chi/v5.URLParam`.
- Also instrument `func chi.URLParamFromCtx(ctx context.Context, key string) string` identically (context-based variant used off the hot request-handling path, e.g. in nested helpers).
- Also instrument the method `func (*chi.Context).URLParam(key string) string` directly, since users may call `chi.RouteContext(r.Context()).URLParam(key)` without going through the package-level helpers — same taint category.
- If iterating `Context.URLParams.Keys`/`.Values` fields directly is deemed in-scope, taint must be applied at the point these slices are populated (`RouteParams.Add`, called from `tree.go` during route matching) rather than at read time, since it's a field access, not a function call, and orchestrion cannot intercept plain field reads. Recommend tainting inside `(*RouteParams).Add(key, value string)` (`context.go`) so any later read of `Values[i]` is already tainted — evaluate call frequency (once per matched param per request; not a hot loop).
- The `r.SetPathValue` call inside `(*Mux).routeHTTP` (`mux.go`) means the stdlib `(*http.Request).PathValue` source instrumentation will apply to chi-routed values too automatically, PROVIDED taint is attached to the string before/at the `SetPathValue` call (i.e. tainting happens in `RouteParams.Add`, not only at `chi.URLParam` read time). Otherwise a handler using `r.PathValue("id")` instead of `chi.URLParam(r, "id")` would see untainted data.
- `RoutePattern()` and `RoutePath` are lower priority: `RoutePattern()` returns the static template, not attacker data (no taint needed); `RoutePath` is rarely read directly by application code.
- All calls are on the request-handling hot path (once per routed request, per accessed param) — keep the aspect a cheap wrap/return-value taint, no additional allocations or copies.

## References

- https://pkg.go.dev/github.com/go-chi/chi/v5
- https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#URLParam
- https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#Context
- https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4#RouteContext
- https://pkg.go.dev/github.com/go-chi/chi/v5@v5.2.4/middleware
- https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#URLFormat
- https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#GetReqID
- https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#RealIP
- `net-http.md` (this repo) for the full inherited `*http.Request`/`http.ResponseWriter` source & sink catalog
