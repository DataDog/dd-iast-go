# gorilla/mux — IAST Sources & Sinks

- **Module:** `github.com/gorilla/mux`
- **Version researched:** `v1.8.1`
- **Reference:** https://pkg.go.dev/github.com/gorilla/mux
- **Built on `net/http`:** yes — underlying `*http.Request` sources apply (see `net-http.md`). mux adds route variables.

## Overview

gorilla/mux is a request router/dispatcher built directly on `net/http`: `mux.Router` implements `http.Handler` and dispatches to `http.Handler`/`http.HandlerFunc` values, so handlers receive a plain `*http.Request`/`http.ResponseWriter` pair. The library's only additive attacker-controlled data is **route variables** — named host/path/query-template segments (e.g. `/products/{key}`) extracted by the router's regexp matcher and stashed in the request's `context.Context`. mux performs no response rendering, cookie-setting, or body/form parsing of its own, but its router does issue a small number of framework-initiated redirects (path cleaning, `StrictSlash`); see Sinks below. Otherwise, essentially all framework-surface sinks and other sources are inherited from `net/http`.

## Sources

### mux-specific: route variables

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `mux.Vars` | `func Vars(r *http.Request) map[string]string` | Named route-template variables merged from **host**, **path**, and **query** matches (e.g. `{id}`, `{key}`) into a single map, keyed by variable name (`regexp.go`, `routeRegexpGroup.setMatch`) | Reads `r.Context().Value(varsKey)`; returns `nil` if no route matched or vars weren't set (e.g. called outside the matched handler). Map **values** are attacker-controlled substrings extracted from the request's host/path/query (`extractVars`); map **keys** are developer-defined route-template variable names and are not tainted. This is the same map stored on `mux.RouteMatch.Vars` during matching. | https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Vars |
| `mux.RouteMatch.Vars` | `type RouteMatch struct { ...; Vars map[string]string; ... }` | Same route variables, populated during `Router.Match`/`Route.Match` before being attached to the request context | Mostly relevant to custom `MatcherFunc`/middleware inspecting matches directly rather than via `mux.Vars`. | https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#RouteMatch |
| `mux.CurrentRoute` | `func CurrentRoute(r *http.Request) *Route` | Returns the matched `*Route` (template strings, name, methods) — not itself attacker data, but `Route.GetPathTemplate()`/`GetVarNames()` can be combined with `Vars` for context | Not a source by itself (templates are developer-defined), listed for completeness since it's commonly used alongside `Vars`. | https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#CurrentRoute |

### Inherited from net/http

Query string (`r.URL.Query()`), headers (`r.Header`), cookies (`r.Cookies()`/`r.Cookie()`), raw body (`r.Body`), form/POST form (`r.Form`, `r.PostForm`, `r.FormValue`), multipart (`r.MultipartForm`), host (`r.Host`), raw URL/request line (`r.URL`, `r.RequestURI`) are all standard `*http.Request` accessors, unmodified by mux. See `net-http.md` for the full catalog and exact signatures. mux's `Route.Headers`/`Route.Queries`/`Route.Host`/`Route.Schemes` matchers only read these same fields for route-matching purposes; they don't create new sources or copies of the data.

## Sinks (framework surface)

mux provides no response-writing, templating, or cookie-setting API of its own — `Router.ServeHTTP` only dispatches to the matched `http.Handler`. It does, however, issue a couple of framework-initiated redirects itself before/while dispatching. All other framework-surface sinks applicable to a mux-based server are `net/http`'s (`http.ResponseWriter.Header().Set`, `http.Redirect`, `http.SetCookie`, `http.ServeFile`/`http.FileServer`, etc.) — see `net-http.md`.

| API | Signature | Vulnerability class | Notes | Reference |
|---|---|---|---|---|
| `(*mux.Router).ServeHTTP` path cleaning | `func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request)` | Open redirect (low risk) | When `!skipClean` and `cleanPath(path) != path`, sets `Location` header to the cleaned path and replies `301 Moved Permanently` (`mux.go` ~:175-190). The redirect target is the router-computed cleaned form of the incoming path, not raw unvalidated attacker input, so this is a low-risk framework-initiated redirect rather than an exploitable sink; listed for completeness. | https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Router.ServeHTTP |
| `StrictSlash` redirect handler | `routeRegexpGroup.setMatch` installs `http.RedirectHandler(u.String(), http.StatusMovedPermanently)` | Open redirect (low risk) | When a route is configured with `Route.StrictSlash(true)` and the request path's trailing slash doesn't match the template's, mux builds a redirect URL by adding/removing the trailing slash and wraps it in `http.RedirectHandler` as `match.Handler` (`regexp.go` ~:347-356). As with path cleaning, the target is router-derived (trailing slash toggle), not attacker-supplied, so risk is low; documented rather than omitted. | https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Route.StrictSlash |

## Propagators / Binders

mux has no request-binding/deserialization helpers (no struct-tag binding, no query/body decoding utilities). The main data transformation is internal: extracting host/path/query segments into the `Vars` map via the route's compiled regexp (`regexp.go`, `routeRegexpGroup.setMatch`) before storing them in the request context (`requestWithVars`, `mux.go`). mux does expose one public propagator, intended for tests, that injects a caller-supplied vars map directly into the request context for later `mux.Vars` reads.

| API | Signature | Notes | Reference |
|---|---|---|---|
| `mux.SetURLVars` | `func SetURLVars(r *http.Request, val map[string]string) *http.Request` | Returns a shallow-copied `*http.Request` with `val` installed as its route vars (via internal `requestWithVars`), so a later `mux.Vars(r)` call on the returned request returns `val` (`test_helpers.go` ~:9,17-18). Godoc marks it as intended "for testing purposes" (to inject vars without running a real match), but it is a real, exported propagation point: whatever taint is present on `val`'s entries when passed in should be preserved through the returned request/`mux.Vars`. | https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#SetURLVars |

## Instrumentation notes

- Primary join point: instrument the **return value** of `mux.Vars(r *http.Request) map[string]string` in package `github.com/gorilla/mux` — every string **value** in the returned map must be marked tainted (source: `http.route.parameter` or equivalent), keyed by request; map **keys** are developer-defined and must NOT be tainted. Values are raw host/path/query substrings captured by the route's regexp (`routeRegexpGroup.setMatch`), so no additional decoding step needs to be modeled.
- Secondary join point: instrument `mux.SetURLVars(r *http.Request, val map[string]string) *http.Request` to propagate existing taint on `val`'s entries onto the vars map attached to the returned request, so downstream `mux.Vars` reads stay consistent with taint already present on the input map.
- The framework-initiated redirects in `(*mux.Router).ServeHTTP` (path cleaning) and `StrictSlash` matching are low-risk (router-computed targets, not raw attacker input) and are not expected to require an unvalidated-redirect join point, but are documented under Sinks for completeness.
- `Vars` is typically called once per handler invocation and returns a small map (usually 0-5 entries), so the tainting cost is low; still, gate on a cheap check (e.g. skip if map is `nil`/empty) before iterating.
- Because `Vars` returns a *new* lookup into context-stored state on every call, taint tagging must be idempotent/cached per-request (e.g. keyed off the same `varsKey`-backed map instance) to avoid repeated re-tainting work if handlers call `mux.Vars` multiple times.
- No separate join point is needed for `mux.RouteMatch.Vars` unless custom `mux.MatcherFunc` implementations are also a target — in stock usage this map's contents end up in the same map object exposed via `mux.Vars`.
- `mux.CurrentRoute` and `Route.GetPathTemplate`/`GetVarNames` are informational only (developer-authored templates) and should NOT be treated as taint sources.
- All other request sources (headers, query, cookies, body, form) should be instrumented via the shared `net/http` aspects, not duplicated here, since mux does not wrap or copy `*http.Request` accessors.

## References

- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Vars
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#CurrentRoute
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#RouteMatch
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#SetURLVars
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Route.StrictSlash
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Router.ServeHTTP
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Router
- https://pkg.go.dev/github.com/gorilla/mux@v1.8.1#Route
- Source read: `mux.go` (`Vars`, `CurrentRoute`, `requestWithVars`, `ServeHTTP`), `route.go` (`Route.Match`, matcher constructors, `StrictSlash`), `regexp.go` (`routeRegexpGroup.setMatch`, `extractVars`), `test_helpers.go` (`SetURLVars`) in `github.com/gorilla/mux@v1.8.1`
