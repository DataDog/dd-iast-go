# echo (v4) — IAST Sources & Sinks

- **Module:** `github.com/labstack/echo/v4`
- **Version researched:** `v4.13.3`
- **Reference:** https://pkg.go.dev/github.com/labstack/echo/v4
- **Built on `net/http`:** yes — `echo.Context` wraps `*http.Request` / `http.ResponseWriter` (via `echo.Response`); underlying `net/http` sources also apply (see `net-http.md`). echo's own `Context` accessors are the primary instrumentation targets since handlers almost never touch `*http.Request` directly.

## Overview

`echo.Context` is an interface passed to every `echo.HandlerFunc`; its single concrete implementation is the unexported `*echo.context` struct (`context.go`). Handlers read request data exclusively through `Context` accessor methods (`Param`, `QueryParam`, `FormValue`, `Cookie`, `Bind`, ...) and write responses through `Context` writer methods (`String`, `HTML`, `JSON`, `Redirect`, `File`, `SetCookie`, `Response().Header()`, ...). `Context.Request()` and `Context.Response()` expose the raw `*http.Request` / `*echo.Response` (itself wrapping `http.ResponseWriter`) for anything not covered by the higher-level API.

## Sources

### Path / route params
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).Param` | `Param(name string) string` | Single path parameter value | Reads `pnames`/`pvalues` set by router | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).ParamValues` | `ParamValues() []string` | All path parameter values | Order matches `ParamNames()` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).ParamNames` | `ParamNames() []string` | Path parameter names | Not attacker-controlled data itself, but pairs with `ParamValues` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |

### Query params
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).QueryParam` | `QueryParam(name string) string` | Single query param value | Backed by `(*url.URL).Query()`, cached in `c.query` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).QueryParams` | `QueryParams() url.Values` | All query params | Returns `net/url.Values` (`map[string][]string`) | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).QueryString` | `QueryString() string` | Raw undecoded query string | `c.request.URL.RawQuery` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |

### Headers
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).Request` | `Request() *http.Request` | Raw request incl. `.Header` (`http.Header`) | Primary way to read arbitrary headers; instrument like plain `net/http` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `DefaultBinder.BindHeaders` | `(b *DefaultBinder) BindHeaders(c Context, i interface{}) error` | All headers bound into struct fields tagged `header:"..."` | See Propagators section | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder.BindHeaders |

### Cookies
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).Cookie` | `Cookie(name string) (*http.Cookie, error)` | Single named cookie | Delegates to `(*http.Request).Cookie` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Cookies` | `Cookies() []*http.Cookie` | All request cookies | Delegates to `(*http.Request).Cookies` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |

### Raw body
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).Request` | `Request() *http.Request` | `.Body io.ReadCloser` | No dedicated echo body accessor; handlers read `c.Request().Body` directly | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `DefaultBinder.BindBody` | `(b *DefaultBinder) BindBody(c Context, i interface{}) error` | JSON/XML/form/multipart body decoded into struct | Dispatches on `Content-Type`; see Propagators | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder.BindBody |

### Form / POST form
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).FormValue` | `FormValue(name string) string` | Single form field (URL + body form) | Delegates to `(*http.Request).FormValue` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).FormParams` | `FormParams() (url.Values, error)` | All form fields | Calls `ParseMultipartForm`/`ParseForm` then returns `c.request.Form` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |

### Multipart / uploaded files
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).FormFile` | `FormFile(name string) (*multipart.FileHeader, error)` | Uploaded file header (incl. attacker-controlled `Filename`, `Header` MIME headers) | Wraps `(*http.Request).FormFile`; file content read via `fh.Open()` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).MultipartForm` | `MultipartForm() (*multipart.Form, error)` | Full multipart form: `Value map[string][]string`, `File map[string][]*multipart.FileHeader` | Calls `(*http.Request).ParseMultipartForm` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |

### Host / authority / scheme
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).Request` | `Request() *http.Request` | `.Host` field | Attacker-controlled `Host` header value | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Scheme` | `Scheme() string` | `http`/`https` derived from TLS state and `X-Forwarded-Proto`/`X-Forwarded-Protocol`/`X-Forwarded-Ssl`/`X-Url-Scheme` headers | Header-derived, spoofable unless behind trusted proxy | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |

### Other
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).RealIP` | `RealIP() string` | Client IP derived from `X-Forwarded-For` / `X-Real-IP` headers (or `Echo.IPExtractor`) or `RemoteAddr` | Header-derived, spoofable; taint-worthy as attacker-controlled string | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Path` | `Path() string` | Registered route pattern (e.g. `/users/:id`) | NOT attacker data (static route template) — do not taint | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).IsTLS` | `IsTLS() bool` | Whether connection is TLS | Boolean, low value as taint source | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).IsWebSocket` | `IsWebSocket() bool` | Derived from `Upgrade` header | Boolean | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Request` | `Request() *http.Request` | `.RemoteAddr`, `.TLS.ServerName` (SNI), `.URL` (`*url.URL`), `.RequestURI` | Same as generic `net/http` sources | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |

## Sinks (framework surface)

| API | Signature | Vulnerability class | Notes | Reference |
|---|---|---|---|---|
| `(echo.Context).Redirect` | `Redirect(code int, url string) error` | Open redirect | Sets `Location` header verbatim (validates `code` range only, not `url`); the `url` arg is the sink parameter | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Response` → `Response().Header().Set/Add` | `(r *Response) Header() http.Header` | Header/CRLF injection | `Header()` returns the live `http.Header` map of the underlying `http.ResponseWriter`; `Set`/`Add` are `net/http` `Header` methods, sink is any call with tainted value/key | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Response.Header |
| `(echo.Context).SetCookie` | `SetCookie(cookie *http.Cookie)` | Cookie injection / response splitting, insecure cookie config | Delegates to `http.SetCookie`; sink if any `*http.Cookie` field (`Name`,`Value`,`Domain`,`Path`) is tainted | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).File` | `File(file string) error` | Path traversal | `file` arg opened via `echo.Filesystem` (`fs.FS`, default `os.DirFS(".")`/`os.Open`); tainted `file` is the sink argument | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).FileFS` | `FileFS(file string, filesystem fs.FS) error` | Path traversal | Same as `File` but explicit `fs.FS` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Attachment` | `Attachment(file string, name string) error` | Path traversal (`file`) + header injection (`name` written into `Content-Disposition` via `fmt.Sprintf`, quote-escaped but not CRLF-stripped) | Calls `contentDisposition` then `File` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Inline` | `Inline(file string, name string) error` | Same as `Attachment` | Sets `Content-Disposition: inline` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `echo.StaticDirectoryHandler` | `StaticDirectoryHandler(fileSystem fs.FS, disablePathUnescaping bool) HandlerFunc` | Path traversal | Builds file name from route wildcard param `c.Param("*")` (URL-unescaped then `filepath.Clean`); registered by `(*Echo).Static`/`StaticFS` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#StaticDirectoryHandler |
| `(echo.Context).HTML` | `HTML(code int, html string) error` | Reflected XSS | Writes `html` string as `text/html` body verbatim, no escaping | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).HTMLBlob` | `HTMLBlob(code int, b []byte) error` | Reflected XSS | Same as `HTML` with `[]byte` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Render` | `Render(code int, name string, data interface{}) error` | Template/XSS (if renderer doesn't autoescape) or template injection if `name`/`data` tainted | Delegates to registered `echo.Renderer.Render`; framework-level dispatch only, actual templating engine is generic sink | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).String` | `String(code int, s string) error` | Reflected content injection (low severity unless `Content-Type` mismatched to HTML by caller) | Writes `text/plain`; still worth tracking if content-type later overridden | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).Blob` / `Stream` | `Blob(code int, contentType string, b []byte) error`, `Stream(code int, contentType string, r io.Reader) error` | Generic response body write / content-type driven XSS if `contentType` tainted to `text/html` | Both eventually call `Response().Write`; `contentType` is itself a taint-relevant argument | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).JSONP` | `JSONP(code int, callback string, i interface{}) error` | Reflected XSS / JSONP callback injection | `callback` is concatenated directly into the `text/javascript` body (`callback + "(" + json + ");"`), no validation/escaping | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(echo.Context).JSONPBlob` | `JSONPBlob(code int, callback string, b []byte) error` | Reflected XSS / JSONP callback injection | Same as `JSONP`; `callback` written verbatim via `Response().Write` before/after the `[]byte` payload | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context |
| `(*echo.Response).Write` | `(r *Response) Write(b []byte) (int, error)` | Reflected content injection / XSS | echo-specific body-write surface underlying `String`/`HTML`/`Blob`/`JSONPBlob`; equivalent sink to `http.ResponseWriter.Write` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Response.Write |
| `echo.StaticFileHandler` | `StaticFileHandler(file string, filesystem fs.FS) HandlerFunc` | Path traversal (low priority) | Handler factory used by `(*Echo).FileFS`/`File` routes; serves `file` from `filesystem` via `fsFile` without further sanitization of `file` itself | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#StaticFileHandler |
| `(*echo.Echo).FileFS` | `(e *Echo) FileFS(path, file string, filesystem fs.FS, m ...MiddlewareFunc) *Route` | Path traversal (low priority) | Registers a GET route serving `file` via `StaticFileHandler`; sink if route registration uses a tainted `file` path, consistent with gin's `StaticFile` coverage | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Echo.FileFS |
| `net/http` (generic, one-liner) | `html/template`, `database/sql`, `os/exec`, `io/fs`, `net/http.Client` | various | Not echo-specific — covered by generic sink catalogs, not detailed here | — |

## Propagators / Binders

| API | Signature | Notes | Reference |
|---|---|---|---|
| `(echo.Context).Bind` | `Bind(i interface{}) error` | Delegates to `Echo.Binder.Bind`; default order: `BindPathParams` → `BindQueryParams` (GET/DELETE/HEAD only) → `BindBody`. All three write into the same tagged struct fields — taint must propagate from param/query/body sources into destination struct fields matched by struct tag | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context.Bind |
| `DefaultBinder.Bind` | `(b *DefaultBinder) Bind(i interface{}, c Context) error` | Concrete implementation of the above; see `bindData` for the reflection-based field-by-field copy (string→any settable kind via `strconv`/`UnmarshalParam`/`UnmarshalText`) | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder.Bind |
| `DefaultBinder.BindPathParams` | `(b *DefaultBinder) BindPathParams(c Context, i interface{}) error` | Binds `c.ParamNames()`/`c.ParamValues()` into fields tagged `param:"..."` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder.BindPathParams |
| `DefaultBinder.BindQueryParams` | `(b *DefaultBinder) BindQueryParams(c Context, i interface{}) error` | Binds `c.QueryParams()` into fields tagged `query:"..."` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder.BindQueryParams |
| `DefaultBinder.BindBody` | `(b *DefaultBinder) BindBody(c Context, i interface{}) error` | Dispatches on `Content-Type`: JSON via `Echo.JSONSerializer.Deserialize`, XML via `encoding/xml`, form via `c.FormParams()` + `bindData(tag="form")`, multipart via `c.MultipartForm()` (`Value` + `File` maps) + `bindData` — multipart file headers (`*multipart.FileHeader`) are assigned directly into struct fields without string conversion | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder.BindBody |
| `DefaultBinder.BindHeaders` | `(b *DefaultBinder) BindHeaders(c Context, i interface{}) error` | Binds `c.Request().Header` (`http.Header`) into fields tagged `header:"..."` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder.BindHeaders |
| `BindUnmarshaler` / `encoding.TextUnmarshaler` | `UnmarshalParam(param string) error` / `UnmarshalText([]byte) error` | User types implementing either interface receive raw tainted strings in `unmarshalInputToField`; taint propagation must reach into user-defined `UnmarshalParam`/`UnmarshalText` calls made by `bindData` (`bind.go`) | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#BindUnmarshaler |
| `bindMultipleUnmarshaler` (internal) | `UnmarshalParams(params []string) error` | Same as above but for multi-value query/form fields (e.g. `?a=1&a=2`), matched via internal interface in `bind.go` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#section-sourcefiles (unexported, see `bind.go`) |
| `echo.QueryParamsBinder` | `QueryParamsBinder(c Context) *ValueBinder` | Builds a `*ValueBinder` sourced from `c.QueryParam`/`c.QueryParams`; taint must flow from query source into every destination pointer bound via the returned `ValueBinder` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#QueryParamsBinder |
| `echo.PathParamsBinder` | `PathParamsBinder(c Context) *ValueBinder` | Same pattern, sourced from `c.Param` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#PathParamsBinder |
| `echo.FormFieldBinder` | `FormFieldBinder(c Context) *ValueBinder` | Same pattern, sourced from `c.Request().FormValue`/`c.Request().Form` (URL + body form) | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#FormFieldBinder |
| `(*ValueBinder).String` | `(b *ValueBinder) String(sourceParam string, dest *string) *ValueBinder` | Copies the bound string value into `*dest` when non-empty; representative of the whole per-type binder API | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#ValueBinder.String |
| `(*ValueBinder).Strings` | `(b *ValueBinder) Strings(sourceParam string, dest *[]string) *ValueBinder` | Copies all bound values into `*dest` | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#ValueBinder.Strings |
| `(*ValueBinder).<Type>` / `Must<Type>` (e.g. `Int64`, `Bool`, `Time`, `Float64`, `Duration`, `UUID`, ...) | `(b *ValueBinder) Int64(sourceParam string, dest *int64) *ValueBinder` (representative) | Full family of typed binder methods in `binder.go`; each parses the tainted source string (via `strconv`/`time.Parse`/etc.) and writes the converted value into the destination pointer — taint must propagate across the type conversion | https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#ValueBinder |

## Instrumentation notes

- `echo.Context` is an interface; the only concrete implementation shipped is the unexported `*echo.context` struct in `context.go` (plus `context_fs.go` for `File`/`FileFS`). Orchestrion aspects must target method bodies on `*echo.context` (or wrap `echo.HandlerFunc`/middleware at the `Context` boundary), not the interface itself, since Go interfaces have no method bodies to instrument.
- Cheapest, highest-value hook: wrap the `echo.HandlerFunc` entry point (where `Echo.Add`/router dispatch invokes the matched handler) to tag the whole `*http.Request` once per request — mirrors `net/http` instrumentation and covers `Request()`-based access transparently.
- `Param`/`QueryParam`/`FormValue`/`Cookie` etc. are called extremely frequently (often multiple times per handler, and internally by `Bind`/`bindData`); taint decisions should be memoized/cached where possible (echo itself caches `c.query` after first `QueryParams()` call — reuse that pattern) to avoid quadratic re-tainting costs in hot paths.
- `QueryParam`/`QueryParams` lazily parse and cache into `c.query` (unexported field) — instrumenting the return value of `QueryParams()`/`QueryParam()` after the lazy-init branch is sufficient; no need to hook the internal `url.Values` construction separately.
- `FormFile`/`MultipartForm` trigger `ParseMultipartForm(32<<20)` (32 MB default) — body reads happen lazily on first call; taint tagging should happen on the returned `*multipart.FileHeader`/`*multipart.Form`, including the `Filename` field (attacker-controlled) and `Header` (MIME headers per part).
- `DefaultBinder.bindData` (in `bind.go`) is reflection-heavy and copies raw strings into destination struct fields; taint propagation here should hook `bindData`/`setWithProperType`/`unmarshalInputToField` at the point where a string value is assigned to a struct field via `reflect.Value.SetString`, or more simply propagate taint from the `data map[string][]string` argument to the `destination interface{}` argument as a single coarse-grained edge (function-level propagator) rather than instrumenting every reflection call site.
- Sinks such as `Redirect`, `SetCookie`, `HTML`/`HTMLBlob`, and `Attachment`/`Inline`/`File` are defined directly on `*echo.context` with simple signatures — straightforward argument-based sink hooks (check taint on the specific string/`[]byte`/`*http.Cookie` argument at function entry, before the body constructs the header/response).
- `Response().Header()` returns the live `http.Header` of the wrapped `http.ResponseWriter` (`(*Response).Header`, in `response.go`); the sink is on the `net/http.Header.Set`/`Add` calls made against that returned map, not on `Header()` itself — same instrumentation as generic `net/http` header-injection sinks.
- `contentDisposition` (unexported helper backing `Attachment`/`Inline`) builds the `Content-Disposition` value with `fmt.Sprintf` and only escapes `"`/`\`, not CRLF — both `file` and `name` parameters are viable sink arguments and should be checked independently (`file` → path traversal via `File`, `name` → header/response injection via the `Set` call).
- `StaticDirectoryHandler`'s wildcard path (`c.Param("*")`) is unescaped and `filepath.Clean`-ed before use; since `Clean` neutralizes simple `..` traversal within the FS root, treat this less as a guaranteed vuln and more as a taint-flow chain to verify (sink is still the `fs.Stat`/`fsFile` call using `name`).
- No dedicated `echo.Context` accessor exists for the raw request body — instrument `c.Request().Body` the same way as plain `net/http`.

## References

- Context interface & concrete impl: https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Context ; source `context.go`
- File/FS Context methods: source `context_fs.go`
- Static/File route registration & path traversal-relevant handler: https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#StaticDirectoryHandler ; source `echo_fs.go`
- Binder / DefaultBinder: https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#DefaultBinder ; source `bind.go`
- ValueBinder family (`QueryParamsBinder`, `PathParamsBinder`, `FormFieldBinder`, `ValueBinder`): https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#ValueBinder ; source `binder.go`
- Response wrapper (`Header`, `Write`, `WriteHeader`): https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#Response ; source `response.go`
- JSONP/JSONPBlob: source `context.go`
- Static file route registration (`StaticFileHandler`, `Echo.FileFS`): https://pkg.go.dev/github.com/labstack/echo/v4@v4.13.3#StaticFileHandler ; source `echo_fs.go`
- Echo router/handler registration: source `echo.go`
