# gin — IAST Sources & Sinks

- **Module:** `github.com/gin-gonic/gin`
- **Version researched:** `v1.10.1`
- **Reference:** https://pkg.go.dev/github.com/gin-gonic/gin
- **Built on `net/http`:** yes — `*gin.Context` wraps `*http.Request` (`Context.Request` field) and `http.ResponseWriter` (`Context.Writer`); see `net-http.md` for the underlying stdlib surface. gin's own `Context` accessors are the primary instrumentation targets since handlers almost never touch `Context.Request` directly.

## Overview

`*gin.Context` is passed to every `gin.HandlerFunc` and is the sole API surface handlers use to read request data and write responses. It caches parsed query (`queryCache`) and form (`formCache`) values from the underlying `*http.Request`, and exposes URL/route params via the `Params` field (populated by the router before the handler chain runs). Response generation goes through `Context.Render` and the `render` package (JSON/HTML/String/Redirect/Data/...), while static file/route helpers live on `*RouterGroup`. A separate `binding` subpackage implements struct-binding (`Bind`/`ShouldBind*` family) that decodes request query/body/header/uri data into user structs.

## Sources

### Route / path params
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).Param` | `func (c *Context) Param(key string) string` | single named route param value | shortcut for `c.Params.ByName(key)` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Param |
| `(*gin.Context).Params` (field) | `Params Params` (`[]Param{Key, Value string}`) | all route params for the matched route | populated by router before handler runs; iterate directly | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Params |
| `(*gin.Context).AddParam` | `func (c *Context) AddParam(key, value string)` | appends attacker-controlled value into `Params` | used mostly in tests, but can be called by user code (e.g. custom routing shims) — value becomes tainted only if caller taints it; not itself a source of untrusted data but a propagation point | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.AddParam |

### Query string
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).Query` | `func (c *Context) Query(key string) (value string)` | single query value or `""` | wraps `GetQuery` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Query |
| `(*gin.Context).DefaultQuery` | `func (c *Context) DefaultQuery(key, defaultValue string) string` | single query value or caller-supplied default | default value is not tainted | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.DefaultQuery |
| `(*gin.Context).GetQuery` | `func (c *Context) GetQuery(key string) (string, bool)` | single query value + presence flag | primitive query accessor; others delegate to it | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetQuery |
| `(*gin.Context).QueryArray` | `func (c *Context) QueryArray(key string) (values []string)` | all values for a repeated query key | wraps `GetQueryArray` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.QueryArray |
| `(*gin.Context).GetQueryArray` | `func (c *Context) GetQueryArray(key string) (values []string, ok bool)` | all values for a repeated query key + presence | populates/reads `queryCache` (`c.Request.URL.Query()`) | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetQueryArray |
| `(*gin.Context).QueryMap` | `func (c *Context) QueryMap(key string) (dicts map[string]string)` | `key[subkey]=value` style query map | wraps `GetQueryMap` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.QueryMap |
| `(*gin.Context).GetQueryMap` | `func (c *Context) GetQueryMap(key string) (map[string]string, bool)` | query map + presence | both keys and values are attacker-controlled | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetQueryMap |

### Form / POST body (urlencoded & multipart)
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).PostForm` | `func (c *Context) PostForm(key string) (value string)` | single form field value | wraps `GetPostForm` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.PostForm |
| `(*gin.Context).DefaultPostForm` | `func (c *Context) DefaultPostForm(key, defaultValue string) string` | single form field value or default | default not tainted | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.DefaultPostForm |
| `(*gin.Context).GetPostForm` | `func (c *Context) GetPostForm(key string) (string, bool)` | single form field value + presence | primitive; triggers `ParseMultipartForm` via `initFormCache` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetPostForm |
| `(*gin.Context).PostFormArray` | `func (c *Context) PostFormArray(key string) (values []string)` | all values for repeated form key | wraps `GetPostFormArray` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.PostFormArray |
| `(*gin.Context).GetPostFormArray` | `func (c *Context) GetPostFormArray(key string) (values []string, ok bool)` | all values for repeated form key + presence | reads `formCache` = `req.PostForm` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetPostFormArray |
| `(*gin.Context).PostFormMap` | `func (c *Context) PostFormMap(key string) (dicts map[string]string)` | `key[subkey]=value` form map | wraps `GetPostFormMap` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.PostFormMap |
| `(*gin.Context).GetPostFormMap` | `func (c *Context) GetPostFormMap(key string) (map[string]string, bool)` | form map + presence | both keys and values attacker-controlled | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetPostFormMap |

### Multipart files / uploads
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).FormFile` | `func (c *Context) FormFile(name string) (*multipart.FileHeader, error)` | `*multipart.FileHeader` — `.Filename` (attacker-controlled string), `.Header` (MIME headers), `.Size` | filename is a classic path-traversal source when later used to build a filesystem path | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.FormFile |
| `(*gin.Context).MultipartForm` | `func (c *Context) MultipartForm() (*multipart.Form, error)` | `*multipart.Form{Value map[string][]string, File map[string][]*multipart.FileHeader}` | full multipart form incl. all field values and file headers/filenames | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.MultipartForm |
| `(*gin.Context).SaveUploadedFile` | `func (c *Context) SaveUploadedFile(file *multipart.FileHeader, dst string) error` | not a source itself, but a **path-traversal sink** if `dst` is built from `file.Filename` or other request data | see Sinks table | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.SaveUploadedFile |

### Raw body
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).GetRawData` | `func (c *Context) GetRawData() ([]byte, error)` | full raw request body bytes | reads `c.Request.Body` via `io.ReadAll`; consumes the stream (body no longer available afterwards unless re-set) | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetRawData |

### Headers
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).GetHeader` | `func (c *Context) GetHeader(key string) string` | single request header value | delegates to unexported `requestHeader` → `c.Request.Header.Get(key)` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.GetHeader |
| `(*gin.Context).ContentType` | `func (c *Context) ContentType() string` | `Content-Type` request header (flags stripped) | derived from header, attacker-controlled | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ContentType |
| `(*gin.Context).IsWebsocket` | `func (c *Context) IsWebsocket() bool` | boolean derived from `Connection`/`Upgrade` headers | low-value source (boolean), listed for completeness | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.IsWebsocket |

### Cookies
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).Cookie` | `func (c *Context) Cookie(name string) (string, error)` | named cookie value, URL-unescaped | delegates to `c.Request.Cookie(name)` then `url.QueryUnescape` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Cookie |

### Host / network / other
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).ClientIP` | `func (c *Context) ClientIP() string` | best-effort client IP, possibly derived from `X-Forwarded-For`/`X-Real-Ip` or a configurable trusted-platform header | attacker-controlled if proxy headers are trusted (`Engine.RemoteIPHeaders`, `TrustedPlatform`); otherwise derived from `RemoteAddr` (still partially attacker-influenced via socket) | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ClientIP |
| `(*gin.Context).RemoteIP` | `func (c *Context) RemoteIP() string` | IP parsed from `Request.RemoteAddr` | lower-trust concern than `ClientIP` (no header trust involved) but still worth tracking as `net/http` source | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.RemoteIP |
| `(*gin.Context).Request` (field) | `Request *http.Request` | full underlying stdlib request (`URL`, `Header`, `Host`, `Body`, `RemoteAddr`, `TLS`, ...) | escape hatch to raw `net/http` surface; catalogued in `net-http.md` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Request |
| `(*gin.Context).FullPath` | `func (c *Context) FullPath() string` | matched *route pattern* (e.g. `/user/:id`), not attacker data | NOT a taint source — included to avoid confusion with `Param`/`Params` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.FullPath |

## Sinks (framework surface)

| API | Signature | Vulnerability class | Notes | Reference |
|---|---|---|---|---|
| `(*gin.Context).Redirect` | `func (c *Context) Redirect(code int, location string)` | Open redirect | `location` written into `Location` response header via `render.Redirect`; unsanitized tainted `location` is a direct vuln | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Redirect |
| `(*gin.Context).Header` | `func (c *Context) Header(key, value string)` | Header/response-splitting (CRLF) injection | sets arbitrary response header key/value; gin does not sanitize CRLF beyond what `net/http`'s `Header.Set`/Go's http server enforces | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Header |
| `(*gin.Context).SetCookie` | `func (c *Context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool)` | Cookie injection / session fixation if tainted `name`/`value`/`domain`/`path` are attacker-controlled | value is `url.QueryEscape`d before being set, mitigating raw CRLF in value; `name`/`domain`/`path` are not escaped | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.SetCookie |
| `(*gin.Context).File` | `func (c *Context) File(filepath string)` | Path traversal | delegates to `http.ServeFile(c.Writer, c.Request, filepath)`; if `filepath` incorporates request data (e.g. a route param), traversal is possible | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.File |
| `(*gin.Context).FileAttachment` | `func (c *Context) FileAttachment(filepath, filename string)` | Path traversal (via `filepath`); header injection (via `filename` in `Content-Disposition`) | sets `Content-Disposition` from `filename` (quote-escaped only, not CRLF-escaped) then `http.ServeFile` with `filepath` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.FileAttachment |
| `(*gin.Context).FileFromFS` | `func (c *Context) FileFromFS(filepath string, fs http.FileSystem)` | Path traversal | temporarily overwrites `c.Request.URL.Path` with `filepath` and serves via `http.FileServer(fs)` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.FileFromFS |
| `(*gin.Context).SaveUploadedFile` | `func (c *Context) SaveUploadedFile(file *multipart.FileHeader, dst string) error` | Path traversal | writes uploaded content to `dst` via `os.MkdirAll`+`os.Create`; `dst` built from `file.Filename` (attacker-controlled) is the classic unsafe pattern | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.SaveUploadedFile |
| `(*RouterGroup).StaticFile` / `StaticFileFS` | `func (group *RouterGroup) StaticFile(relativePath, filepath string) IRoutes` | Path traversal (configuration-time, not typically fed by request data directly — `filepath` is fixed at route-registration time) | low risk in practice since `filepath` is a route-registration constant; included for completeness | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#RouterGroup.StaticFile |
| `(*RouterGroup).Static` / `StaticFS` | `func (group *RouterGroup) Static(relativePath, root string) IRoutes` | Path traversal | registers a wildcard route `/*filepath`; the handler reads `c.Param("filepath")` (attacker-controlled) and calls `fs.Open(file)` — traversal is mitigated by `http.Dir`/`http.FileServer`'s path cleaning, but custom `http.FileSystem` implementations may not clean the same way | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#RouterGroup.Static |
| `(*gin.Context).HTML` | `func (c *Context) HTML(code int, name string, obj any)` | Reflected XSS | renders `obj` (often containing tainted request data) into an HTML template via `engine.HTMLRender`; safety depends on the template engine's auto-escaping (Go `html/template` escapes by default, but `name` selection or raw `text/template` misuse can bypass it) | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.HTML |
| `(*gin.Context).String` | `func (c *Context) String(code int, format string, values ...any)` | Reflected XSS / response injection | writes `fmt.Sprintf`-style formatted tainted data directly into body with `Content-Type: text/plain`; if consumed as HTML downstream (e.g. via `XContentTypeOptions` misconfig) can enable XSS | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.String |
| `(*gin.Context).Data` | `func (c *Context) Data(code int, contentType string, data []byte)` | Reflected XSS / response injection | writes raw tainted bytes with a caller-chosen `contentType` (itself could be tainted, enabling content-type confusion) | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Data |
| `(*gin.Context).DataFromReader` | `func (c *Context) DataFromReader(code int, contentLength int64, contentType string, reader io.Reader, extraHeaders map[string]string)` | Reflected XSS / header injection | `extraHeaders` values are set on the response via `render.Reader`; tainted header values/content-type as above | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.DataFromReader |
| `(*gin.Context).JSON` / `IndentedJSON` / `SecureJSON` / `AsciiJSON` / `PureJSON` / `XML` / `YAML` / `TOML` / `ProtoBuf` | e.g. `func (c *Context) JSON(code int, obj any)` | Generally safe (structured encoding escapes/encodes values) — not primary XSS sinks, but reflect tainted data into responses (info leak / downstream sinks) | keep as low-priority propagation-into-response points, not framework-specific vulnerability sinks | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.JSON |
| `(*gin.Context).JSONP` | `func (c *Context) JSONP(code int, obj any)` | JSONP / reflected-JS injection | reads `callback` from the query string (`c.DefaultQuery("callback", "")`) and, when non-empty, renders `render.JsonpJSON{Callback: callback, Data: obj}`; `render/json.go`'s `JsonpJSON.Render` escapes `callback` with `template.JSEscapeString` before writing it (mitigates raw injection into the callback token itself), but `callback` remains query-derived and `obj` is reflected unescaped into the JS body — flag both `callback` and `obj` as tainted sink arguments | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.JSONP |
| `(*gin.Context).SSEvent` | `func (c *Context) SSEvent(name string, message any)` | Response body / event-stream injection | renders `sse.Event{Event: name, Data: message}` via `c.Render(-1, ...)`; low-priority sink — `name`/`message` are reflected into the SSE stream without HTML escaping | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.SSEvent |

## Propagators / Binders

| API | Signature | Notes | Reference |
|---|---|---|---|
| `(*gin.Context).Bind` | `func (c *Context) Bind(obj any) error` | picks binder via `binding.Default(method, contentType)`; aborts 400 on error | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Bind |
| `(*gin.Context).BindJSON` | `func (c *Context) BindJSON(obj any) error` | `binding.JSON` — decodes JSON request body into struct | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindJSON |
| `(*gin.Context).BindXML` | `func (c *Context) BindXML(obj any) error` | `binding.XML` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindXML |
| `(*gin.Context).BindQuery` | `func (c *Context) BindQuery(obj any) error` | `binding.Query` — binds `c.Request.URL.Query()` into struct | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindQuery |
| `(*gin.Context).BindYAML` | `func (c *Context) BindYAML(obj any) error` | `binding.YAML` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindYAML |
| `(*gin.Context).BindTOML` | `func (c *Context) BindTOML(obj any) error` | `binding.TOML` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindTOML |
| `(*gin.Context).BindHeader` | `func (c *Context) BindHeader(obj any) error` | `binding.Header` — binds request headers into struct fields | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindHeader |
| `(*gin.Context).BindUri` | `func (c *Context) BindUri(obj any) error` | binds `c.Params` (route params) into struct via `binding.Uri` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindUri |
| `(*gin.Context).MustBindWith` | `func (c *Context) MustBindWith(obj any, b binding.Binding) error` | generic entry point used by all `Bind*` shortcuts; aborts 400 on error | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.MustBindWith |
| `(*gin.Context).ShouldBind` | `func (c *Context) ShouldBind(obj any) error` | like `Bind` but does not abort/400 on error | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBind |
| `(*gin.Context).ShouldBindJSON` | `func (c *Context) ShouldBindJSON(obj any) error` | | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindJSON |
| `(*gin.Context).ShouldBindXML` | `func (c *Context) ShouldBindXML(obj any) error` | | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindXML |
| `(*gin.Context).ShouldBindQuery` | `func (c *Context) ShouldBindQuery(obj any) error` | | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindQuery |
| `(*gin.Context).ShouldBindYAML` | `func (c *Context) ShouldBindYAML(obj any) error` | | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindYAML |
| `(*gin.Context).ShouldBindTOML` | `func (c *Context) ShouldBindTOML(obj any) error` | | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindTOML |
| `(*gin.Context).ShouldBindHeader` | `func (c *Context) ShouldBindHeader(obj any) error` | | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindHeader |
| `(*gin.Context).ShouldBindUri` | `func (c *Context) ShouldBindUri(obj any) error` | builds `map[string][]string` from `c.Params` then `binding.Uri.BindUri` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindUri |
| `(*gin.Context).ShouldBindWith` | `func (c *Context) ShouldBindWith(obj any, b binding.Binding) error` | generic entry point: `b.Bind(c.Request, obj)` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindWith |
| `(*gin.Context).ShouldBindBodyWith` | `func (c *Context) ShouldBindBodyWith(obj any, bb binding.BindingBody) (err error)` | reads+caches full body (`BodyBytesKey`) then binds; safe to call multiple times | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindBodyWith |
| `(*gin.Context).BindWith` | `func (c *Context) BindWith(obj any, b binding.Binding) error` | **Deprecated** (`deprecated.go`) — logs a deprecation warning then delegates directly to `MustBindWith(obj, b)`; no distinct instrumentation needed if `MustBindWith` is already covered | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.BindWith |
| `(*gin.Context).ShouldBindBodyWithJSON/XML/YAML/TOML` | e.g. `func (c *Context) ShouldBindBodyWithJSON(obj any) error` | shortcuts for `ShouldBindBodyWith` | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.ShouldBindBodyWithJSON |
| `binding.Binding` implementations (`Form`, `Query`, `FormPost`, `FormMultipart`, `JSON`, `XML`, `ProtoBuf`, `MsgPack`, `YAML`, `TOML`, `Header`) | `Bind(*http.Request, any) error` | package-level singletons in `github.com/gin-gonic/gin/binding`; ultimately use `reflect`-based `mapping.go`/`form_mapping.go` to set struct fields from `url.Values`/headers/params — this is where field-by-field taint propagation must be implemented | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1/binding |
| `binding.Uri` | `BindUri(map[string][]string, any) error` | binds route params (`c.Params`) into struct fields | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1/binding#Uri |
| `(*gin.Context).Copy` | `func (c *Context) Copy() *Context` | duplicates the context for use outside the request's lifecycle (e.g. passing to a goroutine): copies the `Request` pointer as-is, deep-copies `Keys` (`map[string]any`) entry-by-entry, and deep-copies `Params` (`[]Param`) element-by-element into new backing storage | https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context.Copy |

## Instrumentation notes

- Preferred join points are exported `(*gin.Context)` methods (`Query`, `Param`, `PostForm`, `GetHeader`, `Cookie`, `GetRawData`, `FormFile`, `MultipartForm`, `ClientIP`, `RemoteIP`, `Redirect`, `Header`, `SetCookie`, `File`, `FileAttachment`, `FileFromFS`, `SaveUploadedFile`, `HTML`, `String`, `Data`, `DataFromReader`, `JSONP`, `SSEvent`) — orchestrion should wrap the **return values** (or, for sinks, the **arguments**) at these call sites; import path `github.com/gin-gonic/gin`, receiver `*Context`.
- Several public methods are thin wrappers around a `Get*` primitive (e.g. `Query`→`GetQuery`→`GetQueryArray`, `PostForm`→`GetPostForm`→`GetPostFormArray`). Instrumenting the lowest-level primitive (`GetQueryArray`, `GetPostFormArray`, `GetQueryMap`, `GetPostFormMap`) covers all higher-level shortcuts and avoids duplicate/missed taint on the derived helpers — but the public convenience methods are also directly reachable via the `binding` package's own request handling, so verify wrapper call graphs don't bypass the chosen join point.
- `Context.Params` is a plain field (`[]Param`), not a method: taint must be applied at the point the router populates it (outside `Context`, in the tree/router matching code) or by hooking `Context.Param` (the common accessor) plus any manual iteration over `c.Params`/`c.AddParam`.
- `queryCache`/`formCache` are lazily populated unexported fields; safe instrumentation targets are the exported accessor methods, not the cache fields.
- `ShouldBindBodyWith` caches the raw body under context key `BodyBytesKey` (`"_gin-gonic/gin/bodybyteskey"`) via `Context.Set`/`Context.Get` — if generic `Context.Set`/`Get` instrumentation is added elsewhere (e.g. for propagating taint through `Keys`), this specific key must remain compatible (transparent pass-through of `[]byte`).
- Binder implementations (`binding.formBinding`, `binding.queryBinding`, etc.) use reflection-based struct field mapping in `binding/form_mapping.go` — this is a hot path (every `Bind`/`ShouldBind*` call) and per-field taint propagation there must avoid extra allocations; prefer hooking at the `Binding.Bind`/`BindingBody.BindBody`/`BindingUri.BindUri` interface boundary (`github.com/gin-gonic/gin/binding`, method `Bind`) rather than inside the reflection loop, unless field-level provenance (which struct field came from which source) is required.
- `RouterGroup.createStaticHandler` (the handler registered by `Static`/`StaticFS`) reads `c.Param("filepath")` internally and calls `fs.Open` — this is a path-traversal-relevant flow but happens inside gin's own closure, not user code; if `Context.Param` is already instrumented as a source, taint will flow into `fs.Open` automatically as long as `http.FileSystem.Open` (or the concrete `os`/`gin.Dir` implementation) is treated as a path-traversal sink at the `net/http`/`os` layer.
- `Context.File`/`FileAttachment` delegate to `http.ServeFile` (stdlib) — the gin-specific value is only in exposing `filepath`/`filename` as sink arguments; the actual traversal check happens in `net/http`'s `ServeFile`, so this should cross-reference `net-http.md`'s sink catalog rather than duplicate stdlib-level logic.
- `SetCookie`'s `value` parameter is pre-escaped with `url.QueryEscape` before reaching `http.SetCookie`; `name`/`path`/`domain` are not — sink argument tracking should flag all four but note the reduced severity for `value`.
- `Context.Copy` (`context.go`) is a taint-propagation choke point: it reassigns `Request` by reference (any taint tracked on the request object survives untouched), but rebuilds `Keys` and `Params` into fresh maps/slices via manual element copies — any taint metadata attached to individual `Keys`/`Params` values (e.g. via `Context.Set`/`Context.Param`) must be explicitly propagated across this copy loop, since a naive shallow instrumentation keyed on the original map/slice identity would lose it.
- `JSONP`'s `callback` argument is read via `DefaultQuery` (already an instrumented source) and then passed through `template.JSEscapeString` in `render/json.go` before being written — if `template.JSEscapeString` is treated as a generic sanitizer/propagator elsewhere, reuse that mapping here rather than re-deriving escaping semantics.
- `BindWith` (`deprecated.go`) has no unique behavior beyond calling `MustBindWith`; if `MustBindWith` is instrumented, no separate join point is required for `BindWith`, though it remains part of the public API surface and should be documented as delegating rather than silently omitted from the catalog.

## References

- Context (all accessor/render methods): https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#Context
- RouterGroup (Static/StaticFile/StaticFS): https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1#RouterGroup
- binding package: https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1/binding
- render package: https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1/render
- render package (JSONP/SSE): https://pkg.go.dev/github.com/gin-gonic/gin@v1.10.1/render
- Source read locally: `context.go`, `deprecated.go`, `routergroup.go`, `binding/binding.go`, `render/json.go` in `/Users/romain.marcadier/go/pkg/mod/github.com/gin-gonic/gin@v1.10.1`
