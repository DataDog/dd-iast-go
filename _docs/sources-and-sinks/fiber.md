# fiber (v2) — IAST Sources & Sinks

- **Module:** `github.com/gofiber/fiber/v2`
- **Version researched:** `v2.52.12`
- **Reference:** https://pkg.go.dev/github.com/gofiber/fiber/v2
- **Built on `net/http`:** NO — built on `github.com/valyala/fasthttp`; uses `*fiber.Ctx`. See `fasthttp.md` for the underlying substrate. IMPORTANT: many accessors return strings backed by reused fasthttp buffers (zero-copy) — see the "Zero-copy" callout below and the taint-lifetime discussion in Instrumentation notes.

## Overview

`*fiber.Ctx` is passed to every `fiber.Handler` and wraps a `*fasthttp.RequestCtx` (field `c.fasthttp`, exposed via `Ctx.Context()`, `Ctx.Request()`, `Ctx.Response()`). Unlike `net/http`-based frameworks, fasthttp reuses `*RequestCtx` objects and their internal byte buffers across connections/requests via pools (`Ctx` itself is pooled: `App.AcquireCtx`/`ReleaseCtx`); most `Ctx` accessors convert `[]byte` to `string` with `utils.UnsafeString` (`app.getString`), i.e. **without copying**, unless `fiber.Config.Immutable` is set (in which case `app.getString`/`getBytes` are swapped for the `*Immutable` variants that copy). Response generation is done directly against `c.fasthttp.Response` (headers, body, status) rather than through an `http.ResponseWriter`. Struct-binding (`BodyParser`, `QueryParser`, `ParamsParser`, `CookieParser`, `ReqHeaderParser`) lives directly on `*Ctx` (no separate `binding` subpackage as in gin).

**Zero-copy callout:** by default (`Config.Immutable == false`, the default), `Ctx.Query`, `Ctx.Params`, `Ctx.Get`, `Ctx.Cookies`, `Ctx.FormValue`, `Ctx.Body`/`BodyRaw`, `Ctx.Hostname`, `Ctx.OriginalURL`, `Ctx.Path`, etc. return `string`s that alias the underlying fasthttp request/response byte buffers (`utils.UnsafeString` = pointer cast, no copy). Those buffers are owned by the pooled `*fasthttp.RequestCtx`/`Ctx` and get reused/overwritten as soon as the current request's handler chain returns (`ReleaseCtx`, fasthttp's `Server.serveConn` loop). Any taint metadata attached out-of-band (e.g. a side-table keyed by pointer/address, or a `sync.Map` keyed by unsafe pointer) will alias across requests once buffers are recycled, unless taint tracking uses a mechanism robust to this (e.g. wrapping strings in a taint-aware type at the point of return, or copying immediately when tainting).

## Sources

All entries are `(*fiber.Ctx)` methods unless noted.

### Request line / raw URL / path
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `OriginalURL` | `func (c *Ctx) OriginalURL() string` | full original request URI (path+query, as sent) | `fasthttp.Request.Header.RequestURI()` — zero-copy buffer alias | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.OriginalURL |
| `Path` | `func (c *Ctx) Path(override ...string) string` | request path (possibly case/slash-normalized per config) | zero-copy (`c.path`, backed by `c.pathBuffer`); optional `override` arg lets user *set* the path (propagation sink into routing state, not a source) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Path |
| `BaseURL` | `func (c *Ctx) BaseURL() string` | `protocol://host` derived from `Protocol()`+`Hostname()` | cached in `c.baseURI` after first call; composed from other sources below | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.BaseURL |
| `Request` | `func (c *Ctx) Request() *fasthttp.Request` | `*fasthttp.Request` — escape hatch to full fasthttp request (URI, header, body) | catalogue jointly with `fasthttp.md`; any method called on it is an independent source | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Request |
| `Context` | `func (c *Ctx) Context() *fasthttp.RequestCtx` | `*fasthttp.RequestCtx` — full fasthttp per-request context | broadest escape hatch; same buffer-reuse caveats apply | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Context |

### Query params
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `Query` | `func (c *Ctx) Query(key string, defaultValue ...string) string` | single query value or default | `c.fasthttp.QueryArgs().Peek(key)`, zero-copy | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Query |
| `Queries` | `func (c *Ctx) Queries() map[string]string` | all query params (last value wins per key) | iterates `QueryArgs().VisitAll`, zero-copy keys+values | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Queries |
| `QueryInt` | `func (c *Ctx) QueryInt(key string, defaultValue ...int) int` | query value parsed as `int` | value itself not tainted (converted to int) but presence/parse-success can leak info; low priority as a taint carrier | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.QueryInt |
| `QueryBool` | `func (c *Ctx) QueryBool(key string, defaultValue ...bool) bool` | query value parsed as `bool` | same as above (not a string taint carrier) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.QueryBool |
| `QueryFloat` | `func (c *Ctx) QueryFloat(key string, defaultValue ...float64) float64` | query value parsed as `float64` | same as above | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.QueryFloat |

### Path / route params
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `Params` | `func (c *Ctx) Params(key string, defaultValue ...string) string` | single named route param value | zero-copy unless `Config.Immutable`; reads `c.values` populated by the router at match time | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Params |
| `AllParams` | `func (c *Ctx) AllParams() map[string]string` | all route params for the matched route | built by calling `Params` for every name in `c.route.Params` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.AllParams |
| `ParamsInt` | `func (c *Ctx) ParamsInt(key string, defaultValue ...int) (int, error)` | route param parsed as `int` | not a string taint carrier | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.ParamsInt |

### Headers
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `Get` | `func (c *Ctx) Get(key string, defaultValue ...string) string` | single request header value | `c.fasthttp.Request.Header.Peek(key)`, zero-copy | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Get |
| `GetReqHeaders` | `func (c *Ctx) GetReqHeaders() map[string][]string` | all request headers (multi-valued) | `Request().Header.VisitAll`, zero-copy keys+values | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.GetReqHeaders |
| `Accepts` / `AcceptsCharsets` / `AcceptsEncodings` / `AcceptsLanguages` | `func (c *Ctx) Accepts(offers ...string) string` (and variants) | negotiated value derived from `Accept*` request headers, restricted to caller-supplied `offers` | low-value taint carrier (return is one of the caller's own `offers`, not raw header text), but `offers` selection logic parses raw header — list for completeness | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Accepts |
| `Is` | `func (c *Ctx) Is(extension string) bool` | boolean derived from `Content-Type` request header | not a string taint carrier | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Is |
| `Fresh` / `Stale` | `func (c *Ctx) Fresh() bool` | boolean derived from `If-Modified-Since`/`If-None-Match`/`Cache-Control` headers | not taint carriers | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Fresh |
| `XHR` | `func (c *Ctx) XHR() bool` | boolean derived from `X-Requested-With` header | not a taint carrier | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.XHR |

### Cookies
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `Cookies` | `func (c *Ctx) Cookies(key string, defaultValue ...string) string` | single cookie value | `c.fasthttp.Request.Header.Cookie(key)`, zero-copy | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Cookies |

### Raw body
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `Body` | `func (c *Ctx) Body() []byte` | full request body, transparently decompressed per `Content-Encoding` (gzip/br/deflate) | zero-copy `[]byte` alias unless `Config.Immutable` (then `utils.CopyBytes`); decompression path allocates fresh buffers already safe to treat as fresh/tainted-from-source | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Body |
| `BodyRaw` | `func (c *Ctx) BodyRaw() []byte` | raw (still compressed if applicable) request body | zero-copy unless `Immutable`; doc comment explicitly warns "valid only within the handler" | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.BodyRaw |

### Form / POST form
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `FormValue` | `func (c *Ctx) FormValue(key string, defaultValue ...string) string` | single value, searched across query args, POST args, then multipart form field values (fasthttp's `FormValue` order — does **not** search multipart file names) | zero-copy; note it can also surface a **query** value if no form value matches — cross-category source | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.FormValue |

### Multipart files / uploads
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `FormFile` | `func (c *Ctx) FormFile(key string) (*multipart.FileHeader, error)` | `*multipart.FileHeader` — `.Filename` (attacker-controlled), `.Header` (MIME headers), `.Size` | `.Filename` is the classic path-traversal source when used to build a filesystem path (e.g. with `SaveFile`) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.FormFile |
| `MultipartForm` | `func (c *Ctx) MultipartForm() (*multipart.Form, error)` | `*multipart.Form{Value map[string][]string, File map[string][]*multipart.FileHeader}` | full multipart form incl. all field values and file headers/filenames; delegates to `c.fasthttp.MultipartForm()` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.MultipartForm |
| `SaveFile` | `func (*Ctx) SaveFile(fileheader *multipart.FileHeader, path string) error` | not itself a source — see Sinks (path traversal via `path` arg) | delegates to `fasthttp.SaveMultipartFile` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.SaveFile |
| `SaveFileToStorage` | `func (*Ctx) SaveFileToStorage(fileheader *multipart.FileHeader, path string, storage Storage) error` | not itself a source — see Sinks (path/key traversal via `path` arg passed to `Storage.Set`) | reads file content via `fileheader.Open()`+`io.ReadAll` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.SaveFileToStorage |

### Host / network / other
| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `Hostname` | `func (c *Ctx) Hostname() string` | hostname from `X-Forwarded-Host` (if proxy trusted) or `Host` header/URI host | zero-copy; attacker-controlled if `EnableTrustedProxyCheck` is off (default) or proxy is in the trusted set | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Hostname |
| `Port` | `func (c *Ctx) Port() string` | remote TCP port | derived from socket `RemoteAddr()`, not header-controlled — low taint value | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Port |
| `IP` | `func (c *Ctx) IP() string` | remote IP, optionally parsed from a configurable proxy header (`Config.ProxyHeader`) | attacker-controlled if `EnableTrustedProxyCheck` is off (default) and `ProxyHeader` is configured | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.IP |
| `IPs` | `func (c *Ctx) IPs() []string` | slice of IPs parsed from `X-Forwarded-For` | attacker-controlled (header-derived); optionally validated as syntactically-valid IPs (`Config.EnableIPValidation`), which does not remove taint | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.IPs |
| `Protocol` | `func (c *Ctx) Protocol() string` | `"http"`/`"https"`, or attacker-controlled value from `X-Forwarded-Proto`/`X-Forwarded-Protocol`/`X-Url-Scheme` if proxy trusted | zero-copy for header-derived branch | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Protocol |
| `Subdomains` | `func (c *Ctx) Subdomains(offset ...int) []string` | subdomain labels split from `Hostname()` | inherits taint from `Hostname` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Subdomains |
| `Secure` | `func (c *Ctx) Secure() bool` | boolean (`Protocol() == "https"`) | not a taint carrier | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Secure |
| `Method` | `func (c *Ctx) Method(override ...string) string` | HTTP method string | low-value/enum-like source; `override` arg is a propagation point (user-settable, e.g. method-override middleware) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Method |
| `Range` | `func (c *Ctx) Range(size int) (Range, error)` | parsed `Range` request header into `Range{Type string, Ranges []RangeSet}` | `Type` field is attacker-controlled raw substring of header | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Range |
| `String` | `func (c *Ctx) String() string` | debug string containing request method and full URI (`c.fasthttp.Request.Header.Method()` + `c.fasthttp.URI().FullURI()`), plus connection ID/addresses | coarse, low-value source; doc comment states it's intended for logging | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.String |
| `ClientHelloInfo` | `func (c *Ctx) ClientHelloInfo() *tls.ClientHelloInfo` | TLS `ClientHelloInfo` captured during the handshake (only set when a `tlsHandler` is configured) | `ServerName` (SNI) and other fields are client-controlled; analogous to `net/http`'s `TLS.ServerName` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.ClientHelloInfo |

## Sinks (framework surface)

| API | Signature | Vulnerability class | Notes | Reference |
|---|---|---|---|---|
| `Redirect` | `func (c *Ctx) Redirect(location string, status ...int) error` | Open redirect | writes `location` directly into `Location` response header via `setCanonical` (no validation) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Redirect |
| `RedirectBack` | `func (c *Ctx) RedirectBack(fallback string, status ...int) error` | Open redirect | `location` comes from the `Referer` request **header** (attacker-controlled) unless empty, then falls back to `fallback`; delegates to `Redirect` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.RedirectBack |
| `RedirectToRoute` | `func (c *Ctx) RedirectToRoute(routeName string, params Map, status ...int) error` | Open redirect (lower risk — path built from named route + supplied `params`) | if `params` values (e.g. route params re-injected) are tainted, they are concatenated into the redirect URL/query string via `getLocationFromRoute` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.RedirectToRoute |
| `Location` | `func (c *Ctx) Location(path string)` | Open redirect / header injection | sets `Location` response header directly (`setCanonical`, no CRLF filtering beyond fasthttp's own header encoding) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Location |
| `Set` | `func (c *Ctx) Set(key, val string)` | Header injection / response splitting | sets arbitrary response header key/value via `fasthttp.ResponseHeader.Set`; fasthttp itself strips/rejects raw `\r\n` in header values, but downstream consumers should still flag tainted values here | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Set |
| `Append` | `func (c *Ctx) Append(field string, values ...string)` | Header injection | appends comma-joined `values` to an existing response header via `Set` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Append |
| `Vary` | `func (c *Ctx) Vary(fields ...string)` | Header injection (low severity — typically enum field names) | thin wrapper over `Append(HeaderVary, fields...)` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Vary |
| `Cookie` | `func (c *Ctx) Cookie(cookie *Cookie)` | Cookie injection / session fixation | sets `Name`, `Value`, `Path`, `Domain`, `SameSite` etc. on a `fasthttp.Cookie` with **no escaping**; any tainted field is a sink argument | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Cookie |
| `SendFile` | `func (c *Ctx) SendFile(file string, compress ...bool) error` | Path traversal | `file` is turned into an absolute path and set as the request URI for fasthttp's static-file handler (`fasthttp.FS`); if `file` incorporates request data (e.g. a route param) traversal is possible unless the fasthttp `FS` path-cleaning rejects `..` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.SendFile |
| `Download` | `func (c *Ctx) Download(file string, filename ...string) error` | Path traversal (via `file`) + header injection (via `filename` in `Content-Disposition`) | `filename` is quote-escaped (`app.quoteString`) but not CRLF-escaped; delegates path serving to `SendFile` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Download |
| `Attachment` | `func (c *Ctx) Attachment(filename ...string)` | Header injection (`Content-Disposition`) | `filepath.Base(filename[0])` is applied first (strips directory components) then quote-escaped; still not CRLF-escaped | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Attachment |
| `SaveFile` | `func (*Ctx) SaveFile(fileheader *multipart.FileHeader, path string) error` | Path traversal | writes uploaded content to `path` via `fasthttp.SaveMultipartFile`; classic unsafe pattern if `path` is built from `fileheader.Filename` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.SaveFile |
| `SaveFileToStorage` | `func (*Ctx) SaveFileToStorage(fileheader *multipart.FileHeader, path string, storage Storage) error` | Path/key traversal | `path` passed as-is to `Storage.Set`; safety depends on the `Storage` implementation | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.SaveFileToStorage |
| `Render` | `func (c *Ctx) Render(name string, bind interface{}, layouts ...string) error` | Reflected XSS / template injection | `bind` (often containing tainted request data) is rendered via the configured `Views` engine, or — if none configured — via stdlib `text/template` (**not** `html/template`, so **no auto-escaping**) against a file read using `name` as a path (path-traversal risk if `name` is tainted) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Render |
| `Format` | `func (c *Ctx) Format(body interface{}) error` | Reflected XSS | for the `"html"` branch, wraps `body` in a raw `"<p>" + b + "</p>"` string with **no escaping** and sends via `SendString` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Format |
| `SendString` | `func (c *Ctx) SendString(body string) error` | Reflected XSS / response injection | sets raw tainted body with whatever `Content-Type` is currently set (defaults to fasthttp's sniffed/default type) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.SendString |
| `Send` | `func (c *Ctx) Send(body []byte) error` | Reflected XSS / response injection | same as `SendString` for `[]byte` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Send |
| `Write` / `WriteString` / `Writef` | `func (c *Ctx) Write(p []byte) (int, error)` etc. | Reflected XSS / response injection | append tainted bytes/strings directly to response body | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Write |
| `SendStream` | `func (c *Ctx) SendStream(stream io.Reader, size ...int) error` | Reflected XSS / response injection (if `stream` sources tainted data) | sets response body from an arbitrary `io.Reader` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.SendStream |
| `JSONP` | `func (c *Ctx) JSONP(data interface{}, callback ...string) error` | Reflected XSS (JSONP callback injection) | `callback` (attacker-controllable if taken from request data) is concatenated **unescaped** into `cb + "(" + json + ");"` and served as `text/javascript` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.JSONP |
| `Type` | `func (c *Ctx) Type(extension string, charset ...string) *Ctx` | Content-type confusion / header injection (low severity — `extension` is mapped through a MIME table, but `charset` is inserted raw) | `charset` argument, if tainted, is concatenated into the `Content-Type` header value without escaping | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Type |
| `JSON` / `XML` | `func (c *Ctx) JSON(data interface{}, ctype ...string) error` | Generally safe (structured encoding) — not primary XSS sinks; `ctype` override is a lower-risk header-injection vector if tainted | listed for completeness / propagation-into-response tracking | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.JSON |
| `Links` | `func (c *Ctx) Links(link ...string)` | Response-header injection | builds a `<link>; rel="..."` list from caller-supplied `link` strings with no escaping and sets it as the `Link` response header via `setCanonical` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.Links |
| `ClearCookie` | `func (c *Ctx) ClearCookie(key ...string)` | Cookie/header manipulation (low severity) | with explicit `key` args, writes cookie-deletion headers (`DelClientCookie`) from caller-supplied names; with no args, iterates the request's own cookie names (`VisitAllCookie`) and reflects them into deletion headers (`DelClientCookieBytes`) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.ClearCookie |
| `Static` (`App`/`Group`) | `func (app *App) Static(prefix, root string, config ...Static) Router` / `func (grp *Group) Static(prefix, root string, config ...Static) Router` | Path traversal / static-file disclosure | registers a `fasthttp.FS` file server; its `PathRewrite` derives the served file path from `RequestCtx.Path()` (attacker-controlled request path) before stripping the route prefix — traversal-safety depends on `fasthttp.FS`'s own path cleaning (see `fasthttp.md`) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#App.Static |

## Propagators / Binders

| API | Signature | Notes | Reference |
|---|---|---|---|
| `BodyParser` | `func (c *Ctx) BodyParser(out interface{}) error` | dispatches on `Content-Type`: JSON → `config.JSONDecoder`; `application/x-www-form-urlencoded` → `PostArgs().VisitAll` into `map[string][]string`; `multipart/form-data` → `MultipartForm().Value`; XML → `encoding/xml.Unmarshal`; all non-JSON/XML paths go through `formatParserData`+`parseToStruct` (reflection-based, `github.com/gofiber/fiber/v2/internal/schema`) | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.BodyParser |
| `QueryParser` | `func (c *Ctx) QueryParser(out interface{}) error` | iterates `QueryArgs().VisitAll`, binds into struct via `schema` decoder tagged `query` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.QueryParser |
| `ParamsParser` | `func (c *Ctx) ParamsParser(out interface{}) error` | iterates `c.route.Params`, calling `c.Params` for each, binds into struct tagged `params` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.ParamsParser |
| `CookieParser` | `func (c *Ctx) CookieParser(out interface{}) error` | iterates `Request.Header.VisitAllCookie`, binds into struct tagged `cookie` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.CookieParser |
| `ReqHeaderParser` | `func (c *Ctx) ReqHeaderParser(out interface{}) error` | iterates `Request.Header.VisitAll`, binds into struct tagged `reqHeader` | https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx.ReqHeaderParser |
| `(*Ctx) parseToStruct` (unexported) | `func (*Ctx) parseToStruct(aliasTag string, out interface{}, data map[string][]string) error` | shared reflection-based decode step (`internal/schema.Decoder.Decode`) used by all `*Parser` methods above — the actual field-by-field taint-propagation point | (unexported; not directly linkable) |

## Instrumentation notes

- Preferred join points are exported `(*fiber.Ctx)` methods (`Query`, `Queries`, `Params`, `AllParams`, `Get`, `GetReqHeaders`, `Cookies`, `Body`, `BodyRaw`, `FormValue`, `FormFile`, `MultipartForm`, `Hostname`, `IP`, `IPs`, `Protocol`, `OriginalURL`, `Path`, `String`, `ClientHelloInfo` for sources; `Redirect`, `RedirectBack`, `RedirectToRoute`, `Location`, `Set`, `Append`, `Cookie`, `ClearCookie`, `Links`, `SendFile`, `Download`, `Attachment`, `SaveFile`, `Render`, `Format`, `SendString`, `Send`, `Write`/`WriteString`, `JSONP`, `Type` for sinks, plus `(*App).Static`/`(*Group).Static` for the static-file sink) — import path `github.com/gofiber/fiber/v2`, receiver `*Ctx` (or `*App`/`*Group` for `Static`).
- **Zero-copy buffer reuse is the central hazard for this framework.** `app.getString = utils.UnsafeString` by default (`app.go`, `App.init`), meaning strings returned by nearly every source accessor are unsafe pointer-casts over `[]byte` slices owned by the pooled `*fasthttp.RequestCtx`. Because both `*fiber.Ctx` (`App.pool`) and the underlying `*fasthttp.RequestCtx` are recycled by `fasthttp.Server` once the handler returns, any taint metadata that is *not* embedded in the string value itself (i.e. any out-of-band map/table keyed by string content or backing-array pointer) risks: (a) associating stale taint with a buffer now holding a *different* request's data, or (b) losing taint the instant the handler returns because the tracking side-table's key aliases freed/reused memory. Correct handling requires either (1) tainting via a wrapper/shadow mechanism that travels with the `string` header itself (e.g. Go's monotonic taint-string representation, if used elsewhere in this module) rather than an external table, or (2) forcing a copy (`utils.CopyString`/`CopyBytes`, equivalent to enabling `Config.Immutable`) at the instrumentation boundary before tainting, accepting the extra allocation cost on the hot path.
- `Config.Immutable` (bool, `app.go`) is a global app-level switch: when `true`, `app.getString`/`getBytes` are swapped for `getStringImmutable`/`getBytesImmutable` (which copy), and several methods (`Params`, `Body`, `Subdomains`) apply an *additional* explicit copy on top. Instrumentation should detect this config where feasible but must not assume it is enabled — default is `false`.
- `BodyRaw`'s doc comment explicitly says "Returned value is only valid within the handler. Do not store any references." — this is the framework's own acknowledgment of the buffer-reuse hazard; propagate this constraint into taint object lifetime (taint must not outlive the request context, or must be attached to a copy).
- `Ctx.Request()` / `Ctx.Context()` are broad escape hatches to `*fasthttp.Request` / `*fasthttp.RequestCtx` — any fasthttp-level method invoked directly by user or middleware code on these objects bypasses fiber-level instrumentation entirely; these need coverage at the fasthttp layer (see `fasthttp.md`) for completeness (e.g. `Request.Header.Peek`, `Request.PostArgs()`, `Request.Body()`).
- `Ctx` itself is pooled (`app.pool sync.Pool` in `App`, `AcquireCtx`/`ReleaseCtx` in `ctx.go`) — any per-`Ctx` state used for taint bookkeeping (if fiber-specific, e.g. stored via `Locals`) must be reset in `ReleaseCtx`/on `AcquireCtx` to avoid cross-request leakage, mirroring the buffer-reuse concern at the `Ctx` object level, not just its byte buffers.
- `Render`'s no-engine fallback path uses stdlib `text/template`, not `html/template` — no HTML auto-escaping occurs; this is a stronger XSS sink than `gin`'s `HTML` (which normally goes through `html/template`). Flag `Render` as high-severity regardless of whether a custom `Views` engine is configured, since third-party engines vary in escaping behavior.
- `SendFile`/`Download` route through `fasthttp.FS`'s static-file handler (a package-level singleton lazily built via `sync.Once`, shared across all `Ctx`s in the process) — the actual path-cleaning/traversal-prevention logic lives in `fasthttp`, so cross-reference `fasthttp.md`'s sink catalog for the authoritative traversal-safety analysis; fiber's contribution is exposing `file`/`filename` as attacker-reachable arguments.
- Binder methods (`BodyParser`, `QueryParser`, `ParamsParser`, `CookieParser`, `ReqHeaderParser`) all funnel through the unexported `(*Ctx).parseToStruct`, which uses a per-tag `sync.Pool` of `*schema.Decoder` (`internal/schema`, vendored `gorilla/schema`-derived) — this is a hot path (invoked per request when binding is used); prefer instrumenting at the exported `*Parser` method boundary (wrap `out` after return, or intercept the `map[string][]string` before it's handed to `parseToStruct`) rather than reaching into the reflection-based decoder, both for stability across fiber versions and to avoid additional overhead in the decode loop.

## References

- Ctx (all accessor/response methods): https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Ctx
- App / Config (`Immutable`, `EnableTrustedProxyCheck`, `ProxyHeader`, `EnableIPValidation`): https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Config
- App.Static / Group.Static (static-file sink): https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#App.Static, https://pkg.go.dev/github.com/gofiber/fiber/v2@v2.52.12#Group.Static
- fasthttp (underlying substrate — `Request`, `RequestCtx`, `ResponseHeader`, `FS`): https://pkg.go.dev/github.com/valyala/fasthttp
- Source read locally: `ctx.go`, `app.go`, `group.go`, `helpers.go`, `router.go` in `/Users/romain.marcadier/go/pkg/mod/github.com/gofiber/fiber/v2@v2.52.12`; `server.go` in `/Users/romain.marcadier/go/pkg/mod/github.com/valyala/fasthttp@v1.58.0` (for `FormValue` search order)
