# net/http — IAST Sources & Sinks

- **Module:** `net/http` (Go standard library)
- **Version researched:** Go 1.26
- **Reference:** https://pkg.go.dev/net/http
- **Base document:** other framework catalogs in this directory (chi, echo, gin, gorilla/mux, httprouter, ...) build on top of `*http.Request` / `http.ResponseWriter` and cross-reference this file for the underlying stdlib sources/sinks instead of repeating them.

## Overview

A server `http.Handler`/`http.HandlerFunc` receives a `*http.Request` describing the
incoming request and an `http.ResponseWriter` used to produce the response.
Attacker-controlled data enters the handler through fields and methods of
`*http.Request` (URL, headers, cookies, body, form values, uploaded files,
connection metadata) and through the `url.URL` / `url.Values` / `mime/multipart`
types reachable from it. The handler writes the response by mutating the header
map returned by `ResponseWriter.Header()`, calling `ResponseWriter.Write`, or via
helper functions (`http.Redirect`, `http.SetCookie`, `http.ServeFile`,
`http.Error`, ...) that sit on top of the same interface.

## Sources

### Request line / raw URL

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).URL` | field `URL *url.URL` | Parsed request URL (path, raw query, fragment, etc.) | For server requests only `Path`/`RawPath`/`RawQuery`/`Fragment` are normally populated | https://pkg.go.dev/net/http#Request |
| `(*http.Request).RequestURI` | field `RequestURI string` | Unmodified request-target as sent by the client | Raw, unparsed; `URL` should usually be preferred | https://pkg.go.dev/net/http#Request |
| `(url.URL).Path` | field `Path string` | Decoded URL path | — | https://pkg.go.dev/net/url#URL |
| `(url.URL).RawPath` | field `RawPath string` | Optional encoded path hint | Use `EscapedPath()` rather than reading directly | https://pkg.go.dev/net/url#URL |
| `(*url.URL).EscapedPath` | `func (u *URL) EscapedPath() string` | Properly escaped path | — | https://pkg.go.dev/net/url#URL.EscapedPath |
| `(url.URL).RawQuery` | field `RawQuery string` | Raw, still-encoded query string | Use `Query()` to decode | https://pkg.go.dev/net/url#URL |
| `(url.URL).Fragment` | field `Fragment string` | Decoded URL fragment | Not sent to servers by conforming clients, but can be set/forwarded by intermediaries or single-page proxies | https://pkg.go.dev/net/url#URL |
| `(*url.URL).String` | `func (u *URL) String() string` | Reassembled full URL | Aggregates all of the above | https://pkg.go.dev/net/url#URL.String |
| `(*url.URL).RequestURI` | `func (u *URL) RequestURI() string` | Path + query, as would appear on the request line | — | https://pkg.go.dev/net/url#URL.RequestURI |

### Query parameters

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*url.URL).Query` | `func (u *URL) Query() url.Values` | Parsed query-string parameters | `url.Values` is `map[string][]string` | https://pkg.go.dev/net/url#URL.Query |
| `(url.Values).Get` | `func (v Values) Get(key string) string` | First value for a query key | — | https://pkg.go.dev/net/url#Values.Get |
| `(url.Values).Has` | `func (v Values) Has(key string) bool` | Whether key is present (boolean, not tainted data itself) | — | https://pkg.go.dev/net/url#Values.Has |
| `url.ParseQuery` | `func ParseQuery(query string) (Values, error)` | Parses an arbitrary (attacker-controlled) query string | Used internally by `URL.Query`; also directly reachable if handler code re-parses `RawQuery` | https://pkg.go.dev/net/url#ParseQuery |
| `(*http.Request).Form` (query portion) | field `Form url.Values` | Merged URL query + POST/PATCH/PUT body form values | Populated only after `ParseForm`; see Propagators | https://pkg.go.dev/net/http#Request |

### Path / route params

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).PathValue` | `func (r *Request) PathValue(name string) string` | Value bound to a `{name}` wildcard in an `http.ServeMux` pattern (Go 1.22+) | Populated by `ServeMux` routing before the handler runs | https://pkg.go.dev/net/http#Request.PathValue |
| `(*http.Request).Pattern` | field `Pattern string` | The `ServeMux` pattern string that matched | Not attacker-controlled itself, but reveals routing; low priority | https://pkg.go.dev/net/http#Request |

### Headers

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).Header` | field `Header http.Header` (`map[string][]string`) | All request headers except `Host` (promoted to `Request.Host`) | — | https://pkg.go.dev/net/http#Request |
| `(http.Header).Get` | `func (h Header) Get(key string) string` | First value of a header, canonicalized key lookup | — | https://pkg.go.dev/net/http#Header.Get |
| `(http.Header).Values` | `func (h Header) Values(key string) []string` | All values of a header | — | https://pkg.go.dev/net/http#Header.Values |
| `(*http.Request).UserAgent` | `func (r *Request) UserAgent() string` | `User-Agent` header value | Convenience wrapper over `Header.Get` | https://pkg.go.dev/net/http#Request.UserAgent |
| `(*http.Request).Referer` | `func (r *Request) Referer() string` | `Referer` header value | Convenience wrapper over `Header.Get` | https://pkg.go.dev/net/http#Request.Referer |
| `(*http.Request).Trailer` | field `Trailer http.Header` | Trailer header keys/values sent after the body | Populated with real values only after `Body` is read to EOF | https://pkg.go.dev/net/http#Request |
| `(*http.Request).BasicAuth` | `func (r *Request) BasicAuth() (username, password string, ok bool)` | Decoded `Authorization: Basic` username/password | — | https://pkg.go.dev/net/http#Request.BasicAuth |

### Cookies

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).Cookie` | `func (r *Request) Cookie(name string) (*Cookie, error)` | Single named cookie | Returns `http.ErrNoCookie` if absent | https://pkg.go.dev/net/http#Request.Cookie |
| `(*http.Request).Cookies` | `func (r *Request) Cookies() []*Cookie` | All cookies on the request | — | https://pkg.go.dev/net/http#Request.Cookies |
| `(*http.Request).CookiesNamed` | `func (r *Request) CookiesNamed(name string) []*Cookie` | All cookies matching a given name (Go 1.23+) | — | https://pkg.go.dev/net/http#Request.CookiesNamed |
| `(*http.Cookie).Value` / `.Name` | fields on `type Cookie struct` | Cookie name/value strings | Obtained via the accessors above | https://pkg.go.dev/net/http#Cookie |
| `http.ParseCookie` | `func ParseCookie(line string) ([]*Cookie, error)` | Parses a raw `Cookie` header line | Lower-level entry point than `Request.Cookies` | https://pkg.go.dev/net/http#ParseCookie |

### Raw body

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).Body` | field `Body io.ReadCloser` | Raw request body stream | Server never sets this nil; reading is the taint source, propagated to whatever consumes the reader (`io.ReadAll`, `json.Decoder`, etc.) | https://pkg.go.dev/net/http#Request |
| `(*http.Request).ContentLength` | field `ContentLength int64` | Declared body size | Metadata, not itself string/byte taint of interest | https://pkg.go.dev/net/http#Request |

### Form / POST form values

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).FormValue` | `func (r *Request) FormValue(key string) string` | First value for `key` from URL query or body form (calls `ParseMultipartForm` internally) | — | https://pkg.go.dev/net/http#Request.FormValue |
| `(*http.Request).PostFormValue` | `func (r *Request) PostFormValue(key string) string` | First value for `key` from PATCH/POST/PUT body only | — | https://pkg.go.dev/net/http#Request.PostFormValue |
| `(*http.Request).Form` | field `Form url.Values` | Combined URL query + body form values | Populated by `ParseForm`/`ParseMultipartForm` | https://pkg.go.dev/net/http#Request |
| `(*http.Request).PostForm` | field `PostForm url.Values` | Body-only form values | Populated by `ParseForm`/`ParseMultipartForm` | https://pkg.go.dev/net/http#Request |

### Multipart / uploaded files & filenames

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).FormFile` | `func (r *Request) FormFile(key string) (multipart.File, *multipart.FileHeader, error)` | Uploaded file content (`multipart.File`, an `io.Reader`) and its metadata | Calls `ParseMultipartForm` internally | https://pkg.go.dev/net/http#Request.FormFile |
| `(*http.Request).MultipartForm` | field `MultipartForm *multipart.Form` | Parsed multipart form: `Value map[string][]string`, `File map[string][]*multipart.FileHeader` | Populated by `ParseMultipartForm` | https://pkg.go.dev/net/http#Request |
| `(*http.Request).MultipartReader` | `func (r *Request) MultipartReader() (*multipart.Reader, error)` | Low-level streaming multipart reader | Alternative to buffering via `ParseMultipartForm` | https://pkg.go.dev/net/http#Request.MultipartReader |
| `(multipart.FileHeader).Filename` | field `Filename string` | Client-supplied file name for an upload | Classic path-traversal / injection vector if used to build a filesystem path | https://pkg.go.dev/mime/multipart#FileHeader |
| `(multipart.FileHeader).Header` | field `Header textproto.MIMEHeader` | Per-part MIME headers (e.g. `Content-Type`) supplied by the client | — | https://pkg.go.dev/mime/multipart#FileHeader |
| `(*multipart.FileHeader).Open` | `func (fh *FileHeader) Open() (File, error)` | Opens the uploaded file content as an `io.Reader` | — | https://pkg.go.dev/mime/multipart#FileHeader.Open |
| `(*multipart.Reader).NextPart` | `func (r *Reader) NextPart() (*Part, error)` | Next streamed part (headers + body) from a `multipart.Reader` obtained via `Request.MultipartReader` | Decodes `Content-Transfer-Encoding: quoted-printable` transparently | https://pkg.go.dev/mime/multipart#Reader.NextPart |
| `(*multipart.Reader).NextRawPart` | `func (r *Reader) NextRawPart() (*Part, error)` | Same as `NextPart` without quoted-printable decoding | — | https://pkg.go.dev/mime/multipart#Reader.NextRawPart |
| `(*multipart.Part).FormName` | `func (p *Part) FormName() string` | `name` parameter of the part's `Content-Disposition: form-data` header | — | https://pkg.go.dev/mime/multipart#Part.FormName |
| `(*multipart.Part).FileName` | `func (p *Part) FileName() string` | Client-supplied file name from the part's `Content-Disposition` header (passed through `filepath.Base`) | Same path-traversal / injection concern as `FileHeader.Filename` | https://pkg.go.dev/mime/multipart#Part.FileName |
| `(multipart.Part).Header` | field `Header textproto.MIMEHeader` | Per-part MIME headers as seen while streaming | — | https://pkg.go.dev/mime/multipart#Part |
| `(*multipart.Part).Read` | `func (p *Part) Read(d []byte) (n int, err error)` | Streamed body bytes of the current part | Taint source for the bytes read into `d`, same pattern as `Request.Body` | https://pkg.go.dev/mime/multipart#Part.Read |

### Host / authority

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).Host` | field `Host string` | `Host` header (HTTP/1) or `:authority` pseudo-header (HTTP/2) | Promoted out of `Header` map by the server; classic Host-header-injection source | https://pkg.go.dev/net/http#Request |
| `(url.URL).Host` | field `Host string` | Host portion of `Request.URL` (usually empty for server requests except with absolute-form request targets, e.g. via proxies) | — | https://pkg.go.dev/net/url#URL |
| `(*url.URL).Hostname` | `func (u *URL) Hostname() string` | Host without port | — | https://pkg.go.dev/net/url#URL.Hostname |
| `(*url.URL).Port` | `func (u *URL) Port() string` | Port portion of host | — | https://pkg.go.dev/net/url#URL.Port |

### Other URL components (low frequency)

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(url.URL).Scheme` | field `Scheme string` | URL scheme | Low priority; relevant mainly for absolute-form request targets forwarded by proxies | https://pkg.go.dev/net/url#URL |
| `(url.URL).Opaque` | field `Opaque string` | Encoded opaque data for non-hierarchical URLs | Low priority, rarely populated for server requests | https://pkg.go.dev/net/url#URL |
| `(url.URL).User` | field `User *Userinfo` | Username/password embedded in the URL | Low priority; not populated for standard server requests, but reachable when handler code parses a forwarded absolute-form URL | https://pkg.go.dev/net/url#URL |
| `(url.URL).RawFragment` | field `RawFragment string` | Optional encoded fragment hint | Use `EscapedFragment()` rather than reading directly; low priority, non-standard for server-received fragments | https://pkg.go.dev/net/url#URL |
| `(*url.URL).EscapedFragment` | `func (u *URL) EscapedFragment() string` | Properly escaped fragment | Low priority, see `Fragment` above | https://pkg.go.dev/net/url#URL.EscapedFragment |
| `(*url.Userinfo).Username` | `func (u *Userinfo) Username() string` | Username portion of `URL.User` | Low priority | https://pkg.go.dev/net/url#Userinfo.Username |
| `(*url.Userinfo).Password` | `func (u *Userinfo) Password() (string, bool)` | Password portion of `URL.User` | Low priority; sensitive if present | https://pkg.go.dev/net/url#Userinfo.Password |

### Other (connection / TLS metadata)

| API | Signature | Data exposed | Notes | Reference |
|---|---|---|---|---|
| `(*http.Request).RemoteAddr` | field `RemoteAddr string` | Client `"IP:port"` as recorded by the server | Not attacker-fully-controlled in general (comes from the TCP layer) but is influenceable via proxies (`X-Forwarded-For` is a plain header, see Headers) | https://pkg.go.dev/net/http#Request |
| `(*http.Request).TLS` | field `TLS *tls.ConnectionState` | TLS connection info for the request | — | https://pkg.go.dev/net/http#Request |
| `(tls.ConnectionState).ServerName` | field `ServerName string` | SNI server name presented by the client during the TLS handshake | Client-controlled; can differ from the `Host` header | https://pkg.go.dev/crypto/tls#ConnectionState |
| `(*http.Request).Method` | field `Method string` | HTTP method | Low taint value, but can carry attacker input in verb-tampering scenarios | https://pkg.go.dev/net/http#Request |
| `(*http.Request).Proto` | field `Proto string` | HTTP protocol version string as sent | — | https://pkg.go.dev/net/http#Request |

## Sinks (framework surface)

| API | Signature | Vulnerability class | Notes | Reference |
|---|---|---|---|---|
| `http.Redirect` | `func Redirect(w ResponseWriter, r *Request, url string, code int)` | Unvalidated / open redirect | `url` argument is the sink parameter; if built from a tainted source (e.g. query param) without allow-listing, enables open redirect | https://pkg.go.dev/net/http#Redirect |
| `http.RedirectHandler` | `func RedirectHandler(url string, code int) Handler` | Unvalidated / open redirect | Handler-factory variant of `http.Redirect`; `url` is the sink parameter, forwarded verbatim to `Redirect` on every request. Low frequency (called once at route-registration time, not per-request) | https://pkg.go.dev/net/http#RedirectHandler |
| `(http.Header).Set` | `func (h Header) Set(key, value string)` | HTTP response header / CRLF injection | Both `key` and `value` are sink parameters when derived from tainted input; stdlib's header writer rejects raw CR/LF today, but the taint still matters for header-injection-adjacent issues (e.g. cache poisoning via reflected header value) | https://pkg.go.dev/net/http#Header.Set |
| `(http.Header).Add` | `func (h Header) Add(key, value string)` | HTTP response header injection | Same as `Set`, appends instead of replacing | https://pkg.go.dev/net/http#Header.Add |
| `http.SetCookie` | `func SetCookie(w ResponseWriter, cookie *Cookie)` | Trust-boundary violation / cookie injection | `cookie.Name`/`cookie.Value`/other fields are sink parameters if tainted; also relevant for missing `Secure`/`HttpOnly`/`SameSite` when the cookie itself carries sensitive tainted data | https://pkg.go.dev/net/http#SetCookie |
| `http.ServeFile` | `func ServeFile(w ResponseWriter, r *Request, name string)` | Path traversal | `name` is the sink parameter; stdlib rejects `..` in `r.URL.Path` as a best-effort guard, but a `name` built from other tainted fields (headers, form values) bypasses that guard entirely | https://pkg.go.dev/net/http#ServeFile |
| `http.ServeFileFS` | `func ServeFileFS(w ResponseWriter, r *Request, fsys fs.FS, name string)` | Path traversal | Same as `ServeFile` but against an `fs.FS`; same caveat about `name` | https://pkg.go.dev/net/http#ServeFileFS |
| `http.ServeContent` | `func ServeContent(w ResponseWriter, req *Request, name string, modtime time.Time, content io.ReadSeeker)` | Content-Type inference taint (at most) | `name` is never opened and never sent in the response; it is used only to guess `Content-Type` from its extension when the header isn't already set. Not a path-traversal or Content-Disposition sink. The `content` reader is the actual data source and should itself not come from an unsanitized path built with tainted input | https://pkg.go.dev/net/http#ServeContent |
| `http.Dir` / `(http.Dir).Open` | `type Dir string`; `func (d Dir) Open(name string) (File, error)` | Path traversal | Backing implementation used by `http.FileServer`; `name` (derived from `r.URL.Path` by `FileServer`) is the sink parameter | https://pkg.go.dev/net/http#Dir |
| `http.FileServer` / `http.FileServerFS` | `func FileServer(root FileSystem) Handler`; `func FileServerFS(root fs.FS) Handler` | Path traversal | Handler that serves `r.URL.Path` relative to `root`; the framework already strips `..` segments, but custom `FileSystem`/`fs.FS` implementations or `StripPrefix` misuse can reintroduce traversal | https://pkg.go.dev/net/http#FileServer |
| `(http.ResponseWriter).Write` | `Write([]byte) (int, error)` (interface method) | Reflected XSS / response body injection | The `[]byte` argument is the sink; writing tainted request data directly into the body without encoding is the base case for reflected XSS | https://pkg.go.dev/net/http#ResponseWriter |
| `http.Error` | `func Error(w ResponseWriter, error string, code int)` | Reflected text / information leak | `error` string argument is the sink parameter; `Error` explicitly resets `Content-Type` to `text/plain; charset=utf-8` and sets `X-Content-Type-Options: nosniff` before writing it, so it is not a primary XSS sink in the browser itself, but is still relevant if the message leaks sensitive tainted data (e.g. internal errors, stack traces) or is consumed and re-rendered downstream | https://pkg.go.dev/net/http#Error |
| `http.TimeoutHandler` | `func TimeoutHandler(h Handler, dt time.Duration, msg string) Handler` | Reflected body injection (low priority) | `msg` is the sink parameter: on timeout the wrapping handler writes it verbatim into a `503 Service Unavailable` response body via `io.WriteString`. Low frequency (configured once per handler, not per-request) | https://pkg.go.dev/net/http#TimeoutHandler |
| `(http.ResponseWriter).WriteHeader` | `WriteHeader(statusCode int)` (interface method) | n/a directly, but finalizes headers set via `Header().Set/Add` | Marks the point after which header mutations for 2xx-5xx responses have no effect; relevant for aspect ordering | https://pkg.go.dev/net/http#ResponseWriter |

Generic sinks such as `database/sql` (SQL injection), `os/exec` (command injection), `io/fs`/`os` file APIs (path traversal outside the `net/http` file-serving helpers above), outbound `net/http.Client` calls (SSRF), and `html/template`/`text/template` (XSS) are framework-agnostic and are cataloged elsewhere, not in this document.

## Propagators / Binders

| API | Signature | Notes | Reference |
|---|---|---|---|
| `(*http.Request).ParseForm` | `func (r *Request) ParseForm() error` | Parses `URL.RawQuery` and, for POST/PUT/PATCH with a form content type, the body, populating `Request.Form` and `Request.PostForm` from tainted sources (URL + Body) | https://pkg.go.dev/net/http#Request.ParseForm |
| `(*http.Request).SetPathValue` | `func (r *Request) SetPathValue(name, value string)` | Public setter backing `PathValue`; propagates taint into path-value storage when third-party routers/middleware (not just Go 1.22+ `ServeMux`) bridge their own route matches into `*http.Request` | https://pkg.go.dev/net/http#Request.SetPathValue |
| `(*http.Request).ParseMultipartForm` | `func (r *Request) ParseMultipartForm(maxMemory int64) error` | Calls `ParseForm` then parses a multipart body into `Request.MultipartForm`, propagating taint from `Body` into both form values and uploaded `FileHeader`s | https://pkg.go.dev/net/http#Request.ParseMultipartForm |
| `url.ParseQuery` | `func ParseQuery(query string) (Values, error)` | Propagates taint from a raw query string (e.g. `URL.RawQuery`) into `url.Values` | https://pkg.go.dev/net/url#ParseQuery |
| `(*url.URL).Query` | `func (u *URL) Query() url.Values` | Propagates taint from `URL.RawQuery` into `url.Values` | https://pkg.go.dev/net/url#URL.Query |
| `url.Parse` | `func Parse(rawURL string) (*URL, error)` | Propagates taint from a raw URL string into every field of the resulting `*url.URL` | https://pkg.go.dev/net/url#Parse |
| `url.ParseRequestURI` | `func ParseRequestURI(rawURL string) (*URL, error)` | Same as `Parse`, for request-URI-only forms (must be absolute or path-absolute) | https://pkg.go.dev/net/url#ParseRequestURI |
| `url.QueryUnescape` | `func QueryUnescape(s string) (string, error)` | Propagates taint through percent-decoding of a query-escaped string | https://pkg.go.dev/net/url#QueryUnescape |
| `url.PathUnescape` | `func PathUnescape(s string) (string, error)` | Propagates taint through percent-decoding of a path-escaped string | https://pkg.go.dev/net/url#PathUnescape |
| `(url.Values).Encode` | `func (v Values) Encode() string` | Propagates taint from a `url.Values` map back into an encoded query string | https://pkg.go.dev/net/url#Values.Encode |
| `http.ParseCookie` | `func ParseCookie(line string) ([]*Cookie, error)` | Propagates taint from a raw `Cookie` header value into `[]*Cookie` | https://pkg.go.dev/net/http#ParseCookie |
| Body decoding (`encoding/json`, `encoding/xml`, `io.ReadAll`, etc.) | e.g. `func (dec *json.Decoder) Decode(v any) error` reading from `Request.Body` | Not part of `net/http` itself, but is the dominant way body taint flows into arbitrary structs; must be covered by the corresponding `encoding/*` / `io` propagator aspects so taint reaches struct fields | https://pkg.go.dev/encoding/json#Decoder.Decode |
| `(*http.Request).Clone` / `.WithContext` | `func (r *Request) Clone(ctx context.Context) *Request`; `func (r *Request) WithContext(ctx context.Context) *Request` | Produce a shallow copy of the request; any taint tracking keyed by request pointer identity must be re-associated with the clone | https://pkg.go.dev/net/http#Request.Clone |

## Instrumentation notes

- **`(*http.Request).FormValue` / `PostFormValue`**: hook as a return-value source; both internally call `ParseMultipartForm`, so a single aspect on these two methods (plus `FormFile`) covers the majority of "get one param" call sites without needing to intercept `ParseForm` separately.
- **`Request.Form` / `Request.PostForm` / `Request.MultipartForm` fields**: since these are plain struct fields (not method calls), taint must be attached at the point they are populated — i.e. by hooking `ParseForm`/`ParseMultipartForm` on return and tainting the resulting `url.Values`/`multipart.Form` maps in bulk, since orchestrion cannot intercept a bare field read.
- **`(url.URL).Query`**: hook as a return-value source (returns `url.Values`); this is the single highest-traffic query-parameter entry point across virtually every framework built on `net/http`.
- **`Header.Get`/`Values`/`(*Request).UserAgent`/`Referer`**: cheap, frequently-called accessors; gate any wrapping logic behind the existing `CanBeTainted`-style fast path since these sit in every request's hot path (header lookups happen many times per request in typical middleware stacks).
- **`Request.Body`**: taint should be attached to the `io.ReadCloser` value itself (wrapping `Read`) rather than per-call, since body reads are inherently streaming and the field is read once and passed around.
- **`multipart.FileHeader.Filename`**: struct field populated during multipart parsing; taint it in bulk when `ParseMultipartForm`/`FormFile` returns, same pattern as `Form`/`PostForm`.
- **`http.Redirect` / `http.SetCookie` / `Header.Set`/`Add` / `ResponseWriter.Write` / `http.ServeFile`/`ServeFileFS` / `http.Error`**: hook as argument sinks (check taint on the specific string/[]byte argument named above) at the call site; these are comparatively low-frequency (once or a few times per request) so the cost of a taint check here is negligible relative to gains, but the check itself should still short-circuit via `CanBeTainted` before doing any propagation-graph walk.
- **`http.FileServer`/`http.Dir.Open`**: lower priority to instrument directly since `FileServer` already derives its `name` from `r.URL.Path` with `..`-stripping baked in; the higher-value target is any *user* code that builds a `name`/path from other tainted sources (headers, form values) and calls `ServeFile`/`os.Open`, which is caught by the generic path-traversal sink instrumentation, not a `net/http`-specific aspect.
- **`Request.Clone`/`WithContext`**: needed only to keep request-scoped taint bookkeeping (if any is keyed off the `*Request` pointer) consistent across clones; not a source/sink itself.

## References

- https://pkg.go.dev/net/http
- https://pkg.go.dev/net/http#Request
- https://pkg.go.dev/net/http#ResponseWriter
- https://pkg.go.dev/net/http#Header
- https://pkg.go.dev/net/http#Cookie
- https://pkg.go.dev/net/http#ServeFile
- https://pkg.go.dev/net/http#FileServer
- https://pkg.go.dev/net/http#Redirect
- https://pkg.go.dev/net/url
- https://pkg.go.dev/net/url#Values
- https://pkg.go.dev/mime/multipart#FileHeader
- https://pkg.go.dev/mime/multipart#Form
- https://pkg.go.dev/mime/multipart#Reader
- https://pkg.go.dev/mime/multipart#Part
- https://pkg.go.dev/net/url#Userinfo
- https://pkg.go.dev/crypto/tls#ConnectionState
- Source read at: `/opt/homebrew/Cellar/go/1.26.4/libexec/src/net/http/{request.go,header.go,cookie.go,server.go,fs.go,response.go}`, `/opt/homebrew/Cellar/go/1.26.4/libexec/src/net/url/url.go`, `/opt/homebrew/Cellar/go/1.26.4/libexec/src/mime/multipart/{formdata.go,multipart.go}`
