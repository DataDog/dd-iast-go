# IAST Sources & Sinks — HTTP Server Frameworks

This directory catalogs the **taint-tracking sources and sinks** exposed by
common Go HTTP server frameworks. It is research material to guide where
`dd-iast-go` should weave [orchestrion] aspects.

Terminology (see the repository `README.md`):

- **Source** — an API that surfaces attacker-controlled request data (query,
  path params, headers, cookies, body, form, multipart, host, …) as a Go value.
  These are the points where taint is *introduced*.
- **Sink** — a framework operation that becomes a vulnerability when fed a
  tainted, unsanitized value (redirect → open redirect, response header →
  header/CRLF injection, static file serving → path traversal, HTML/template
  render → XSS, …).
- **Propagator / Binder** — a helper that transforms request data into another
  value (e.g. binding a JSON body into a struct). Taint must flow *through*
  these so provenance is preserved.

Generic sinks that are not framework-specific — `database/sql`, `os/exec`,
`io/fs`, the `net/http` *client* (SSRF), `html/template`/`text/template` — are
intentionally out of scope here; they are cataloged with the relevant
vulnerability type, independent of the web framework.

## Frameworks

| Framework | Built on | Document | Distinctive surface |
|---|---|---|---|
| Go standard library | — | [`net-http.md`](./net-http.md) | Base: `*http.Request` sources, `http.ResponseWriter` sinks |
| chi v5 | `net/http` | [`chi.md`](./chi.md) | Route/path params |
| echo v4 | `net/http` | [`echo.md`](./echo.md) | `echo.Context` accessors + `Bind` family |
| gin | `net/http` | [`gin.md`](./gin.md) | `*gin.Context` accessors + `ShouldBind` family |
| gorilla/mux | `net/http` | [`gorilla-mux.md`](./gorilla-mux.md) | Route variables (`mux.Vars`) |
| fiber v2 | `fasthttp` | [`fiber.md`](./fiber.md) | `*fiber.Ctx`; zero-copy buffer reuse |
| fasthttp | — (own types) | [`fasthttp.md`](./fasthttp.md) | Low-level `[]byte` sources; buffer reuse |
| httprouter | `net/http` | [`httprouter.md`](./httprouter.md) | Route params via handler argument |

## Reading order

Start with [`net-http.md`](./net-http.md): chi, echo, gin, gorilla/mux and
httprouter all build on `*http.Request`, so their documents cover only the
framework-specific *additive* surface (mostly route parameters and binding
helpers) and cross-reference the standard-library catalog for the shared
sources.

fiber and fasthttp are the exception — they do **not** use `net/http`. They are
backed by `github.com/valyala/fasthttp`, whose accessors return `[]byte`/string
values that are zero-copy views over buffers reused across requests. This is a
taint-*lifetime* hazard called out in both documents.

[orchestrion]: https://github.com/DataDog/orchestrion
