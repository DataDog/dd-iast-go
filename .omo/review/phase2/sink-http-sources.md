# sink-http-sources: HTTP request source instrumentation
Verdict: Incorrect: eager header management changes observable request-header alias behavior, and lazy URL query management attributes application-created values to HTTP input.
Scope covered: `iast/net/http/orchestrion.yml`, `iast/net/http/http.go`, `iast/net/http/http_test.go`, `internal/taint/httpbridge/bridge.go`, `internal/taint/httpbridge/bridge_test.go`, `internal/taint/request/http.go`, `lazy.go`, `scope.go`, `reader.go`, `owner.go`, `iast/net/url/orchestrion.yml`, origin constants, and Go 1.26.6 `net/http/request.go`; focused woven tests and paired plain/woven reproducers.

## Findings

### sink-http-sources-F1: Header map replacement loses caller-visible mutations
- Severity: Critical
- Category: behavior-change
- Location: `iast/net/http/orchestrion.yml:109-119`; `internal/taint/request/http.go:142-155`
- Claim: At the direct-handler fallback, `WithContext` copies the request while retaining its original `Header` map, but eager tainting assigns a newly allocated map to the copy. A handler's `req.Header.Set` then changes only the new map; callers retaining the original header map no longer see that mutation. The server-handler advice also assigns the rebuilt map at line 41. Plain Go preserves the shared map alias; the instrumentation changes a customer-observable side effect for any request with eligible headers.
- Evidence: `.omo/review/evidence/sink-http-sources/review_alias_test.go` and `.omo/review/evidence/sink-http-sources/review_alias.out.txt`. In the private copy run `GOTOOLCHAIN=go1.26.6 go test -timeout 12m -count=1 -run ^TestReview_ -v ./iast/net/http` (PASS), then `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 12m -count=1 -run ^TestReview_ -v ./iast/net/http` (FAIL): `header map alias lost handler mutation: got "", want "observed"`.
- Fix: Preserve the original map object, inserting managed header strings/values without replacing its identity; handle key replacement and concurrent use without introducing additional observable map behavior. Where preserving alias semantics is impossible, drop header provenance rather than change host behavior.

### sink-http-sources-F2: Replaced URL query is falsely attributed to the request
- Severity: High
- Category: provenance
- Location: `internal/taint/request/lazy.go:28-45`; `internal/taint/request/http.go:69-75`
- Claim: Eager handling binds the `*url.URL` to the request owner, and every later `URL.Query()` on that object taints the returned map as HTTP parameters. It does not check whether `RawQuery` still contains the request's original input. After application code replaces `RawQuery` with a trusted literal, `URL.Query().Get` returns that literal marked with `OriginHttpRequestParameter`; downstream sinks can therefore report a false vulnerability.
- Evidence: `.omo/review/evidence/sink-http-sources/review_alias_test.go` and `.omo/review/evidence/sink-http-sources/review_alias.out.txt`. The same paired commands show plain Go PASS and woven FAIL: `replaced query yielded value "trusted-value", tainted=true; want clean trusted-value`.
- Fix: At eager binding retain a bounded snapshot or identity of the original query and only attribute lazy query results while the URL's query still corresponds to that input; after modification, leave the result clean rather than treating application-created values as request sources.

## Checked and found correct

- `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 12m -count=1 ./iast/net/http ./internal/taint/httpbridge ./internal/taint/request` passed before adding the failing reproducers. Existing tests exercise HTTP/1, TLS HTTP/2, h2c, direct and nested handlers, panic/permit release, sampling, capacity drops, normal query/form/multipart/cookie/path extraction, and owned versus direct body reads.
- The eager advice checks for a nil URL before taking path/query pointers; `EagerHTTP` never eagerly parses a form or reads a body, and it binds only the URL and body objects for later handling. `FromContext(ctx).Analysis()` safely handles a context without a scope.
- Static origin inspection confirms URI, path, raw query, header names/values, cookie names/values, query/form values/names, path values, multipart names/values, and owned body results use their corresponding HTTP origin constants; cookie and map value names derive from the original key. Existing woven assertions cover ordinary source creation, including query and multipart value origins.
- Go 1.26.6 `Request.ParseForm`/`ParseMultipartForm`/`FormValue`/`PostFormValue` behavior was compared with the advice: the wrappers defer source management until after the original method and do not replace its error return. `Cookie` preserves the returned pointer/error and manages fields only for a non-nil result; the body reader association does not consume the body at entry.

## Not covered / open questions

- Exhaustive combinations of manually pre-populated `Form`/`PostForm`, all malformed multipart errors, and concurrent mutations of caller-held request maps were not reproduced.
- HTTP/2 protocol handling beyond the existing woven integration tests and the precise performance cost of header and URL management were not measured.
