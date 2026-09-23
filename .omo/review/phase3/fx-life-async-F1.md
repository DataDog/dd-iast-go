# fx-life-async-F1: verification of life-async-F1

## Verdict per finding
- **life-async-F1, CONFIRMED.** Behind `http.StripPrefix` or `Request.Clone`, `URL.Query()` results lose request taint, and SQLi built from a query parameter goes unreported. This is deterministic and needs no race or load. Only the URL.Query source is affected. `RawQuery`, `FormValue` and headers on the same forwarded request stay tainted and still report.

## Reproduction
My own reproducer is independent of the finder's. It uses the finder's harness conventions but none of their code: a woven integration testapp and a real `httptest` server, so `serverHandler.ServeHTTP` creates the scope. It adds a dd-trace root span the way a tracing middleware would, and a realistic sub-router: `mux.Handle("/api/", http.StripPrefix("/api", api))` with `api.Handle("/items", handler)`. The application-root handler does `name := r.URL.Query().Get("name")`, builds `"SELECT id FROM items WHERE name = '" + name + "'"`, and calls `db.QueryContext(r.Context(), query)`. The taint flags are sampled inside the handler, while the request is live.

Files: `evidence/fx-life-async-F1/fxurl.go` and `fxurl_test.go`. Output: `run2-go1266.out.txt`, the decisive run. `run1-go1266.out.txt` is the earlier run with the same report counts. Its taint flags were sampled after the request ended, so they all read false and should be ignored.

Command (private copy): `cp .omo/review/evidence/fx-life-async-F1/fxurl{,_test}.go <private-copy>/iast/integration/testapp/ && cd <private-copy>/iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -run '^TestFxURLQueryBehindStdlibRouting$' -count=1 -v -timeout 15m .`

Key output from run2 (Go 1.26.6, peak RSS 366 MB):
```
control: ServeMux, URL.Query            valueTainted=true  rawQueryTainted=true queryTainted=true  SQLi_reported=1
ServeMux + http.StripPrefix, URL.Query  valueTainted=false rawQueryTainted=true queryTainted=false SQLi_reported=0  FALSE NEGATIVE
ServeMux + http.StripPrefix, FormValue  valueTainted=true  rawQueryTainted=true queryTainted=true  SQLi_reported=1
Request.Clone middleware, URL.Query     valueTainted=false rawQueryTainted=true queryTainted=false SQLi_reported=0  FALSE NEGATIVE
http.TimeoutHandler (same *URL), Query  valueTainted=true  rawQueryTainted=true queryTainted=true  SQLi_reported=1
```
Differential controls isolate the cause. The scope is intact (FormValue behind the same StripPrefix reports), and `RawQuery` on the copied URL is still tainted. A shallow request copy that keeps the same `*url.URL` (TimeoutHandler) works. Only the fresh `*url.URL` object loses attribution. This matches the finder's `final-race.out.txt`, which shows `urlBoundOwners=0` and `reported=1 of 2`.

## Reachability
- Default configuration: yes. The test sets sampling to 100% and dedup off only to make it deterministic. Every analyzed request behind these shapes misses the finding. At default sampling, the miss applies to every sampled request.
- Triggers: `http.StripPrefix` (Go 1.26.6 `net/http/server.go`: `r2.URL = new(url.URL); *r2.URL = *r.URL`), `Request.Clone` (`r2.URL = cloneURL(r.URL)`), and any application copy such as `u := *r.URL; u.Query()`. `http.StripPrefix` is the stdlib's standard way to mount a sub-router. Frameworks that keep the original `*url.URL` (gorilla/mux, chi Mount, `WithContext`, `TimeoutHandler`, `MaxBytesHandler`) are unaffected.
- Go 1.27.0: `StripPrefix` and `Clone` are byte-identical in `/opt/homebrew/Cellar/go/1.27.0/libexec/src/net/http`, so the same behavior applies. I did not build woven on 1.27.0: per hooks-compile-matrix, those builds fail on the JSON advice and can reach 17-22 GiB RSS, and the machine load average was about 97.
- Documented limitation: no. Neither the README (Propagation coverage and Sink coverage) nor `01-design-intent.md` ("Deliberate limitations") mentions URL copies or StripPrefix. `URL.Query` is an advertised lazy source, and `database/sql` is a supported sink. This violates product rule 4 (no lost taint on supported paths).

## Adjusted severity
**High (unchanged).** This is a deterministic false negative on a supported source-to-sink path (URL.Query to SQL) behind stdlib routing. It is not rated higher because it drops nothing else: headers, FormValue and RawQuery still taint and report, and it never produces false positives or cross-request bleed.

## Root cause (file:line, HEAD 2e23b46)
- `internal/taint/request/lazy.go:31-36`: `ManageURLQuery` attributes only through `LookupObject(urlObject, store.BindingURL, ...)`, and `count != 1` returns the values unmanaged. The lookup key is pointer identity (`internal/taint/store/binding.go`, `LookupObjectValue` -> `dynamicPointer`).
- `internal/taint/request/http.go:74-77`: `EagerHTTP` binds only the `*url.URL` present at scope creation.
- `iast/net/http/orchestrion.yml:101-117`: the nested `application.http.Handler` entry reuses the existing scope (`__dd_iast_created == false`), so it never binds the copied URL. `URL.Query` gets no context (`iast/net/url/orchestrion.yml:24-28`), so no scope fallback is possible. The parsed values are fresh substrings produced by `url.ParseQuery`, and stdlib-internal propagation is not woven, so the tainted `RawQuery` does not carry over.

## Minimal fix
In `ManageURLQuery`, when `count == 0`, fall back to the provenance of the URL's `RawQuery`. It is the exact managed source clone that `EagerHTTP` installed, and struct copies keep it. Resolve its single live owner with a `VisitString`-style lookup that returns owner identity, call `analysisForOwner`, and `manageMap` as today. Keep the multi-owner ambiguity drop. To keep the bridge net/url-agnostic, pass `u.RawQuery` from the advice (`iasturlbridge.Query({{ .Function.Receiver }}, {{ .Function.Receiver }}.RawQuery, result)`) and change the bridge signature to match. A cheaper, partial alternative: in the non-created branch of `application.http.Handler`, bind `r.URL` to the context scope's owner when it is unbound. That covers StripPrefix and Clone forwarded to a woven handler, but not ad-hoc `*r.URL` copies. Add a woven regression test with StripPrefix and Clone cases, like `fxurl_test.go`.
