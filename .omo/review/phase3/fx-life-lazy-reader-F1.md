# fx-life-lazy-reader-F1: repeated form parsing races with form readers

## Verdict per finding
- **life-lazy-reader-F1: CONFIRMED.** Original severity: Critical. Adjusted severity: **Critical**.
  The mechanism is real, and the race is wider than the finding says. On a repeated `ParseMultipartForm` or `ParseForm` call, uninstrumented `net/http` only *reads* request fields. The woven advice *writes* on every call, in three places:
  1. `copy(target[start:], managed)` into the existing `Request.Form[name]` and `Request.PostForm[name]` slices (`internal/taint/request/lazy.go:141`, reached from `lazy.go:125-126`). This happens only when the request has an active IAST analysis.
  2. `req.MultipartForm.Value = iasthttpbridge.Multipart(...)` (`iast/net/http/orchestrion.yml:179-186`). This happens on every woven request, including sampled-out ones.
  3. `req.Form, req.PostForm = iasthttpbridge.Form(...)` (`iast/net/http/orchestrion.yml:152-159`). This also happens on every woven request, including sampled-out ones.

  Any goroutine that reads the already-parsed form during such a call races with these writes. The same program built without weaving is race-free.

## Reproduction
My reproducer is `.omo/review/evidence/fx-life-lazy-reader-F1/zz_fx_repeated_parse_test.go`. I wrote it independently of the finder's test and did not run the finder's test. It drives a real `httptest.Server`, so the woven `serverHandler.ServeHTTP` creates the IAST scope; it does not call `request.Begin` directly. It sends a real multipart or urlencoded POST. The handler:
1. parses the form once;
2. starts a goroutine that reads the parsed form 500 times, using `FormValue`, `PostFormValue`, or `MultipartForm.Value`;
3. re-calls `ParseMultipartForm(1<<20)` or `ParseForm()` 500 times on the handler goroutine.

The go statement orders the goroutine after the first parse. Commands, run from the private copy at HEAD 2e23b46 with `GOFLAGS=-p=4`:
```
GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -c -race -o woven126.test ./iast/net/http   # woven
GOTOOLCHAIN=go1.26.6 go test -c -race -o plain126.test ./iast/net/http                      # control
cd iast/net/http && ../../woven126.test -test.run '^TestFxRepeatedParse$/^<Subtest>$' -test.v -test.count=1
```
Key output, from `evidence/fx-life-lazy-reader-F1/repeated-parse-race-go1.26.6.out.txt`:
```
MultipartFormValue: races=2 ... woven=true value="attacker-input" tainted=true  EXIT=1
MultipartPostFormValue: races=2 ... tainted=true  EXIT=1
MultipartValueField: races=1 ... tainted=true  EXIT=1
URLEncodedParseForm: races=2 ... tainted=true  EXIT=1
SampledOutMultipartValueField: races=1 ... tainted=false EXIT=1   (sampling 0%, no analysis)
SampledOutURLEncodedParseForm: races=2 ... tainted=false EXIT=1   (sampling 0%, no analysis)
UNWOVEN: races=0 ... --- PASS: TestFxRepeatedParse (all 6 subtests)
```
Representative race stacks:
- MultipartFormValue: `Read at ... net/http/request.go:1424` (`FormValue` → `url.Values.Get`). `Previous write at ... internal/taint/request/lazy.go:141` ← `lazy.go:125` ← `<generated>:4` (`ParseMultipartForm` defer).
- A second race: `Read at <generated>:5` (the woven `FormValue` defer reading `MultipartForm.Value`). `Previous write at <generated>:4 +0x10c` (the `MultipartForm.Value =` assignment).
- URLEncodedParseForm: `Read at net/http/request.go:1420` (`FormValue` reading `r.Form`). `Previous write at <generated>:4` (the `ParseForm` defer assigning `r.Form, r.PostForm`).

Go 1.27.0: the same woven test binary does not compile under Go 1.27.0. The woven encoding/json advice fails with `dec.r undefined (type *Decoder has no field or method r)` (`evidence/.../go1.27.0-woven-build.out.txt`). That is a separate compile break, so I could not run the race under 1.27. The 1.27.0 `ParseForm`/`ParseMultipartForm` source is identical to 1.26.6: early return when already parsed, no writes. The advice is version-independent, so the race would apply once the build compiles.

Build memory: the woven build peaked at about 450 MB RSS, well under the 4 GB note threshold.

## Reachability
- **Default configuration, supported toolchain (1.26.6): reachable.** The trigger needs two things together:
  - the application re-calls `ParseForm` or `ParseMultipartForm` on a request that is already parsed. This is common: defensive `r.ParseForm()` in helpers and middleware, and frameworks such as echo re-calling `ParseMultipartForm` in `FormParams()`/`MultipartForm()` on every call;
  - another goroutine reads `r.Form`, `r.PostForm`, `r.FormValue`, or `r.MultipartForm` at the same time.

  The concurrency half is the uncommon part. `net/http` does not promise that `*Request` is goroutine-safe, but this specific pattern is race-free in plain Go, as my control run shows (0 races).
- The field-assignment races (items 2 and 3) do **not** depend on IAST admission. They occur on 100% of requests in any woven build, including the ~70% that default 30% sampling drops. Only the slice `copy` (item 1) needs an admitted request.
- **Not a documented limitation.** Neither the README nor `phase1/01-design-intent.md` mentions concurrency restrictions on request forms. It violates product rule 1 (a wrapped stdlib call gains side effects that uninstrumented Go does not have).

## Adjusted severity
**Critical (unchanged).** This is a data race in production woven code: a wrapped stdlib call gains memory writes that uninstrumented Go does not perform. The field-write variant affects every woven request regardless of sampling.

Mitigating note for triage: every racing write stores a value identical to the one already there (same map header, or string headers with the same data pointer and length). In practice this is unlikely to corrupt data. The concrete customer impact is `-race` test/CI failures that appear only in woven builds, plus formally undefined behavior under the Go memory model.

## Root cause (file:line, HEAD 2e23b46)
- `iast/net/http/orchestrion.yml:150-160`: the `ParseForm` defer assigns `req.Form, req.PostForm` unconditionally, even when the call was a no-op.
- `iast/net/http/orchestrion.yml:176-187`: the `ParseMultipartForm` defer assigns `req.MultipartForm.Value` unconditionally and calls `Multipart` even when `MultipartForm` was already set on entry.
- `internal/taint/request/lazy.go:119-127,131-142`: `ManageMultipart` calls `replaceMatchingSuffix` for every name. The suffix already holds the managed strings, so the equality check at `:137` passes and `copy` at `:141` rewrites identical values into slices that are shared with readers.

## Minimal fix
1. In both advice templates, check on entry whether the form was already parsed and skip all management in the defer when it was. Use `__dd_iast_parsed := req != nil && req.Form != nil` for `ParseForm`, and `req != nil && req.MultipartForm != nil` for `ParseMultipartForm`. The stdlib writes nothing on these paths, so the advice must not write either. A concurrent *first* parse is already racy in plain Go, so the entry check adds no new hazard.
2. Assign request fields only when the bridge actually returned a new map. For example, have `Form`/`Multipart` return a `changed bool` and guard the assignment with it. This removes the header write when management is dropped or the request is sampled out.
3. Defense in depth: in `replaceMatchingSuffix`, skip the `copy` when every target element already has the same backing as the managed string (`sameStringBacking`).
4. Add a woven `-race` regression test shaped like `TestFxRepeatedParse`, covering both admitted and sampled-out requests.

The original parse and body-read sequence stays untouched.
