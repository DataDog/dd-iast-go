# fx-sink-http-sources-F1: Header alias behavior

## Verdict per finding

**`sink-http-sources-F1`: CONFIRMED.** At HEAD
`2e23b4614320defd0d32177a69888dcab73f4d11`, woven request-entry instrumentation
replaces the header map and its value slices. Mutations then disappear from
caller-held aliases. Independent plain/woven tests reproduce both effects.
An additional directly called function reproduces the map failure without
relying on the `http.Handler` contract permitting request mutation.

Only F1 was assigned. The slice-alias failure is another consequence of the
same rebuilding operation, not a separate finding. F2 in the originating
report concerns a different mechanism and was not evaluated here.

## Reproduction

Evidence directory:
`.omo/review/evidence/fx-sink-http-sources-F1/`.

The independently authored `header_alias_test.go` and `direct_call_test.go`
belong in `reviewhttp/` in a private copy of HEAD. They use public HTTP APIs,
the public taint inspection API, and the woven-build indicator. They do not
call internal taint APIs or modify configuration globals. No production
source was changed.

Run from the private copy:

```sh
export GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6
export DD_IAST_ENABLED=true DD_IAST_REQUEST_SAMPLING=100
unset DD_IAST_MAX_CONCURRENT_REQUESTS
timeout 720s go test -timeout 10m -count=1 \
  -run '^TestHeader' -v ./reviewhttp
timeout 720s /usr/bin/time -l go tool orchestrion go test \
  -timeout 10m -count=1 -run '^TestHeader' -v ./reviewhttp
```

Captured Go 1.26.6 results:

| Case | Plain | Woven, 100% sampling |
|---|---|---|
| Empty initial header map | Pass | Pass |
| Eligible header map | Caller sees `"visible"` | Caller sees `""`; fail |
| Retained header value slice | Caller sees `"changed"` | Caller sees `"external-value"`; fail |
| Directly called mutation helper | Status 204, caller sees `"visible"` | Status 204, caller sees `""`; fail |

Key lines from `woven-go1.26.6.txt`:

```text
woven=true request_copied=true source_tainted=false handler="visible" caller="visible"
woven=true request_copied=true source_tainted=true handler="visible" caller=""
woven=true handler="changed" caller_slice="external-value"
--- FAIL: TestHeaderMapAliases
--- FAIL: TestHeaderValueSliceAliases
```

The direct-function pair is captured in `controls-go1.26.6.txt`:

```text
woven=false direct_function_status=204 caller="visible"
EXIT_CODE=0
woven=true direct_function_status=204 caller=""
EXIT_CODE=1
```

The initial plain and woven commands exited 0 and 1 respectively. The woven
failure is an assertion about missing mutations, not a compilation error.
The initial woven run reported 341,393,408 bytes maximum RSS, below 4 GiB.
Both test files passed language-server diagnostics and formatting inspection.

Additional controls, captured in `controls-go1.26.6.txt`:

```sh
DD_IAST_REQUEST_SAMPLING=0 timeout 600s /usr/bin/time -l \
  go tool orchestrion go test -timeout 8m -count=1 \
  -run '^TestHeader' -v ./reviewhttp
unset DD_IAST_ENABLED DD_IAST_REQUEST_SAMPLING DD_IAST_MAX_CONCURRENT_REQUESTS
timeout 600s /usr/bin/time -l go tool orchestrion go test \
  -timeout 8m -count=1 -run '^TestDefaultSamplingObservation$' -v ./reviewhttp
```

At 0% sampling, all three regression tests pass despite
`request_copied=true`. With the configuration overrides unset, the 64-request
observation reports:

```text
woven=true default_requests=64 source_tainted=13 alias_lost=13
```

The observation intentionally makes no probabilistic test assertion;
the 100% regression establishes deterministic failure.

Go 1.27.0 was also tried, with output in `go1.27.0.txt`:

```sh
export GOTOOLCHAIN=go1.27.0 DD_IAST_ENABLED=true DD_IAST_REQUEST_SAMPLING=100
timeout 600s go test -timeout 8m -count=1 -run '^TestHeader' -v ./reviewhttp
timeout 600s /usr/bin/time -l go tool orchestrion go test \
  -timeout 8m -count=1 -run '^TestHeader' -v ./reviewhttp
```

Plain Go 1.27.0 passed all three tests, exit 0. The woven build exited 1
before tests ran because existing JSON instrumentation refers to removed
decoder fields:

```text
# encoding/json
<generated>:2: dec.r undefined (type *Decoder has no field or method r)
<generated>:2: dec.d undefined (type *Decoder has no field or method d)
FAIL github.com/DataDog/dd-iast-go/reviewhttp [build failed]
```

Therefore runtime behavior on Go 1.27.0 is **not verified**; confirmation rests
on the explicitly supported Go 1.26.6. This separate compatibility blocker
was not repaired or added as another finding. Every measured woven command
was below 4 GiB maximum RSS.

## Reachability

**Reachable with default configuration.** `internal/config/config.go:72-74`
defaults to enabled, 30% sampling, and two concurrent analyses. One ordinary
nonempty eligible header is enough when sampled and admitted. The default
probe actually lost 13 of 64 mutations, matching its 13 tainted requests.
The reproducer uses 100% sampling only to make the regression deterministic.

The fallback matches root-application functions with exactly
`func(http.ResponseWriter, *http.Request)` and no results
(`iast/net/http/orchestrion.yml:81-97`). It does not require implementing
`http.Handler` or registering a server handler. Direct dispatch is explicitly
an intended source boundary.

Adversarial qualification: Go 1.26.6 `net/http/server.go:78-79` says handlers
should not modify the provided request. That weakens an unrestricted
server-handler mutation example, but does not govern an ordinary directly
called helper whose contract includes header mutation. The independent
`stampDispatchResult` helper proves that valid customer code is affected.
This report does not claim that every nested handler or every ordinary
network request loses mutations: an existing scope is reused, and the
replacement happens at the first instrumented boundary.

**Not a documented limitation.** README's mutable-byte provenance limitations
do not authorize changing header map or slice behavior. The design-intent
map explicitly requires preserving aliases. The parent plan at
`_docs/plans/taint-tracking-net-http-sqli-cmdi.md:502` does prescribe rebuilding
headers; it does not acknowledge or accept lost caller-visible mutations.
That recipe conflicts with the same plan's alias-preservation/drop rule at
lines 203-207 and product rule 1. It is a flawed implementation prescription,
not an accepted behavioral limitation.

## Adjusted severity

**Critical, unchanged:** default-enabled instrumentation changes the
observable side effect of valid customer code and its `http.Header.Set`
operation, meeting the brief's explicit host-behavior severity criterion.
No crash, exploit, or universal HTTP-server impact is claimed.

## Root cause (file:line)

1. `iast/net/http/orchestrion.yml:106-119` creates a scope, shallow-copies the
   request with `WithContext`, then assigns `EagerHTTP`'s result to `Header`.
   Go's `WithContext` itself preserves the original header map alias.
2. `internal/taint/request/http.go:65-78` selects an active analysis and calls
   `taintHeaders`. Its bounds are 32 header names and 64 values
   (`http.go:51-54,97-106`). Successful tainting sets `changed`.
3. `internal/taint/request/http.go:144-155` allocates a new map and new
   non-nil value slices. The advice installs these only in the request copy;
   the caller's map and slice aliases still refer to the old containers.
4. `iast/net/http/orchestrion.yml:35-44` uses the same assignment at the
   server boundary. The directly reproduced customer-visible divergence
   occurs at the fallback boundary.

The empty-header control already disproves context cloning alone as the
cause: `request_copied=true` still preserves the mutation when rebuilding
does not happen.

## Minimal fix

Do not replace caller-owned header maps or value slices at fallback entry.
Preserving just the map is insufficient: the independent slice test would
still fail. The immediate safe containment is to leave these containers
untouched and drop eager header provenance where exclusive ownership cannot
be established. Restore that coverage through audited source-extraction hooks
that return managed strings, or an ownership-proven entry path.

An in-place rewrite is not automatically safe: it must preserve both alias
levels and must not introduce writes racing with otherwise valid shared
readers. Do not taint original interned string backing as a shortcut. Keep
the paired map, slice, and direct-function tests as regression coverage.
No fix was applied as part of this verification.
