# fx-hooks-panic-safety-F3: deferred HTTP callback panic masking

Verdict: the conditional panic-masking mechanism is real, but the Critical rating is not supported by ordinary default-config reachability.

Scope covered: HEAD `2e23b461`; `iast/net/http/orchestrion.yml`, Go 1.26.6 `net/http.Request.ParseForm`, `internal/taint/httpbridge/bridge.go`, `internal/taint/request/{scope,lazy}.go`, README/design intent, and woven reproductions.

## Verdict per finding

### hooks-panic-safety-F3: Deferred HTTP advice replaces the host's original panic

- Verdict: **CONFIRMED** (conditional).
- Original severity: Critical. Adjusted severity: **Medium**.
- The advice installs `defer` before native `Request.ParseForm` executes. During unwinding, it calls `httpbridge.Form`; that bridge directly invokes its atomic lazy callback without recovery. A second panic in that callback replaces the body's first panic under Go's normal defer/panic rules.
- Root cause: `iast/net/http/orchestrion.yml:131-158` defers the IAST form callback; `internal/taint/httpbridge/bridge.go:96-103` has no panic boundary around `callback.form`. The production callback is registered as `request.ManageForm` in `internal/taint/request/scope.go:138-145`.

## Reproduction

Finder control, reproduced in the private copy on Go 1.26.6:

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l \
  go tool orchestrion go test -timeout 10m -count=1 \
  -run TestFinder_DeferredSourceAdviceMustNotReplaceHostPanic ./iast/net/http -v
```

It failed as expected with `host panic replaced ... internal fault identical=true`; captured at `evidence/fx-hooks-panic-safety-F3/finder-go1.26.6.out.txt`.

Independent reproducer: copy `evidence/fx-hooks-panic-safety-F3/independent_deferred_panic_test.go` to `iast/net/http/zz_f3_independent_test.go` in an isolated copy, then run:

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l \
  go tool orchestrion go test -timeout 10m -count=1 \
  -run '^Test_RequestParseForm_preserves_body_panic_when_deferred_IAST_callback_fails$' \
  ./iast/net/http -v
```

The active-scope control retained the exact `Body.Read` panic pointer with the real registered callback. Re-registering only `Form` to panic made recovery observe `&{IAST deferred Form}` (`gotIAST=true`), not the customer pointer. See `evidence/fx-hooks-panic-safety-F3/independent-go1.26.6.out.txt`.

Go 1.27.0 could not build the woven package: generated `encoding/json` advice references removed `Decoder.r`/`Decoder.d` fields. This prevented an F3-specific Go 1.27 execution; capture: `evidence/fx-hooks-panic-safety-F3/go1.27.0-woven-build.out.txt`.

## Reachability

An ordinary program can make a `POST` `ParseForm` body reader panic, and the advice is woven into the supported stdlib path. However, the observed replacement additionally requires an IAST `Form` callback panic. Customers cannot register that internal bridge callback, and the actual `request.ManageForm` path was not shown to panic for any supported request input; the independent control proves it preserves the host panic under an active IAST scope. Thus the compound failure is **not reachable under default configuration from ordinary customer code** on current evidence.

Neither README nor `phase1/01-design-intent.md` documents this as an accepted limitation. The design intent explicitly requires preservation of application panics, so a real internal callback panic would still violate a product rule.

## Adjusted severity

**Medium:** this is a missing containment boundary for an unlikely internal failure, with a precise host-visible consequence; it is not a demonstrated customer-triggerable crash/behavior change and therefore does not meet the brief's Critical threshold.

## Minimal fix

Recover narrowly inside `httpbridge.Form` around `callback.form` and return the original `form`/`postForm` maps on recovery. Do not recover around `Request.ParseForm` or its body read: its panic must remain in flight untouched. Add a woven regression asserting exact host-panic identity after a deliberately panicking `Form` callback.
