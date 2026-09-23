# Independent verification journal

Target: HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.
The cited source files match that revision. Both Go 1.26.6 and Go 1.27.0
are installed.

## Hypotheses

1. Eager header rebuilding breaks map and value-slice aliases. Distinguish by
   running the same public HTTP handler test plain and woven, with nonempty
   and empty initial headers.
2. The finder relied on an artificial test-only configuration. Distinguish
   by using environment configuration, then observing ordinary default
   sampling without changing globals or calling internal APIs.
3. Context cloning alone explains the result. Distinguish by a woven
   sampled-out run: it still clones the request but does not rebuild headers.

## Artifacts

- Private copy: `/tmp/ddiast-review/wt/fx-sink-http-sources-F1/`.
  Remove after retaining reproducer and output here.
- Independent public-surface reproducer:
  `reviewhttp/header_alias_test.go` in the private copy.
- Independent direct-call counterexample:
  `reviewhttp/direct_call_test.go`, also retained here. It tests an ordinary
  function with an explicit request-mutation contract, not `http.Handler`.
- Command output will be captured under this evidence directory.
- No production source edits or changes to the main checkout outside the
  assigned review artifacts.

## Observations

- Plain Go 1.26.6: both map and slice alias tests pass.
- Woven Go 1.26.6 with 100% sampling:
  `request_copied=true source_tainted=true handler="visible" caller=""`.
- Woven empty-header control:
  `request_copied=true source_tainted=false handler="visible" caller="visible"`.
- Woven slice test:
  `handler="changed" caller_slice="external-value"`.
- Initial woven run exits 1, with maximum resident set size 341,393,408 bytes.
- Reproducer directory has no language-server diagnostics; `gofmt -l` is empty.
- Direct helper, plain Go 1.26.6:
  `woven=false direct_function_status=204 caller="visible"`, exit 0.
- Direct helper, woven Go 1.26.6:
  `woven=true direct_function_status=204 caller=""`, exit 1.
- Woven 0% sampling: all map, slice, and direct-helper regressions pass;
  `request_copied=true` still holds, so context copying alone is not the cause.
- Default-configuration observation:
  `woven=true default_requests=64 source_tainted=13 alias_lost=13`.
  No configuration globals or internal APIs were changed by the tests.
- Go 1.27.0 plain: all three regressions pass, exit 0.
- Go 1.27.0 woven: build exits 1 before tests run because `encoding/json`
  instrumentation refers to undefined decoder fields `dec.r` and `dec.d`.
  Runtime header-alias behavior on Go 1.27.0 is not established by this run.
- All monitored commands exited before cleanup. All woven runs were below
  4 GiB maximum RSS.
- The two archived reproducer files compare byte-for-byte equal to the
  executed private-copy files.

## Contract counterargument

Go 1.26.6 `net/http/server.go:78-79` discourages `http.Handler` implementations
from modifying the provided request. This constrains a server-only impact claim,
but `application.http.Handler` matches function signatures without checking
whether the function implements or is registered as an HTTP handler. The
direct-call counterexample tests that separate, legal customer-code surface.

The parent plan at
`_docs/plans/taint-tracking-net-http-sqli-cmdi.md:502` explicitly prescribes
rebuilding headers. It does not document or accept loss of caller-visible
mutations. The same plan at lines 203-207 requires dropping tracking where
cloning changes alias semantics.
