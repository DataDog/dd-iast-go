# Plan: support otelc as an alternative to orchestrion

Status: draft, revised after critic review (research done, no prototype yet).

## 1. Goal

Applications must be able to build with dd-iast-go using **otelc**
(`go.opentelemetry.io/otelc`, the OpenTelemetry Go compile-time instrumentation
tool) instead of **orchestrion**. Both tools stay supported until orchestrion is
deprecated. The detections must give the same results with both tools.

Out of scope: new detections, new taint sources, removal of orchestrion.

## 2. Facts from research

Labels: **[V]** = verified in source or docs. **[I]** = inferred, prototype must
confirm.

### 2.1 What dd-iast-go uses today

- [V] 4 `orchestrion.yml` files, **14 aspects** in total:
  - `internal/spans/orchestrion.yml`: 1 aspect on `(*tracer.Span).Finish`
    (`tracer-internal: true`).
  - `iast/crypto/hash/orchestrion.yml`: 5 aspects (md4.New, md5.New, md5.Sum,
    sha1.New, sha1.Sum).
  - `iast/crypto/cipher/orchestrion.yml`: 8 aspects (des x2, rc4, blowfish x2,
    rc2, pkcs12 x2).
  - `taint/orchestrion.yml`: `aspects: []` (placeholder).
- [V] Only 2 advice kinds are in use:
  - `prepend-statements` (14 aspects): one report call at the start of the
    function body.
  - `inject-declarations` (9 aspects): a body-less `//go:linkname` function
    declaration (pull from the dd-iast-go package), plus an `init()` that
    increments `telemetry.InstrumentedSink[...]`, plus `links:`.
- [V] Only 1 join point kind: `function-body` (by name, with an optional
  receiver), combined with `import-path`.
- [V] The only orchestrion runtime use is `built.WithOrchestrion` in tests
  (`iast/crypto/{hash,cipher}/*_test.go`, `benchmarks/overhead`).
- [V] `internal/vulnerability/stacktrace/stacktrace.go:81-88`
  (`IsGeneratedFile`) skips `<generated>` frames.
- [V] CI: `.github/workflows/ci.yml:76` runs `go tool orchestrion go test`.
  `.github/workflows/system-tests.yml` builds the `net-http-orchestrion`
  weblog and pins orchestrion from `go.mod`. The benchmark runner
  (`benchmarks/overhead/runner/main.go:471`) builds with orchestrion.

### 2.2 What otelc gives

- [V] Stable since v1.0.0. Latest release **v1.2.0** (2026-10-12). Needs Go
  1.26 to build the tool. dd-iast-go is on Go 1.26.6.
- [V] Same discovery model as orchestrion: a `//go:build tools` file
  (`otel.instrumentation.go`) with blank imports. Each imported package holds an
  `otelc.yml`/`otelc.yaml` rule file. A module can ship its own tool file to
  make a bundle (`docs/external-configuration.md`).
- [V] An imported package with no rule file and no tool file is an **error**.
- [V] When a tool file exists, the embedded OTel bundle is **not** applied.
- [V] Rule modifiers that we need:
  - `inject_code`: raw Go statements at the start of a function body. Template
    fields: `.Receiver`, `.FuncArgument N`. `imports:` is per rule.
  - `add_file`: copy one Go file from package `path` into the target package.
    No selectors. dd-trace-go uses it with a `//go:build ignore` file that holds
    `//go:linkname` declarations (`ddtrace/tracer/gls_accessors.go`).
  - `assign_value`: replace a package-level `var` initializer (dd-trace-go
    uses it for its `enabled` flag).
  - `inject_hooks`: `before`/`after` hook functions. Each call allocates a
    `HookContext`, boxes the arguments, and adds a `defer`. Too slow for hot
    paths.
- [V] `where.func` without `recv` matches only free functions
  (`tool/internal/ast/shared.go:82-116`). This is the same as orchestrion's
  `receiver: false`.
- [V] otelc writes an `otelc.runtime.go` file into **every requested build
  package** (not only `main`). This file blank-imports every `inject_hooks.path`
  and every `add_file.path` package, except the package itself
  (`tool/internal/setup/setup.go:273-290`, `tool/internal/setup/add.go:150-192`).
  Consequences:
  - these source packages must not be `internal/` (a customer package cannot
    import them);
  - `otelc go test ./...` **inside dd-iast-go** makes import cycles: for example
    `internal/vulnerability` gets a blank import of `iast/crypto/hash`, and
    `iast/crypto/hash` imports `internal/vulnerability`.
  - Rule-only packages (only `inject_code`/`assign_value`) are not imported.
- [V] `add_file` rules ignore `where` and apply when the target package (and
  `version:` range) matches (`tool/internal/setup/match.go:120-139`). An
  `inject_code` rule applies only when the function exists.
- [V] `otelc pin --validate` is not a quality gate: it prunes by default
  (`tool/cmd/otelc/command.go:43-60`), and it warns but returns success for
  invalid rules (`tool/internal/setup/pin.go:522-555`).
- [V] No inline equivalent of `inject-declarations`. `add_file` is the
  replacement.
- [V] No tool reads `orchestrion.yml`. All rules must be rewritten.

### 2.3 What dd-trace-go gives

- [V] dd-trace-go `main` has otelc support (PR #5117 core, GLS, tracer start;
  #5425 net/http; #5434 database/sql; #5145 chi; #5123 redigo). It ships
  `otelc/all` (module `github.com/DataDog/dd-trace-go/otelc/all/v2`).
- [V] **No release contains it.** v2.11.1 (2026-10-08) does not. dd-iast-go
  pins v2.11.0-rc.1.
- [V] dd-trace-go also puts an `inject_code` on `(*Span).Finish`
  (`span_gls_finish`). dd-iast-go will add a second one on the same function.

## 3. Design

### 3.1 Pattern for every sink aspect: `add_file` + `inject_code`

We do not use `inject_hooks`, because of its per-call cost (rule "NEVER slow
down the host application"). Instead, each orchestrion aspect becomes:

1. One `add_file` rule per **target package**. It copies a small
   `//go:build ignore` file that holds only:
   - the `//go:linkname` body-less declaration (same as today);
   - `import _ "unsafe"` and the stdlib imports that the signature needs.
2. One `inject_code` rule per **target function**, with the same statement as
   today's `prepend-statements`.

This also removes the "anchor the declaration on exactly one function"
workaround (`iast/crypto/hash/orchestrion.yml:41-49`), because `add_file` is
per package.

**Sink-count telemetry (`telemetry.InstrumentedSink`).** Today the injected
`init()` imports `internal/instrumentation/telemetry` and writes into a map.
The Go import edge makes the telemetry package initialize first. Under otelc
we cannot keep this, and a linkname call does **not** add an init-order edge:
an injected `init()` in `crypto/md5` can run before the telemetry map exists,
and a write to a nil map panics. Design rules:

1. Injected code imports only the stdlib and `unsafe`.
2. Injected code never writes to a value that needs run-time initialization.
   Use a statically allocated counter (for example a fixed-size
   `[VulnerabilityTypeCount]uint32` array, zero at load time), reached by
   `//go:linkname`. The telemetry package reads it when it sends metrics.
3. The count must match the functions that were really instrumented.
   `add_file` applies even when a target function is missing (2.2). So the
   count must come from the `inject_code` side or be guarded with `version:`
   ranges, and a test must cover a missing-function case.

The prototype (phase 1) must show: no panic at startup, and exact counts, with
both tools.

Example (hash, crypto/md5):

```yaml
# iast/crypto/hash/otelc.yml
version: "v1.2.0"

md5_declarations:
  target: crypto/md5
  do:
    - add_file:
        file: otelc_decl_md5.go     # //go:build ignore; linkname decls only
        path: github.com/DataDog/dd-iast-go/iast/crypto/hash

md5_new:
  target: crypto/md5
  where: { func: New }
  do:
    - inject_code: { raw: "__dd__iast_ReportWeakHash__(nil, crypto.MD5)" }
  imports: { crypto: crypto }

md5_sum:
  target: crypto/md5
  where: { func: Sum }               # no recv => free function only [V]
  do:
    - inject_code: { raw: "__dd__iast_ReportWeakHash__(nil, crypto.MD5)" }
  imports: { crypto: crypto }
```

Open design choice (decide in the prototype): where the sink count comes from.
Option 1: one declaration file per target package (8 files) with an `init()`
that adds the count to the static counter (rule 2), plus `version:` guards.
Option 2: no count in the target package; the IAST package computes the count
from a list of expected sinks. Option 1 is closer to today, option 2 is safer.

### 3.2 Porting map (14 aspects)

| Orchestrion aspect | otelc rules | Notes |
|---|---|---|
| `internal/spans`: `(*tracer.Span).Finish` | `add_file` into `ddtrace/tracer` + `inject_code` (`func: Finish`, `recv: "*Span"`, `{{ .Receiver }}`) | The `add_file` source package must be public (see 3.3). Order versus dd-trace-go `span_gls_finish` is not defined (otelc #583). |
| hash: md4.New, md5.New, sha1.New | `add_file` + `inject_code` | Direct. |
| hash: md5.Sum, sha1.Sum | `inject_code`, `func: Sum`, no `recv` | Declaration comes from the package `add_file`. |
| cipher: des.NewCipher, des.NewTripleDESCipher | `add_file` + 2x `inject_code` | Direct. |
| cipher: rc4.NewCipher | `add_file` + `inject_code` | Direct. |
| cipher: blowfish.NewCipher, NewSaltedCipher | `add_file` + 2x `inject_code` | Replace the literal `salt` with `{{ .FuncArgument 1 }}`. |
| cipher: pkcs12/internal/rc2.New | `add_file` + `inject_code` | Target is an `internal` package of x/crypto: allowed as a `target` [V]. |
| cipher: pkcs12 `create` x2 | `add_file` + 2x `inject_code` with `recv: shaWithTripleDESCBC` / `shaWith40BitRC2CBC` | Unexported value receivers. Receiver match is exact type text [V]; the names exist in x/crypto v0.58.0 (`pkcs12/crypto.go:35,49`). |
| `taint`: `aspects: []` | none | Do not import `taint` in the otelc tool file (error: no rule file). |

### 3.3 Package layout and wiring

- Rule files: `otelc.yml` next to each `orchestrion.yml` (same package).
- `add_file` source packages are imported into every requested build package
  (2.2). So they must be **public**, and their imports must not reach back into
  the packages that are built.
- The `add_file` source for `Span.Finish` cannot be in `internal/spans`.
  Move the linkname target to a small public package, for example
  `github.com/DataDog/dd-iast-go/instrumentation/spans`, that forwards to
  `internal/spans.Finished`.
- Root tool file `otel.instrumentation.go` (`//go:build tools`, package
  `ddiast`), next to `orchestrion.tool.go`. It blank-imports
  `iast/crypto/hash`, `iast/crypto/cipher`, the spans package, and
  `github.com/DataDog/dd-trace-go/v2/ddtrace/tracer` (tracer start + GLS rules).
  Do not import `taint` (no rule file: error).
- [V] A tools-only root package works with otelc discovery
  (`tool/internal/setup/config.go:84-131`).
- User setup (README):

  ```go
  //go:build tools
  package tools

  import (
      _ "github.com/DataDog/dd-iast-go"               // IAST rules
      _ "github.com/DataDog/dd-trace-go/otelc/all/v2" // tracer + integrations
  )
  ```

  Then `go tool otelc go build ./...`.
- Update docs that say "orchestrion only": `README.md:11`, `AGENTS.md`,
  `iast/AGENTS.md`, `CONTRIBUTING.md:60-137`.

### 3.4 Tool-neutral runtime changes

1. **"Is the build instrumented?" flag.** Replace `built.WithOrchestrion` in
   tests with an internal flag, for example `internal/build.Instrumented`:
   - orchestrion: `//orchestrion:enabled` on the variable;
   - otelc: an `assign_value` rule (same as dd-trace-go `enable_otelc_flag`).
   - Also expose which tool built the binary, for telemetry (optional).
2. **Sink location and stack traces.** otelc puts `inject_code` statements in
   the original body (`tool/internal/instrument/apply_raw.go:146-189`). Only the
   `inject_hooks` trampoline gets `//line <generated>:1`
   (`apply_func.go:220`). Today IAST skips `<generated>` frames and uses
   `skipFrames=2` (`internal/vulnerability/stacktrace/stacktrace.go:81-88`,
   `internal/vulnerability/report.go:64-75,152-154`). Under otelc, a crypto
   library frame can become the reported location. The prototype must compare
   path, line, and method of the location (md5.Sum, salted blowfish) and both
   stack-trace modes, with both tools. Possible fix: our injected code adds its
   own `//line <generated>:1` marker, if otelc keeps comments in `raw` [I].

### 3.5 Tests and CI

1. `go.mod`: add `go.opentelemetry.io/otelc` to the `tool` block (pin v1.2.0
   or later). Check that its dependencies do not force bad upgrades on
   consumers (both tools then sit in the `require` graph).
2. **Do not run `otelc go test ./...` on the root module.** It makes import
   cycles (2.2), and it writes `otelc.runtime.go` files into the source tree.
   Instead, add a **separate test module**, for example `_integration/otelc/`
   with its own `go.mod` and a `replace` to `../..`. It holds a customer-style
   app and end-to-end tests: each sink reports once, at the correct location,
   with the correct sink counts. Run the same tests with orchestrion, so the
   two tools are compared on the same code.
3. Unit tests of the root module stay on `go tool orchestrion go test` (and
   plain `go test`) until orchestrion is removed.
4. `ci.yml`: add a job (or matrix `tool: [orchestrion, otelc]`) for the
   integration module. The quality gate is this functional test, **not**
   `otelc pin --validate` (it prunes and passes on invalid rules, 2.2). Also
   assert that `.otelc-build/matched.json` lists every expected rule.
5. Benchmarks: `benchmarks/overhead` is a separate module
   (`benchmarks/overhead/go.mod`). It needs its own `otel.instrumentation.go`,
   an otelc tool dependency, and a pinned `dd-trace-go/otelc/all` /
   `contrib/net/http` version. `runner/main.go:471` must build with either
   tool. Set an explicit overhead limit for otelc versus orchestrion
   (for example: not more than orchestrion + 5%).
6. System tests: need a `net-http-otelc` weblog in `DataDog/system-tests`
   (none exists today; see 5.2). Then add a `tool` matrix to
   `system-tests.yml` and pin the otelc version from `go.mod`.
7. `LICENSE-3rdparty.csv`: add otelc.

## 4. Phases and estimates

Estimates are for one engineer, with an agent, after this plan is approved.

| # | Phase | Output | Estimate |
|---|---|---|---|
| 1 | Prototype: md5 only, in the new `_integration/otelc` module. Cover linkname, sink counts, startup with no panic, location accuracy | One passing end-to-end test with each tool; answers every [I] item | 1 day |
| 2 | Port all hash + cipher rules; tool-neutral test flag | Integration tests pass with both tools | 1 day |
| 3 | Port `Span.Finish` (public spans package); bump dd-trace-go to a `main` pseudo-version | Span tests pass with both tools | 0.5 to 1 day |
| 4 | CI job, matched-rule assertion, docs, licenses | Green CI for both tools | 0.5 day |
| 5 | Benchmarks for otelc | Overhead numbers side by side, under the limit | 1 day |
| 6 | System tests (blocked by 5.2) | `system-tests.yml` with otelc | 1 day after the weblog exists |

Phases 1 to 4: about 3 to 3.5 days. Phase 1 can change the design: if the
linkname pattern fails, stop and re-plan before phase 2.

## 5. Gaps outside dd-iast-go (for Romain)

### 5.1 dd-trace-go

1. **Release with otelc support.** #5117 and the integrations are on `main`
   only. dd-iast-go must depend on a release that contains `otelc/all` and
   `ddtrace/tracer/otelc.yaml`. Until then, pin a `main` pseudo-version.
2. **Tracer starts at the top of `main`, not in `init()`.** The otelc rule
   `create_tracer` (`ddtrace/tracer/otelc.yaml:169-193` on `main`) says spans
   from package `init()` are lost. Orchestrion starts the tracer in `init()`.
   An IAST sink hit during `init()` (for example `md5.New` in a package var)
   gives a different result. Blocked upstream by otelc #1347 / #1348.
   **Decision (Romain): not an issue.** Untrusted data is not expected during
   `init()`. No action.
3. **Rule ordering on `(*Span).Finish`.** dd-trace-go `span_gls_finish` and the
   dd-iast-go rule both inject at the start of `Finish`. The order is not
   defined (otelc #583). Ask dd-trace-go to confirm that the order is not
   important, or to give a stable extension point (for example, a public
   "on span finish" callback that dd-iast-go can use without compile-time
   rules). The callback also removes the need for our `Span.Finish` rule.
4. **Tool detection is internal.** `internal/orchestrion.Enabled()` stays false
   under otelc. The otelc flag (`internal/otelc.Enabled()`) is internal.
   - Telemetry (`ddtrace/tracer/telemetry.go:59,97,122`) reports only
     `orchestrion_enabled`. otelc builds are not visible.
   - AppSec RASP LFI/CMDi capabilities are registered only when
     `orchestrion.Enabled()` (`internal/appsec/remoteconfig.go:389`).
5. **Stack-trace filter.** `internal/stacktrace/stacktrace.go:25-26` filters
   only orchestrion frames. Add otelc frames (`<generated>`, trampoline). This
   affects IAST evidence stacks, which use `instrumentation.CaptureStackTrace`.
6. **Missing otelc integrations** (needed later for IAST taint sources): gin,
   echo, gorilla/mux, fiber, fasthttp, gqlgen (#5142), grpc (#5144), and
   `contrib/os` (LFI/CMDi). Also issue #5514 (racy `Server.Handler` write in the
   net/http `Serve` rule, both tools).

### 5.2 system-tests

1. No otelc Go weblog exists (`utils/build/docker/golang/` has
   `net-http-orchestrion.Dockerfile` and `install_orchestrion.sh` only). Need a
   `net-http-otelc` weblog and an `install_otelc.sh`.

### 5.3 otelc upstream (watch)

1. #1347 / #1348: `add_file` ignores `where` and breaks test mains. This
   blocks tracer start in `init()` (5.1 item 2). It also makes sink counts
   less precise (3.1).
2. #583: no explicit order for several rules on one function.
3. `otelc go test ./...` on a module that holds its own `add_file` sources
   makes import cycles. Ask upstream for a way to skip `otelc.runtime.go` for
   packages in the rule module (or to link without an import).
4. `otelc pin --validate` passes on invalid rules. Ask for a strict mode.
5. #469 (no `//orchestrion:ignore`), #671 (`-toolexec` drop-in through
   `GOFLAGS` reported broken; use `otelc go ...`), and #164 (feature parity:
   future taint propagation needs call-site rewriting of expressions;
   `wrap_call` handles only function calls).

## 6. Risks

| Risk | Effect | Mitigation |
|---|---|---|
| `add_file` + pull `//go:linkname` into stdlib fails with otelc | Pattern 3.1 fails | Phase 1 tests this first. Fallback: `inject_hooks` (slower), measured in phase 5. |
| Init-order panic from injected `init()` | Host application crashes at startup | Rule 3.1.2 (static counters only); startup test in phase 1. |
| Wrong sink counts | Wrong telemetry | Rule 3.1.3; missing-function test. |
| Wrong reported location | Wrong vulnerability location / dedup | Phase 1 location test; 3.4 item 2. |
| dd-trace-go `main` pin before a release | Unstable dependency | Keep orchestrion CI as the main signal until a release. |
| Two tools in `go.mod` `tool` block | Larger dependency graph for consumers | Check `go mod graph` in phase 4. |
| Rule drift between `orchestrion.yml` and `otelc.yml` | One tool misses a sink | Same integration tests run with both tools. |
