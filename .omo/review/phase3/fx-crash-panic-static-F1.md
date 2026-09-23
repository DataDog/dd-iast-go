# fx-crash-panic-static-F1: independent verification of the weak-crypto init-order panic

## Verdict per finding

**crash-panic-static-F1 — CONFIRMED** (Critical, crash). The claimed mechanism is real at HEAD
2e23b46, I reproduced the process-killing panic under the default configuration with **my own**
reproducer (different hook surface than the finder: `sha1.New()` inside an application package
`init()`), and the finder's unmodified reproducer reproduces in my private copy as well. One
nuance the finder did not spell out fully: the crash is *layout-dependent* — I also built a
non-crashing control layout where the hook fires **before** `internal/config` initializes, so
`config.Enabled` is still `false` and the gate saves the process. That control run confirms the
claimed window (`internal/config` init → `internal/spans`/tracer init) precisely.

## Mechanism check at HEAD 2e23b46

- `iast/crypto/hash/orchestrion.yml` injects `//go:linkname __dd__iast_ReportWeakHash__ .../hash.ReportWeakHash`
  plus `prepend-statements` into `crypto/md5.{New,Sum}`, `crypto/sha1.{New,Sum}`, `golang.org/x/crypto/md4.New`.
  `iast/crypto/cipher/orchestrion.yml` has the same shape for `crypto/des` (DES, 3DES), `crypto/rc4` (and the rest of that file).
  The woven stdlib package gets only a **link** dependency, not an import: its init graph contains
  `internal/instrumentation/telemetry` and `internal/model/constants`, but **not** `vulnerability`,
  `spans`, or dd-trace-go's tracer. Go's init-order guarantees therefore do not cover the call.
- `internal/vulnerability/report.go:37` gates only on `config.Enabled`, which defaults to **true**
  (`internal/config/config.go:72`, `loader.BoolFromEnv(observer, EnvVarEnabled, true)`), so a default
  deployment passes the gate.
- With a nil ctx, `tracer.SpanFromContext` misses, so `report.go:47` calls
  `spans.NewOrphanVulnerabilitySpan()` (`internal/spans/vulnerability.go:18`) → `tracer.StartSpan`
  → `internal.GetGlobalTracer[Tracer]()` → `*globalTracer.Load().(*T)` panics with
  `interface conversion: interface {} is nil, not *tracer.Tracer` (dd-trace-go
  `ddtrace/internal/globaltracer.go:43`) because dd-trace-go's tracer `init()` (which installs the
  NoopTracer) has not run yet. Nothing on this path recovers; the process dies during package init,
  before `main`. (Secondary window claimed by the finder — nil `spans` globals — is real per
  `annotation.go:29-31` but I did not hit it; the tracer assertion fires first in every observed run.)

## Reproduction (my own; commands + key output)

Sources: `.omo/review/evidence/fx-crash-panic-static-F1/initcrash2/` (module `github.com/zzz/initcrash2`;
`fp/fp.go` is an ordinary application package that compiles a validation regexp and computes a
SHA-1 fingerprint in `init()`).

```
cd <copy>/_repro/initcrash2 && GOFLAGS='-p=4 -mod=mod' GOTOOLCHAIN=go1.26.6 GOPROXY=off \
  /usr/bin/time -l go tool orchestrion go build -o initcrash2 . && ./initcrash2
EXIT=2
panic: interface conversion: interface {} is nil, not *tracer.Tracer
  ...tracer.StartSpan ... tracer.go:468
  ...internal/spans.NewOrphanVulnerabilitySpan() vulnerability.go:18
  ...internal/vulnerability.Report ... report.go:47
  ...iast/crypto/hash.ReportWeakHash ... hash.go:19
  crypto/sha1.New() <generated>:2
  github.com/zzz/initcrash2/fp.init.0() fp/fp.go:16
```
- `DD_IAST_ENABLED=false ./initcrash2` → `EXIT=0` (gate escape hatch).
- `GODEBUG=inittrace=1`: `init .../internal/config @53 ms`, `.../internal/taint/request`, `.../iast/encoding/json`,
  then the panic; **`ddtrace/tracer` and `internal/spans` never initialize**.
- Control layout (`.omo/review/evidence/fx-crash-panic-static-F1/initcrash-v1-nocrash.out.txt`):
  a hashing package with only `crypto/sha1`+`encoding/hex` deps initialized at 3.6 ms, **before**
  `internal/config` (47 ms) → hook fired but `config.Enabled==false` → no crash. The window is real
  and both of its boundaries are observable.
- Finder's unmodified repro rerun in my copy: `EXIT=2`, same panic, in `hasher.init()` via `crypto/md5.Sum`
  (`finder-repro-rerun.out.txt`).
- Build facts: go1.26.6, peak RSS 438 MB (well under the 4 GB build-memory finding threshold).

## Reachability

Default configuration (`DD_IAST_ENABLED` unset → true), supported toolchain go1.26.6, standard woven
build (`go tool orchestrion go build`). Trigger: any package of the customer's application — or of a
**transitive third-party dependency** — that calls `md5.Sum`/`md5.New`/`sha1.New`/`sha1.Sum`/`md4.New`
or `des`/`rc4` constructors in a var initializer or `init()`, provided that package's init task lands
between `internal/config` and tracer/`spans` initialization. That placement is common (my crashing
layout is a textbook "compile a validation regexp, compute a digest constant" package) but not
guaranteed for every layout (my control layout escaped via the gate). Not a documented limitation:
neither the README nor `.omo/review/phase1/01-design-intent.md` mentions init-time hooks or a
startup-crash restriction; it directly violates product rule #1 (never break the host application).

## Adjusted severity

**Critical** (unchanged). Process-killing panic reachable from ordinary customer code under default
configuration and the supported toolchain, before `main` even starts; escape hatch exists
(`DD_IAST_ENABLED=false`) but requires the operator to already know about the bug.

## Root cause (file:line)

`iast/crypto/hash/orchestrion.yml` (linkname declaration + `prepend-statements` advice;
same root cause in `iast/crypto/cipher/orchestrion.yml`): reporting code is invoked through
`go:linkname` from woven stdlib bodies whose init graph never imports `vulnerability`/`spans`/tracer.
Panic sites reached: `internal/vulnerability/report.go:47`, `internal/spans/vulnerability.go:18`;
the failing assertion itself is dd-trace-go `ddtrace/internal/globaltracer.go:43` (upstream code,
triggered by the init-order violation, not a dd-trace-go bug). The hash and cipher hooks share this
**one** root cause; phase-2 findings F2 (missing recover boundaries) and F3 (latent lock leak on
recovered panics) are related but distinct root causes, not duplicates of F1.

## Minimal fix

Route both weak-crypto report entry points through an initialization-safe guard instead of a bare
linkname call into reporting code:
- In `iast/crypto/hash` and `iast/crypto/cipher`, add `var ready atomic.Bool` set at the end of each
  package's `init()`; check it first in `ReportWeakHash`/`ReportWeakCipher` (those packages import
  `vulnerability` → `spans` → tracer, so their own init only completes after every dependency has
  initialized). Before the flag is set the call is a no-op.
- Additionally wrap the report body in `defer func(){ _ = recover() }()` as the SQL/command
  bridges do, so any future pre-init path cannot kill the host.
- Add a woven regression test with an init-time `md5.Sum` (and one des/rc4 init case) that asserts
  the binary starts and exits 0.
