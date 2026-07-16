# Plan: Weak Cipher Detection

## Status

- **Phase:** design review.
- **Goal:** report `WEAK_CIPHER` vulnerabilities when supported Go or
  `golang.org/x/crypto` weak-cipher implementations are constructed or selected.
- **Reference implementation:** `iast/crypto/hash`.
- **Confirmed scope:** all constructors for DES/TripleDES, Blowfish/salted
  Blowfish, and RC4; internal RC2 and PKCS#12 PBE implementations; every
  overlapping sink invocation reports through the existing event capacity and
  deduplication policies.

## Decisions Confirmed with the User

1. Extract weak-hash/weak-cipher reporting commonalities into
   `internal/vulnerability/report.go`.
2. Instrument all public constructors in each supported family, including
   TripleDES and salted Blowfish.
3. Instrument x/crypto's internal RC2 and PBE implementations even though they
   have no public constructors of their own.
4. Use source-backed evidence labels:
   - `DES`
   - `TripleDES`
   - `RC4`
   - `Blowfish`
   - `RC2`
   - `PBEWithSHAAnd3KeyTripleDESCBC`
   - `PBEWithSHAAnd40BitRC2CBC`
5. When one operation selects multiple weak algorithms, invoke reporting for
   every applicable sink. PKCS#12 using the RC2 PBE implementation reports
   `PBEWithSHAAnd40BitRC2CBC` and `RC2`; the TripleDES implementation reports
   `PBEWithSHAAnd3KeyTripleDESCBC` and `TripleDES`. Existing event capacity and
   location-based deduplication still determine which findings are retained.

## Evidence Naming and Provenance

Evidence uses the algorithm spelling exposed by the relevant Go package or,
where no public API exists, by x/crypto's concrete internal implementation:

| Evidence | Source for the spelling |
|---|---|
| `DES` | `crypto/des` package documentation names the Data Encryption Standard as `DES`. |
| `TripleDES` | The public constructor is `crypto/des.NewTripleDESCipher`; the stdlib concrete type, errors, examples, and tests use the same `TripleDES` spelling. |
| `RC4` | The import path is `crypto/rc4`, its package documentation says it implements `RC4`, and its public `Cipher` documentation calls it an instance of `RC4`. Go exports no `ARCFOUR` symbol or constant. |
| `Blowfish` | `golang.org/x/crypto/blowfish` package and public API documentation consistently call the algorithm `Blowfish`. |
| `RC2` | `golang.org/x/crypto/pkcs12/internal/rc2` is internal, but its package documentation explicitly calls the implementation the `RC2` cipher. |
| `PBEWithSHAAnd3KeyTripleDESCBC` | x/crypto has no public PBE constructor. This label is the concrete internal identifier `oidPBEWithSHAAnd3KeyTripleDESCBC` from `pkcs12/crypto.go`, with only the implementation-detail `oid` prefix removed. |
| `PBEWithSHAAnd40BitRC2CBC` | Likewise derived from the concrete internal identifier `oidPBEWithSHAAnd40BitRC2CBC` in `pkcs12/crypto.go`. |

The earlier `ARCFOUR` proposal is intentionally rejected: although ARCFOUR is
an alias for RC4 in some ecosystems, it is not the name presented by Go's
`crypto/rc4` API.

## Supported API Matrix

| Evidence | Package | Instrumentation point | Count |
|---|---|---|---:|
| `DES` | `crypto/des` | `NewCipher` body | 1 |
| `TripleDES` | `crypto/des` | `NewTripleDESCipher` body | 1 |
| `RC4` | `crypto/rc4` | `NewCipher` body | 1 |
| `Blowfish` | `golang.org/x/crypto/blowfish` | `NewCipher` and `NewSaltedCipher` bodies | 2 |
| `RC2` | `golang.org/x/crypto/pkcs12/internal/rc2` | `New` body | 1 |
| `PBEWithSHAAnd3KeyTripleDESCBC` | `golang.org/x/crypto/pkcs12` | `shaWithTripleDESCBC.create` body | 1 |
| `PBEWithSHAAnd40BitRC2CBC` | `golang.org/x/crypto/pkcs12` | `shaWith40BitRC2CBC.create` body | 1 |

The instrumented-sink telemetry count is therefore eight call sites when every
relevant package is linked into the application. This static count is distinct
from executed-sink telemetry: one supported PKCS#12 PBE selection executes two
sinks (its concrete PBE algorithm plus the underlying `RC2` or `TripleDES`).

PBE is instrumented at the two concrete `pbeCipher.create` methods rather than
at `pbDecrypterFor` entry. Those methods are reached only after PKCS#12 has
recognized one of its supported weak PBE algorithms and validated its
parameters, avoiding a PBE finding for unsupported algorithm identifiers.
Their calls into TripleDES or RC2 naturally generate the requested overlapping
underlying-cipher finding.

## Shared Vulnerability Reporter

Create `internal/vulnerability/report.go` and move the generic reporting path
out of `iast/crypto/hash.ReportWeakHash`:

1. Return immediately when IAST is disabled.
2. Normalize a nil context to `context.Background()`.
3. Find the active trace span or create and finish an orphan vulnerability
   span.
4. obtain its IAST annotation and honor request sampling.
5. Increment the supplied executed-sink telemetry counter.
6. Capture the source location while accounting for the new thin-wrapper stack
   frame and an optional, exact immediate-caller frame to skip.
7. Add a vulnerability with the supplied type and evidence.
8. Marshal the event and update `_dd.iast.json` while holding the annotation
   lock.
9. Preserve the existing drop-and-log behavior when event capacity is
   exhausted.

The intended internal API is:

```go
func Report(
    ctx context.Context,
    vulnerabilityType constants.VulnerabilityType,
    evidence string,
    executed *atomic.Uint64,
    skipCallerFunction string,
)
```

The helper constructs `model.UnredactedStringValue` only after its initial
`config.Enabled` check. This preserves the current zero-allocation disabled
path; accepting a pre-built `model.Evidence` interface would allocate before
the helper could return. `Report` is exported only because sibling packages
under `iast/` must call it; its documentation will state the counter and
wrapper-frame preconditions. Passing the concrete atomic counter avoids a
closure allocation in customer hot paths.

`skipCallerFunction` is normally empty. When non-empty, location selection
compares it only with the first candidate logical frame and advances once on an
exact `runtime.Frame.Function` match. This makes the exceptional path a single
string comparison on top of stack collection that reporting already performs;
normal sinks pay only a cheap empty-string branch. It does not introduce a
callback, variadic argument, allocation, goroutine-local state, or an extra
stack walk.

Refactor `iast/crypto/hash.ReportWeakHash` into a thin wrapper that converts
`crypto.Hash` to its existing string evidence and delegates with
`telemetry.ExecutedSink.WeakHash` and no caller frame to skip. Add
`iast/crypto/cipher.ReportWeakCipher(context.Context, string, string)` as the
equivalent weak-cipher wrapper using `VulnerabilityTypeWeakCipher` and
`telemetry.ExecutedSink.WeakCipher`; its final argument is the optional exact
caller function.

Do not inhibit wrapper inlining. `stack.Frames` is built on `runtime.Callers`
and `runtime.CallersFrames`; the runtime records and skips logical frames,
including inlined functions (`runtime.tracebackPCs` explicitly expands and
skips inline frames). The shared reporter can therefore account for its wrapper
frame without `//go:noinline` and without imposing that optimization barrier on
customer hot paths. The existing weak-hash location assertions are a regression
test for this extraction. Adjust the reporter's stack skip—not the instrumented
call sites—so hash locations remain unchanged.

## Preserve Existing Deduplication

Do not change `model.Vulnerability.ComputeHash`. Weak hash and weak cipher both
use the established default hash of vulnerability type and location, excluding
evidence. Consequently, different algorithms reported at the same source
location collapse to one event entry when deduplication is enabled.

This is supported by the existing weak-hash test, which explicitly disables
deduplication before reporting MD4, MD5, and SHA-1 from the same synthetic line.
Weak cipher follows the same policy: every applicable instrumentation sink
invokes the reporter and increments executed-sink telemetry, while
`Event.AddVulnerability` remains responsible for location-based deduplication
and the per-request capacity limit.

## Orchestrion Aspects

Replace the placeholder in `iast/crypto/cipher/orchestrion.yml` with aspects
using the established weak-hash pattern:

- Match the exact import path and function body.
- Inject one package-level `go:linkname` declaration for
  `cipher.ReportWeakCipher` per target source package.
- Prepend a report call with the fixed evidence label.
- Increment
  `telemetry.InstrumentedSink[constants.VulnerabilityTypeWeakCipher]` by the
  number of matched call sites in that package.

DES, Blowfish, and PKCS#12 each have multiple targets declared in one source
file. Anchor `inject-declarations` to one uniquely matched function/method and
use separate report aspects for each target so the linkname declaration and
telemetry `init` function are not emitted more than once in the same package.
RC4 and RC2 each need one combined declaration/report aspect.

`blowfish.NewSaltedCipher` delegates to `NewCipher` when its salt is empty.
Make its prepended report conditional on a non-empty salt. A non-empty salt
therefore reports from `NewSaltedCipher` itself. For an empty salt, the delegated
`NewCipher` aspect produces the single `Blowfish` report and passes
`golang.org/x/crypto/blowfish.NewSaltedCipher` as `skipCallerFunction`; when
that immediate logical frame is present, location selection advances to the
application frame that called `NewSaltedCipher`. A direct `NewCipher` call does
not contain that frame and keeps its direct application caller. This avoids
both duplicate reporting and exposing the nested implementation-detail call
site. Document this delegation assumption beside the Blowfish aspect so a future
x/crypto implementation change is reviewed deliberately. The build-time
instrumented count remains two API call sites, while either runtime construction
path executes exactly one of them.

The injected declaration uses only `context.Context` and `string` in its
signature. As with weak hash, the injected foreign package does not directly
import the implementation package; Orchestrion's `links` entry and
`go:linkname` connect it to the reporter.

Register the new aspect package by adding a tools import for
`github.com/DataDog/dd-iast-go/iast/crypto/cipher` to `orchestrion.tool.go`.

## Tests

All instrumentation tests begin with the required `built.WithOrchestrion`
conditional skip.

### Shared reporter and weak-hash regression

- Keep all existing `iast/crypto/hash` tests passing unchanged in behavior.
- Add focused tests under `internal/vulnerability` only for behavior that is not
  already covered through hash/cipher integration tests, avoiding duplicate
  coverage.
- Verify disabled IAST and unsampled requests remain no-ops if those branches
  cannot be covered cleanly through the existing integration suites.

### Public cipher constructors

Create `iast/crypto/cipher/cipher_test.go`, following the weak-hash test style:

- start a mock tracer and configure IAST sampling deterministically;
- invoke constructors indirectly so location assertions verify the injected
  instrumentation rather than direct calls to the reporter;
- construct and use each cipher with a published/stdlib test vector, ensuring
  instrumentation does not alter the API result or encryption behavior;
- assert vulnerability type, evidence, span metadata, stable zero-based source
  location, and executed telemetry for:
  - DES;
  - TripleDES;
  - RC4;
  - Blowfish;
  - salted Blowfish, including an empty-salt case that must produce only the
  delegated `NewCipher` finding, increment executed-sink telemetry by exactly
  one from its pre-call value, and locate the finding at the synthetic
  application call to `NewSaltedCipher`, not at the nested call inside
  x/crypto;
- add a secure AES negative case that creates and uses an AES cipher without a
  weak-cipher finding.

Disable deduplication only in aggregate tests that intentionally exercise
multiple algorithms from one synthetic source location. Otherwise leave it
enabled so normal behavior is tested.

### RC2 and PBE overlap

RC2 cannot be imported directly from this module because Go enforces x/crypto's
`internal` boundary. Exercise it through the public
`golang.org/x/crypto/pkcs12` API with checked-in test fixtures:

- one PKCS#12 value using SHA + 40-bit RC2 PBE, expecting
  `PBEWithSHAAnd40BitRC2CBC` and `RC2`;
- one PKCS#12 value using SHA + TripleDES PBE, expecting
  `PBEWithSHAAnd3KeyTripleDESCBC` and `TripleDES`.

The fixtures will be minimal, non-secret test certificates/keys generated for
this suite. Leave their certificate bags unencrypted so each decode selects
exactly one PBE implementation for its encrypted key bag. Record their
generation command and provenance beside them; tests must not shell out to
OpenSSL.

PKCS#12 key derivation also invokes instrumented SHA-1 from several locations.
Keep deduplication enabled to prevent those repeated hash operations from
filling the event, raise `config.VulnerabilitiesPerRequest` enough to admit all
unique hash and cipher locations, and filter assertions to `WEAK_CIPHER`
findings. Verify both weak-cipher vulnerabilities and exactly two weak-cipher
executed-sink increments. This exercises normal deduplication policy rather
than redefining it.

The aspects' receiver-specific `create` join points guarantee that unsupported
algorithm identifiers—which return from `pbDecrypterFor` before either method
is called—cannot report either PBE algorithm. Do not add a synthetic
unsupported-OID fixture:
constructing a structurally valid, correctly MACed PKCS#12 file for that single
negative assertion would add disproportionate fixture-generation complexity.

## Documentation

Update the module `README.md` vulnerability table to mark weak cipher as
implemented. The same table currently marks weak hash as unimplemented despite
`iast/crypto/hash` being present and tested; correct that stale entry in the
same documentation change.

No system-tests manifest activation is included in this module-level change;
that would require an end-to-end Go test application exposing the weak-cipher
endpoint, which is outside this implementation request.

## Validation

Run, in order:

1. `gofmt` on all changed Go files.
2. YAML formatting and lint checks for the changed Orchestrion aspect.
3. `go tool orchestrion go test ./internal/model ./internal/vulnerability ./iast/crypto/hash ./iast/crypto/cipher`.
4. `go tool orchestrion go test ./...` for the module-wide regression suite.
5. Plain `go test ./...` to ensure packages still build and instrumentation-only
   tests skip with the prescribed message.
6. The repository formatting command required by the parent system-tests
   repository before committing.

## Implementation Sequence

1. Add the shared reporter and refactor weak hash, then run weak-hash tests to
   lock in behavior, location semantics, and existing deduplication behavior.
2. Add the weak-cipher reporter and register its aspect package.
3. Implement public constructor aspects and tests.
4. Implement RC2/PBE aspects and public-API fixture tests, including overlap.
5. Update module documentation and run the complete validation matrix.
6. Obtain a cross-foundry, maximum-effort code review and resolve every accepted
   finding before considering implementation complete.

## Known Trade-offs

- RC2 and PBE findings originate in x/crypto implementation internals, so their
  locations may be dependency source lines rather than the application call
  site. If a future stack change maps overlapping weak-cipher findings to one
  customer location, the existing location-based policy may intentionally
  deduplicate them.
- Constructor-body instrumentation reports an attempted weak-cipher
  construction even when a caller supplies an invalid key and the constructor
  returns an error. This matches sink-at-invocation behavior and the existing
  prepend-advice model; valid-key tests cover the normal path.
- PKCS#12's PBE and RC2 support is internal and deprecated, but instrumenting it
  is intentional per the confirmed scope.
