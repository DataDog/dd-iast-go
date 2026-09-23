# fx-life-lazy-reader-F2: MultiReader false body provenance

Verdict: CONFIRMED. A woven real HTTP handler marks a server-created prefix as
`http.request.body` when it combines that prefix with `req.Body` through
`io.MultiReader` and consumes the result with `io.ReadAll`.

Scope covered: `iast/io/orchestrion.yml`, `internal/taint/request/reader.go`,
`internal/taint/request/http.go`, `internal/taint/store/binding.go`, the
README/design-intent reader contract, and independent woven HTTP tests.

## Verdict per finding

### life-lazy-reader-F2: Mixed MultiReader marks trusted bytes as request body

- Verdict: **CONFIRMED**
- Same root cause as another finding: no duplicate was supplied for this node.
- The cited mechanism is present at HEAD `2e23b461`: the `io.MultiReader`
  advice propagates each of its first eight child bindings to one composite
  reader (`iast/io/orchestrion.yml:46-70`). `PropagateReader` consequently
  binds that one composite to every owner of a bound child
  (`internal/taint/request/reader.go:27-42`). `ReadAllBytes` then adopts the
  whole returned slice as one HTTP-body source (`reader.go:67-88,90-128`).
  It has no child-offset or clean-child information left to preserve.

## Reproduction

Independent reproducer:
`.omo/review/evidence/fx-life-lazy-reader-F2/fx_life_lazy_reader_f2_test.go`.
It starts a real `httptest` HTTP server; the woven handler executes:

```go
io.ReadAll(io.MultiReader(strings.NewReader("trusted-"), req.Body))
```

Command (Go 1.26.6, exit 0):

```sh
cd /tmp/ddiast-review/wt/fx-life-lazy-reader-F2 && GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 /usr/bin/time -l go tool orchestrion go test -race -timeout 10m -count=1 -run '^TestReviewFXMixedMultiReaderAttributesTrustedPrefixToRequestBody$' -v ./iast/net/http
```

Key captured output in
`.omo/review/evidence/fx-life-lazy-reader-F2/go1.26.6.out.txt`:

```text
OBSERVED false provenance: range=[0,16) origin=http.request.body source="trusted-attacker" trustedPrefix="trusted-"
PASS
```

The range covers all of `"trusted-attacker"`; `"trusted-"` was produced only
by application code. Go 1.27.0 was also attempted. Its woven build fails
before the reproducer runs because generated `encoding/json` code references
`Decoder.d`; see `go1.27.0.out.txt`. That separate toolchain incompatibility
does not affect the confirmed Go 1.26.6 result.

## Reachability

Reachable through ordinary woven customer code on the documented supported
path: an HTTP handler uses a constant/configuration prefix with `req.Body` in
`io.MultiReader`, then calls the advertised `io.ReadAll` owned-result path.
No special configuration is required beyond normal IAST instrumentation; the
default configuration enables IAST and samples 30% of requests, so a sampled
request reaches the defect. The README/design intent documents reader
provenance and the eight-input inspection limit, but does **not** document
attributing bytes from unbound children to the request body. It violates the
accurate-provenance product rule.

## Adjusted severity

**High (unchanged):** this is a false source range on an advertised reader
path, capable of producing a false-positive sink finding and reporting a
server-controlled prefix as attacker-controlled request data.

## Root cause (file:line)

`iast/io/orchestrion.yml:46-70` loses child identity by propagating a single
composite binding for each bound input. `internal/taint/request/reader.go:27-42`
stores only reader-to-owner association, and `reader.go:67-128` assigns one
full-result HTTP body range after `io.ReadAll`.

## Minimal fix

Replace per-child `Propagate` calls for `io.MultiReader` with a bounded
composite-specific bridge operation. Bind the composite only when every
inspected child is bound to the same owner set and there are no uninspected
children; otherwise do not bind it. This deliberately drops mixed-reader
provenance rather than falsely tainting clean bytes. Per-child offset tracking
would retain more coverage but is not the minimal safe fix.
