# fx-life-table-lookup-F1: Embedded NULs force a full source-index probe chain

Verified against HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.

## Verdict per finding

### life-table-lookup-F1: CONFIRMED

The hash collision is real and independent of the randomized seed. Full tuple equality preserves distinct source identities, so the finding is a request-path performance defect rather than a provenance defect. Only one finding was supplied; duplicate comparison does not apply.

## Reproduction

I restored and ran the supplied reproducer in the private copy with Go 1.26.6. Its collision-threshold test intentionally exits nonzero; the live-analysis admission test passes. The captured output is in `.omo/review/evidence/fx-life-table-lookup-F1/supplied_go1.26.6.out.txt`.

```sh
cd /tmp/ddiast-review/wt/fx-life-table-lookup-F1
GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test -race -count=1 -run '^TestReview' -v -timeout=5m ./internal/taint/request
```

I also wrote an independent internal-API reproducer, `.omo/review/evidence/fx-life-table-lookup-F1/independent_formvalue_collision_test.go`. It builds a 256-field percent-encoded query from one NUL-containing byte stream, parses it with `Request.ParseForm`, verifies bulk `ManageForm` admits nothing because the map exceeds its 48-name limit, then calls `Request.FormValue` and explicitly invokes the `ManageParameter` callback for every field. This is not a woven build; the callback is the internal surface called by the FormValue advice. It confirms 256 distinct sources share one home slot.

Go 1.26.6 output:

```text
parsed fields=256; ManageParameter callbacks=256; common home slot=96; final insertion probes=256; total insertion probes=32896
PASS
```

Go 1.27.0 output:

```text
parsed fields=256; ManageParameter callbacks=256; common home slot=142; final insertion probes=256; total insertion probes=32896
PASS
```

The home slot differs because each table has a fresh seed; all tuples in each run still have the same hash input and home slot. Full captured output is in `independent_go1.26.6.out.txt` and `independent_go1.27.0.out.txt`. The request-package race suite also passed on Go 1.26.6 with only the supplied test's intentional threshold failure skipped; see `request_race_suite_go1.26.6.out.txt`.

## Reachability

Reachable under default configuration on sampled requests. IAST defaults to enabled, request sampling defaults to 30%, and the concurrent-request limit defaults to 2 (`internal/config/config.go:72-74`). The `net/http.Request.FormValue` advice invokes `httpbridge.Parameter` for each result (`iast/net/http/orchestrion.yml:196-218`); request initialization registers that callback to `ManageParameter`, which calls `Analysis.ManageString` (`internal/taint/request/scope.go:138-145`, `lazy.go:60-71`).

The bulk map path drops maps over 48 names or 96 values (`internal/taint/request/lazy.go:16-18,164-170`), but that does not cap repeated per-field `FormValue` calls. A handler that reads many request fields individually can admit the full collision family in one active request. This is conditional on application code requesting those fields; a single oversized `URL.Query`/form-map operation alone does not produce all 256 admissions.

Neither the README nor the phase-1 design-intent limitations document this collision. The randomized hash and fixed-capacity design do not make this worst-case probe chain an accepted limitation.

## Adjusted severity

**High** — a request can force 32,896 table probes for 256 source admissions while each insertion holds the request source lock. This is a large hot-path multiplier; the 256-source and 512-probe bounds remain intact, so it is not Critical.

## Root cause

`internal/taint/request/table.go:208-220` hashes `origin || name || NUL || value` without framing the variable-length name. Moving a NUL from the name into the value preserves the exact bytes passed to `maphash`, so all family members start at the same slot for any fixed seed. `Table.prepare` linearly probes from that slot (`table.go:131-152`); full equality (`table.go:140-150`) preserves identity but cannot prevent the chain.

## Minimal fix

Prefix the name with an unambiguous fixed-width length before hashing it, consistently for string- and byte-valued sources. Keep the full equality check.
