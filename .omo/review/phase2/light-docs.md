# light-docs: README verification and documentation hygiene
Verdict: Documentation needs correction: the README propagation and sink coverage match the woven implementation, but two runtime-configuration claims and several documentation-hygiene requirements do not.
Scope covered: `README.md`; `AGENTS.md`; all files in `_docs/plans/`; historical `_docs/sources-and-sinks/` deleted by `a5923cc`; `internal/config/{config.go,parser/parser.go,loader/loader.go,init.go}`; `iast/{propagation,encoding/json,database/sql,os/exec}` instrumentation and wrappers; `internal/taint/jsonbridge/bridge.go`; `internal/taint/redaction/analyzer.go`; `internal/spans/payload.go`.

## Findings
### light-docs-F1: README advertises a database-row setting that has no implementation
- Severity: Medium
- Category: config
- Location: README.md:125
- Claim: `DD_IAST_DB_ROWS_TO_TAINT` is documented as controlling “Number of database rows tainted for each request,” but its only production use is parsing into `config.DbRowsToTaint` (`internal/config/config.go:83`). There is no `database/sql.Rows`/`Scan` instrumentation, and the parent plan explicitly says database-row taint is a later source integration (`_docs/plans/taint-tracking-net-http-sqli-cmdi.md:62`). Users can configure a behavior the product does not provide.
- Evidence: static reasoning only (NEEDS-REPRO). `git grep -n -E 'DbRowsToTaint|DD_IAST_DB_ROWS_TO_TAINT'` finds only the README, config declaration/load, and the deferred-plan statement; a production search for `Rows.Scan`, `*Rows`, and `Scan(` finds no row-source instrumentation.
- Fix: Remove the row-count setting from the README and public configuration until row sources exist, or implement and test `database/sql` row tainting before retaining the claim.

### light-docs-F2: Runtime configuration omits the enforced vulnerability ceiling
- Severity: Medium
- Category: config
- Location: README.md:117
- Claim: The table defines `DD_IAST_VULNERABILITIES_PER_REQUEST` as any integer greater than or equal to one, while `internal/config/config.go:75` clamps it to the hard range `1..64`. This conflicts with the preceding promise that values outside a *documented* range are clamped (`README.md:110`): the upper bound is enforced but undocumented.
- Evidence: static reasoning only (NEEDS-REPRO). `loader.UintFromEnvBounded(..., 1, MaxVulnerabilitiesPerRequest)` and `MaxVulnerabilitiesPerRequest = 64` establish the actual range.
- Fix: Change the type column to “Integer from `1` to `64`” and mention the hard event ceiling in the description.

### light-docs-F3: Completed plans remain and the phase record is internally contradictory
- Severity: Medium
- Category: doc
- Location: _docs/plans/taint-tracking-net-http-sqli-cmdi-phase-7a.md:5
- Claim: `AGENTS.md:45-55` requires plans to be deleted after delivered code is accepted, but all eleven plan-directory files remain: `propagation-coverage-{matrix,paths,results,review,testing}.md`, `taint-tracking-net-http-sqli-cmdi{-phase-0,-phase-5,-phase-6,-phase-7a,-phase-8}.md`, and `taint-tracking-net-http-sqli-cmdi.md`. This is not merely cleanup: phase 7a still says “draft, pending critic and user review,” whereas the parent says all implementation phases are complete (`taint-tracking-net-http-sqli-cmdi.md:5`) and the coverage artifacts say implementation was approved for publication on 2026-09-23.
- Evidence: static reasoning only (NEEDS-REPRO). The remaining-file inventory and each cited status/removal line were read directly; the parent plan itself says to delete it after acceptance (`taint-tracking-net-http-sqli-cmdi.md:9`).
- Fix: Delete accepted implementation plans and supporting handoff artifacts from `_docs/plans/`, preserving them only in Git history; if any plan legitimately remains active, update its status and explain why it is exempt.

### light-docs-F4: Finder metadata is committed at repository root
- Severity: Low
- Category: quality
- Location: .DS_Store
- Claim: The root `.DS_Store` is tracked (`git ls-files -- .DS_Store _docs/.DS_Store`), adding opaque machine-local metadata to the repository. The requested `_docs/.DS_Store` is not tracked and is absent from the checkout, so only the root artifact requires removal.
- Evidence: static reasoning only (NEEDS-REPRO). The tracked object is `.DS_Store` blob `0ec1a69642b4e288e8dd5f0c027020e71f3c5a39`; `_docs/.DS_Store` is globally ignored and absent.
- Fix: Remove the tracked root `.DS_Store` and retain an explicit repository `.gitignore` rule for Finder metadata if one is not already present.

### light-docs-F5: Removing the sources-and-sinks directory discarded useful future-integration research
- Severity: Low
- Category: doc
- Location: _docs/sources-and-sinks/README.md (deleted in a5923cc)
- Claim: Commit `a5923cc` deleted 1,131 lines across nine documents as “old, outdated plan (DO NOT USE).” Although those exact version-specific recommendations should not be restored unchanged, the material included framework-specific attacker-controlled APIs, sink surfaces, binder/copy hazards, and the `fasthttp`/Fiber zero-copy buffer-reuse lifetime warning. No current in-tree successor mentions chi, Echo, Fiber, Gin, gorilla/mux, httprouter, or fasthttp. The deletion therefore lost reusable source/sink reconnaissance rather than merely obsolete execution steps.
- Evidence: static reasoning only (NEEDS-REPRO). `git show a5923cc^:_docs/sources-and-sinks/{README,chi,echo,fasthttp,fiber,gin,gorilla-mux,httprouter,net-http}.md` shows the catalog; `git diff --stat a5923cc^ a5923cc -- _docs/sources-and-sinks` reports 1,131 deletions.
- Fix: Preserve a concise, versioned framework-source research index or move the still-relevant lifecycle and API inventory into maintained design documentation; do not reinstate the old plan verbatim.

## Checked and found correct
- The propagation matrix is backed by root-package-only aspects in `iast/propagation/orchestrion.yml`: string windows/copies/transforms, two- and three-index byte windows, formatting, URL/strconv wrappers, 2–16 operand concatenations, byte-to-string conversion, and direct builder/buffer operations all have matching advice and wrapper implementations. The stated direct-call limitation and excluded compiler contexts match the aspect filters.
- The buffer limitation text is consistent with native `bytes.Buffer` function-body invalidation for indirect mutations and for `Bytes`, `AvailableBuffer`, and `Peek` exposure (`iast/propagation/orchestrion.yml:1558-1679`).
- JSON’s advertised `Unmarshal`/`Decoder.Decode` typed-string propagation matches its five woven decoder hooks. `internal/taint/jsonbridge/bridge.go` has exactly 64 decoder slots and four-probe admission, matching the README limit.
- The SQL and command sink claims match the instrumentation: `PrepareContext`, `ExecContext`, and `QueryContext` are woven for `database/sql`; the command report is invoked only after `os.StartProcess` returns. Root executable bootstrap and non-root/library exclusions are also present.
- The 32-KiB analyzer and 25,000-byte event limits are implemented by `internal/taint/redaction/analyzer.go:8-17` and `internal/spans/payload.go:12-77`.
- All other README configuration names, defaults, aliases, parser behavior, and documented ranges match `internal/config/config.go`; `DD_IAST_ENABLED` is consumed at request admission and report paths.
- Focused private-copy validation passed: `GOTOOLCHAIN=go1.26.6 go test -timeout 15m ./internal/config ./iast/propagation ./iast/database/sql ./iast/os/exec ./iast/encoding/json`.

## Not covered / open questions
- This audit did not revalidate the deleted framework API inventories against their historical dependency versions; it establishes only that useful categories of research have no maintained in-tree successor.
- No woven end-to-end executable was run because the assigned scope is documentation-to-code verification; the focused package tests validate the directly read implementation packages.
