# map-design: design-intent and documented-limitations digest
Verdict: MEDIUM documentation inconsistencies found; the plans otherwise define a bounded, fail-open-for-host / fail-closed-for-provenance design that downstream reviewers should verify against code.
Scope covered: `_docs/plans/*.md`; `README.md`; `CONTRIBUTING.md`; `AGENTS.md`; `iast/AGENTS.md`; `internal/config/AGENTS.md`; branch commit subjects from `1135a291dcb3c424c870ce1978c3ede6dbd1470b..HEAD`; cheap corroboration in `go.mod`, `orchestrion.tool.go`, and `internal/config/config.go`.

## Findings

### map-design-F1: Phase 7a's status header contradicts its implementation record
- Severity: Medium
- Category: doc
- Location: _docs/plans/taint-tracking-net-http-sqli-cmdi-phase-7a.md:5
- Claim: The document labels Phase 7a “draft, pending critic and user review,” but its own implementation checkpoint says commit boundaries 1--10 are implemented at line 445 and records user-approved activation at line 492. The parent plan consequently presents Phase 7a as complete with approved compatibility assumptions. The header can cause reviewers to treat completed code as unreviewed plan work, or to miss that only the normative corpus/live-backend assumptions remain pending.
- Evidence: static reasoning only (NEEDS-REPRO)
- Fix: Replace the stale status with the implemented/conditionally approved state and list the normative redaction corpus plus live backend fixture as the remaining general-availability gates.

### map-design-F2: The parent plan overstates the one-byte exclusion
- Severity: Medium
- Category: doc
- Location: _docs/plans/taint-tracking-net-http-sqli-cmdi.md:209
- Claim: The parent plan says the first version “does not track empty or one-byte values,” while the approved named-propagation plan explicitly permits a one-byte derived window when an existing managed root owns it (`taint-tracking-net-http-sqli-cmdi-phase-5.md:49`). The actual documented invariant is narrower: empty values and new one-byte managed roots are rejected, but a one-byte window may preserve existing root provenance.
- Evidence: static reasoning only (NEEDS-REPRO)
- Fix: Amend the parent plan to distinguish rejected one-byte root admission from supported one-byte derived windows.

## Checked and found correct

- README's runtime configuration agrees with `internal/config/config.go`: 0--64 concurrent requests, 1--64 vulnerabilities per request, and 1--64 maximum ranges; defaults also match.
- `go.mod` pins Go 1.26.6 and the documented Orchestrion pseudo-version at commit `23afa71d6dcb`.
- `orchestrion.tool.go` imports the documented propagation, I/O/bufio, HTTP, JSON, SQL, command, URL, and taint integrations, consistent with the aggregate-enable claims.
- README records the key safe misses called out by the implementation plans: indirect calls, mutable byte operators, replacement terms, mutable buffer exposure, request-body read buffers, and JSON destination exclusions.

## Not covered / open questions

- This was a document digest, not an implementation or benchmark audit. All “complete,” validation, retained-memory, fuzz, coverage, and timing statements in the plans require current-code verification.
- The plans retain external release gates: a normative cross-tracer redaction corpus and a live backend compatibility fixture for the 25,000-byte `MAX_SIZE_EXCEEDED` payload behavior.
- Orchestrion PR #881 remains a pinned pseudo-version pending a released upstream version.
