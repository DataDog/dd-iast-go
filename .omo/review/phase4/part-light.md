# Part "light" — consolidated report (config, model, CI, docs, testapps, deps/licensing, pre-existing code, test determinism, benchmark code, wiring)

Branch romain.marcadier/taint-tracking @ 2e23b46. Deduplicated by root cause across phase-2 light-* nodes plus cross-part findings sharing light-lane root causes.

**Counts after dedup: 1 Critical, 0 High, 5 Medium** (plus 5 Low entries and Info notes).

## 1. Part verdict

The light lanes contain no runtime correctness defect: configuration parsing never panics on extreme or malformed `DD_IAST_*` values and always clamps or falls back with a warning (crash-config-extremes), the model codecs are regenerated-consistent with a hard 64-vulnerability cap, the nested testapps pass instrumented shuffled tests with all bootstrap symbols present, wiring imports every `iast` manifest package, and the benchmark runner is correct. The single Critical defect is on the release path, not in light runtime code: the Orchestrion pseudo-version pin at `go.mod:14` is both (a) taken from an unmerged topic branch and (b) silently downgradable by MVS to a released Orchestrion that cannot load dd-iast-go aspects, failing any customer build that resolves a released orchestrion — a rule-1 compile break on valid customer code, independently confirmed in phase 3. Crash-safety and memory-bounds for this part are clean (no config/model/doc-driven crash or unbounded growth found); provenance is not directly affected by light code, but four Medium documentation defects can mislead operators into configuring behavior the product does not implement (row taint, vuln ceiling) or relying on coverage the README overstates.

## 2. Findings by root cause (Critical > High > Medium > Low)

### L-1 (Critical): Orchestrion pin at go.mod:14 breaks weaving for customers using any released Orchestrion, and points at an unmerged topic branch
- Severity: **Critical** (phase-3 adjusted; `phase3/fx-hooks-compile-matrix-F1.json`)
- Status: CONFIRMED in phase 3 (fx-hooks-compile-matrix-F1; the pin-provenance aspect light-deps-license-F1 is separately CONFIRMED but adjusted to **Info** by `phase3/fx-light-deps-license-F1.json` as a documented pre-GA prerequisite)
- Location: `go.mod:14`; `iast/propagation/orchestrion.yml:21`
- Contributing finding ids: hooks-compile-matrix-F1 (Critical, CONFIRMED), light-deps-license-F1 (High→Info, CONFIRMED), hooks-orchestrion-dep-F5 (Medium, reviewer-reported — Orchestrion PR #881 still changes-requested, so the immutable pseudo-version cannot receive corrections without repinning)
- Mechanism: the root module pins `github.com/DataDog/orchestrion v1.12.2-0.20260828141217-23afa71d6dcb`, a prerelease of v1.12.2 taken from `origin/romain.marcadier/iast-operator-join-points` (not an ancestor of `origin/main`, in no release tag). Under MVS the pseudo-version loses to every released v1.12.2+; in particular dd-trace-go `orchestrion/all/v2 v2.11.0-rc.1` requires orchestrion v1.13.0, which `go mod tidy` picks silently. The released Orchestrion lacks the operator join points, so `go tool orchestrion go build` fails at configuration load with `unknown injection point type "string-concat"` on otherwise valid customer code (Go 1.26.6 and 1.27.0 alike). The falsifier confirmed the failure is reachable by default (fx reason: "reachable_default: true"; pending-release pin is documented only in internal plans, never as a customer-facing limitation). The same pin is repeated in `benchmarks/overhead` and the three nested testapp modules.
- Reproduction: `evidence/fx-hooks-compile-matrix-F1/repro-released-v1.13.0.go1.26.6.log` (command in the fx JSON: `go mod tidy` then `go tool orchestrion go build` in an app requiring orchestrion/all v2.11.0-rc.1); original finding log `evidence/hooks-compile-matrix/logs/st-golang-app_net-http-orchestrion.build126.log`; pin provenance `evidence/light-deps-license/orchestrion-pin-provenance.txt` (`git merge-base --is-ancestor 23afa71d6dcb origin/main` → exit 1).
- Minimal fix: once Orchestrion PR #881 merges and a release containing the join points is published, replace the pseudo-version consistently in the root, overhead, and testapp modules and regenerate the tool pin; until then document the pin as a customer-facing limitation and prevent the silent downgrade (e.g. a `replace`/tool-version guard or a startup check that the loaded Orchestrion understands the operator join points).
- Cross-reference: hooks-compile-matrix-F1 is also consolidated in part-hooks; the root cause (the dependency pin) lives in this part's code (`go.mod`).

### L-2 (Medium): README hides the hard 1–64 clamp on DD_IAST_VULNERABILITIES_PER_REQUEST
- Severity: Medium (reviewer-reported; no phase-3 check for Medium-or-lower)
- Status: reviewer-reported (three independent nodes)
- Location: `README.md:117` vs `internal/config/config.go:33-34,75`
- Contributing finding ids: light-config-F1, light-docs-F2, crash-config-extremes-F1
- Mechanism: the README table types the variable as "Integer greater than or equal to `1`", but the loader clamps to `[1, MaxVulnerabilitiesPerRequest]` with `MaxVulnerabilitiesPerRequest = 64`; setting e.g. 1000000 silently resolves to 64 with a warning. README.md:110 promises values outside a *documented* range are clamped, so the enforced upper bound is both real and undocumented, contradicting `internal/config/AGENTS.md`'s requirement that documentation describe every variable's accepted values.
- Reproduction: `evidence/crash-config-extremes/configdump_matrix_results.json`; command: `DD_IAST_VULNERABILITIES_PER_REQUEST=1000000 ./configdump` (harness `evidence/crash-config-extremes/configdump_main.go`).
- Minimal fix: change the README type column to "Integer from `1` to `64`" and mention the hard event ceiling.

### L-3 (Medium): DD_IAST_DB_ROWS_TO_TAINT is advertised but has no implementation
- Severity: Medium (reviewer-reported)
- Status: reviewer-reported
- Location: `README.md:125`; `internal/config/config.go:83`
- Contributing finding ids: light-docs-F1
- Mechanism: the README documents "Number of database rows tainted for each request", but the setting is only parsed into `config.DbRowsToTaint`; there is no `database/sql` `Rows`/`Scan` instrumentation, and the parent plan explicitly defers row taint to a later source integration (`_docs/plans/taint-tracking-net-http-sqli-cmdi.md:62`). Users can configure behavior the product does not provide.
- Reproduction: static reasoning (NEEDS-REPRO); `git grep -n -E 'DbRowsToTaint|DD_IAST_DB_ROWS_TO_TAINT'` finds only README, config declaration/load, and the deferred-plan statement.
- Minimal fix: remove the setting from the README and public configuration until row sources exist, or implement and test `database/sql` row tainting.

### L-4 (Medium): Accepted implementation plans remain in-tree with internally contradictory status
- Severity: Medium (reviewer-reported)
- Status: reviewer-reported
- Location: `_docs/plans/taint-tracking-net-http-sqli-cmdi-phase-7a.md:5`
- Contributing finding ids: light-docs-F3 (phase 2), map-design-F1 (phase 1)
- Mechanism: `AGENTS.md:45-55` requires plans to be deleted once delivered code is accepted, but all eleven plan-directory files remain. Phase 7a still says "draft, pending critic and user review" while the parent plan (`taint-tracking-net-http-sqli-cmdi.md:5`) says all implementation phases are complete and the coverage artifacts record approval on 2026-09-23 — the plan record misstates the branch's actual state.
- Reproduction: static reasoning; the file inventory and status lines were read directly.
- Minimal fix: delete accepted plans (git history preserves them) and, for any legitimately active plan, update its status and state the exemption.

### L-5 (Medium): CI never exercises woven taint tracking end-to-end or under -race
- Severity: Medium (reviewer-reported)
- Status: reviewer-reported
- Location: `.github/workflows/ci.yml:151-152`; `.github/workflows/system-tests.yml:162-170`
- Contributing finding ids: light-ci-F1, sink-systemtests-F1 (cross-ref part-sink)
- Mechanism: two distinct lanes share the root cause that the woven product has no end-to-end CI coverage. (a) The race jobs are plain `go test -race` against `./.github` and `./internal/taint/...` — they never invoke `go tool orchestrion`, so races introduced at instrumentation join points or in woven integration are untested (verified: both commands pass while CI confirms they are ordinary `go test`). (b) The system-tests CI gate only requires weak hash/cipher/dedup scenarios; SQLi, CMDi, and source scenarios are `missing_feature`, so the taint pipeline has no cross-tracer e2e coverage at all.
- Reproduction: `evidence/light-ci/race-coverage.txt` (`go test -race -shuffle=on ./.github && go test -race -count=1 -shuffle=on ./internal/taint/...`); `evidence/sink-systemtests/weblog_iast_routes.txt`.
- Minimal fix: add a `go tool orchestrion go test -race` lane for the woven integration tests, and add IAST SQLi/CMDi/source scenarios to the system-tests CI gate.

### L-6 (Medium): README propagation-coverage claims overstate the implementation
- Severity: Medium (reviewer-reported)
- Status: reviewer-reported
- Location: `README.md:32` (fmt.Sprint*), `README.md:38-39` (application-root boundary), `internal/taint/propagation/string_coarse.go:206-221`
- Contributing finding ids: hooks-yml-fmt-strconv-url-F2, prop-string-coarse-F3 (duplicate of F2), hooks-scope-root-F2 (all cross-ref part-hooks / part-prop)
- Mechanism: three README coverage claims do not match behavior. `fmt.Sprint*` is advertised without saying only direct string/`[]byte` operands propagate (other operand types are lost); coarse fmt/url/strconv output keeps only the first source (the provenance half of this defect is owned by part-prop); and the README leaves the module boundary of the "application root" ambiguous, so users cannot tell which packages weaving covers.
- Reproduction: static reasoning; `evidence/hooks-yml-fmt-strconv-url/run_woven_go1.26.6.out.txt` and part-prop evidence.
- Minimal fix: qualify the README rows (direct string/[]byte operands only; root-module scope) or implement the missing paths.

### Low entries
- **L-7 (Low, reviewer-reported)** — Tracked root `.DS_Store` (light-docs-F4). Tracked Finder blob at repo root; `_docs/.DS_Store` absent. Fix: remove and add a `.gitignore` rule.
- **L-8 (Low, reviewer-reported)** — Deleting `_docs/sources-and-sinks/` (commit a5923cc, 1,131 lines) discarded reusable framework source/sink/lifetime research with no in-tree successor (light-docs-F5). Fix: maintain a concise, versioned research index.
- **L-9 (Low, reviewer-reported)** — `internal/model/event_test.go:88,115`: round-trip fixture sets `SourceIndex` 3 with only one source, verifying serialization of an invalid reference (light-model-F1). Fix: set the index to 0.
- **L-10 (Low, reviewer-reported)** — `internal/taint/store/identity_test.go:43-58`: the stale-entry/address-reuse assertion can `t.Skip` when the allocator does not reuse the address, giving silent zero coverage (light-test-determinism-F1; evidence `evidence/light-test-determinism/address-reuse-test.txt`). Fix: separate the always-run finished-owner invalidation check from the allocator-dependent reuse scenario.
- **L-11 (Low, reviewer-reported)** — `.github/workflows/system-tests.yml:13,25,50`: CI depends on the mutable, unmerged system-tests branch `romain.marcadier/dd-iast-go` by name, not SHA (sink-systemtests-F11, cross-ref part-sink). Fix: pin a commit SHA.

## 3. Low/Info and code-quality notes (compact)
- README coverage doc nits whose underlying behavior is owned by other parts: `bytes.Join` >16 elements goes coarse (crash-diff-bytes-F2, part-crash); writer tracking bounded by capacity — a Builder/Buffer over 64 KiB capacity is permanently blind (crash-diff-bytes-F3); `ToUpperSpecial`/`ToLowerSpecial`/`ToTitleSpecial`/`Title` unhooked despite README (prop-unicode-F3, part-prop); Go 1.27 `CutLast` unhooked (hooks-fidelity-bytes-F3, part-hooks); writer receiver escape always happens though README says "can" (perf-escape-F6, part-perf).
- hooks-compile-matrix-F5 (Info): the aggregate `orchestrion.tool.go:26` import silently enables dd-trace-go tracer auto-start in woven binaries — undocumented (cross-ref part-hooks).
- base-test-127-F2 (Info): the `go 1.26.6` directive at `go.mod:3` is the effective toolchain guard (Go 1.25.9 is rejected before Orchestrion runs).
- base-bootstrap-F1 / perf-binary-compile-F2 (Info): woven bootstrap binaries are ~12.7x larger (+~20.4 MB) than plain — build-size observation, owned by part-perf.
- base-static-F1/F2 (Low): unused `charge` parameter in `store/root.go:323` and always-true `release` in `store/writer.go:498` — pre-existing store code, owned by part-store.

## 4. What was verified correct (with the node that verified it)
- Config: no panic on any extreme/malformed `DD_IAST_*` input across 57 environment combinations; numeric clamps and defaults match documented bounds; telemetry levels, redaction-pattern fallback, and alias precedence all correct (crash-config-extremes, light-config).
- README config table, propagation matrix, sink claims, JSON 64-slot decoder limit, 32-KiB analyzer and 25,000-byte event limits match the implementation apart from the findings above (light-config, light-docs).
- Model: `MaxVulnerabilities` aliases the 64 hard bound and admission applies min(configured, hard); `go generate` produced no codec drift; round-trip/unknown-field/enum tests pass (light-model).
- CI: module discovery finds all four nested modules and prunes vendor/hidden dirs; coverage profiles atomic-mode with correct merge/ordering; four fuzz targets exist and are bounded (10k execs, 5-min timeout); actions pinned by full SHA with read-only permissions (light-ci).
- Testapps: nested `replace` directives resolve; the three go.sum files are byte-identical; instrumented, shuffled, repeated suites pass; all bootstrap fixture symbols present in the woven binaries (light-testapps).
- Wiring: all ten `iast` orchestrion.yml packages imported in `orchestrion.tool.go`, none stale; README vulnerability table lists each implemented type with its package path (light-wiring).
- Benchmark code: runner alternates control/IAST sample order, validates sampling bounds, closes result files, and its buffer workloads prevent dead-code elimination; runner and overhead module tests pass (light-bench-code).
- Pre-existing code: weak hash/cipher reporting preserves stdlib results under weaving; stacktrace matching, telemetry atomics, and source/sink iterators correct; focused plain and instrumented tests pass (light-preexisting).
- Test determinism: no `time.Sleep`, polling, `t.Parallel`, or map-order dependence in all 139 test files; bounded deadline waits and fixed PCG seeds only (light-test-determinism).
- Deps/licensing: go-sqllexer (MIT) used in production SQL redaction and attributed in LICENSE-3rdparty.csv; x/net/x/text attributions consistent; nested-module checksums match; dd-trace-go v2.11.0-rc.1 tag exists (light-deps-license).

## 5. Coverage gaps
- No wall-clock performance conclusions for the benchmark code; the full runner orchestration (dual builds + benchstat artifact generation) was reviewed statically, not run end to end (light-bench-code).
- The four CI fuzz campaigns were configured-inspected but never run; action SHA ↔ upstream release correspondence not verified; nested coverage exercised only for the SQL testapp (light-ci).
- Testapps: no race-detector runs and only Go 1.26.6 (light-testapps, light-testapps validation `evidence/light-testapps/validation.txt`).
- light-docs did not run a woven end-to-end executable (doc-to-code verification only); the deleted framework API inventories were not revalidated against their historical versions.
- light-wiring left the `go generate` delta unresolved: the tool added `dd-trace-go/orchestrion/all/v2` to tool imports and warned about a missing dd-trace-go contrib replacement (`evidence/light-wiring/audit.txt`).
- Go 1.27 compatibility is NOT consolidated here: the woven encoding/json compile break and the associated 17–24 GiB orchestrion job-server growth (base-test-127-F1, hooks-compile-matrix-F2/F6, both Critical, CONFIRMED in `phase3/fx-base-test-127-F1.json`) root-cause in `iast/encoding/json/orchestrion.yml` and are owned by part-hooks; they are noted here only because fx-light-deps-license-F1 observed the Go 1.27 failure during dependency reproduction.
- Telemetry verbosity, `DD_IAST_DB_ROWS_TO_TAINT`, `DD_IAST_STACK_TRACE_ENABLED`, and `DD_IAST_DEDUPLICATION_ENABLED` were not driven through extreme-input fuzzing beyond the pre-existing suites (crash-config-extremes).
