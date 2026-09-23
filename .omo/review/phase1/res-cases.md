# res-cases: Orchestrion e2e propagation coverage catalogue
Verdict: No correctness findings; this scope is a mechanical catalogue of the research PR's e2e propagation cases and shadow-fixture case names.
Scope covered: `runtime/taint/instrument/testdata/e2e/README.md`, all 114 `case_*.go` files in that directory, and all 115 `experiments/go-shadow/fixture/*/cases.json` files on `DataDog/orchestrion` branch `eliottness/iast-testing`.
## Findings
None.
## Checked and found correct
- Confirmed the e2e directory inventory contains 114 unique `case_*.go` files and each source registers one case with an ID and name.
- Recorded each case's declared `Want` report values/ranges or its no-report outcome in `.omo/review/phase1/research/cases.md`.
- Recorded names from all 115 shadow fixture `cases.json` files in the catalogue's fixture section.
- Read the README's case format and expected-report conventions.
## Not covered / open questions
- No tests or prototype execution were requested or run; expected outcomes are transcribed from source declarations.
- The catalogue describes research prototypes, not product behavior in `dd-iast-go`.
