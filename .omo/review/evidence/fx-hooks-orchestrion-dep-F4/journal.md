# F4 independent verification

Target: dd-iast-go `2e23b4614320defd0d32177a69888dcab73f4d11`.
Pinned Orchestrion: `v1.12.2-0.20260828141217-23afa71d6dcb`.
Both Go 1.26.6 and Go 1.27.0 are installed.

## Hypotheses

1. The resolver rejects a syntactic mixed union before intersecting constraints.
   Distinguish with equivalent simple and intersected generic constraints in a
   woven build; inspect the generated operator bodies.
2. Finder setup, inactive analysis, or missing source instrumentation caused
   the apparent miss. Distinguish using real instrumented HTTP handlers, header
   and body sources, explicit source-taint checks, and positive controls.
3. A scope, identity, or range-check artifact caused the miss. Give every
   operation a separate HTTP request and inspect full source/range metadata
   inside the request lifetime.

## Artifacts

- Private copy: `/tmp/ddiast-review/wt/fx-hooks-orchestrion-dep-F4/`.
  Remove the entire private copy after preserving the reproducer and output.
- Independent test: `review_f4/intersection_test.go` inside the private copy.
- Test logs and retained woven build work: inside the private copy, with
  relied-upon output and relevant generated source preserved in this evidence
  directory before cleanup.
- Final reports: the node's `.md` and `.json` under `.omo/review/phase3/`.

No implementation fix or main-checkout source edit is authorized or planned.
