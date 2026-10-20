# Agent Instructions

The @README.md file contains a high-level description of the module, and can be
consulted to obtain general information about the intent and purpose of this
code.

## Operating Constraints

This package is designed to be hooked into customer code-bases at compilation
time using [orchestrion]. This implies this code might run in hot loops or
within the critical path of the customer's application. In light of this, all
code in this module MUST abide by the following rules:

- NEVER break the host application (e.g, by causing a `panic`)
- NEVER slow down the host application more than strictly necessary
- NEVER leak memory or hold onto memory for longer than is necessary
- ALWAYS keep accurate provenance information through taint propagation

As a consequence of these principles:
- this codebase prefers dropping data when under excessive load over blocking;
  and all expensive operations are gated by a cheap check (e.g,
  `CanBeTainted(value)`);
- all data storage must guarantee a maximum memory footprint that will never be
  exceeded, and we can accept dropping data if the allowed storage is saturated.

## Project Structure

- `/iast/` contains sub-directories for each kind of IAST vulnerability
  supported by this package. These directories contain the `orchestrion.yml`
  files, and all packages containing one such `orchestrion.yml` file is imported
  from `orchestrion.tool.go` at the package root. This gives users an easy way
  to bring in all supported instrumentation while keeping the flexibility to
  only enable the things they want.
- `/internal/` contains all implementation details not intended for external
  consumption. Those details are those that are not necessary to implement new
  IAST detections externally to this package (but building on public features
  from it).
- `/taint/` contains all the taint tracking machinery; exposing a simple API
  that instrumentation will use to track untrusted values through the program
  flow.

## Instrumentation Back-Ends (Orchestrion and otelc)

This module supports two compile-time instrumentation tools: [orchestrion] and
[otelc]. Both tools MUST give the same detections. These rules apply to all
new and changed instrumentation:

- ALWAYS write each aspect for both tools: an `orchestrion.yml` rule and the
  equivalent `otelc.yml` rule (with its `otelc_decl_<package>.go` file when
  necessary). Do not add, change, or remove an aspect for one tool only.
- ALWAYS put the detection logic in shared Go code (for example
  `hash.ReportWeakHash`), and call it from both tools. Keep the code that is
  specific to one tool (the YAML rules and the injected snippets) as small as
  possible. Do not copy logic between the two.
- ALWAYS test both tools: the Orchestrion tests (`go tool orchestrion go test`)
  and the otelc integration tests (`_integration/otelc`).

Reviewers MUST check feature parity between the two tools. A change that
makes the `orchestrion.yml` and `otelc.yml` aspects differ (different targets,
sinks, sink counts, or reported data) is a defect, unless the change gives an
explicit reason why the tool cannot support it.

[orchestrion]: https://github.com/DataDog/orchestrion
[otelc]: https://github.com/open-telemetry/opentelemetry-go-compile-instrumentation

## Plans

Before implementing any significant feature:
1. a detailed plan should be created and stored under `_docs/plans/<slug>.md`
2. the plan is to be reviewed by a critic sub-agent (if possible from another
   provider and with maximum effort budget), and refined until both agents agree
   the plan is solid
3. the plan is to be reviewed by the user, and refined until the user agrees the
   plan is solid
4. the plan is to be committed yo the repository with a commit message which
   title is of the form `wip(plan): <feature tag line>`

Then, once the feature is implemented, and the user is satisfied with the
delivered code; the plan should be deleted from `_docs/plans`. This way, the
plan exists in the history of the pull request, but does not stay permanently
in the codebase where it would be dead weight.

## Pre-Commit Validation

Before committing any change:

- run `gofmt` on every modified Go file;
- run all applicable linters and checkers and fix every reported issue; and
- do not commit until all applicable validation completes cleanly.

## More information

Read [CONTRIBUTING.md](./CONTRIBUTING.md) for additional information that must
be considered when working on this repository.
