# Agent Instructions

Each package under `iast` MUST have its instrumentation for both tools: an
`orchestrion.yml` file for [orchestrion] and an `otelc.yml` file for [otelc].
The two files MUST give the same detections (feature parity). Read the
"Instrumentation Back-Ends" section of the repository-root `AGENTS.md` for the
complete rules.

When you add, change, or remove an aspect in a package under `iast`:

- Do the same change in both `orchestrion.yml` and `otelc.yml`. For otelc, also
  add, change, or remove the `otelc_decl_<package>.go` file of each target
  package. Keep the sink count in each `otelc_decl_<package>.go` file equal to
  the number of `inject_code` rules for its target package in `otelc.yml`.
- Put the detection logic in the Go code of the package (for example
  `ReportWeakHash` in `iast/crypto/hash`). The two YAML files must only call
  this shared code. Do not copy logic into the injected snippets.
- Add or update the end-to-end checks in `_integration/otelc/internal/suite`.
  These checks run with both tools, so they show differences between the two.

When adding or removing an `orchestrion.yml` file under this package, keep the
repository-root `orchestrion.tool.go` file up to date. It must import every Go
package under `iast` that contains an `orchestrion.yml` file, and must not retain
imports for packages whose `orchestrion.yml` file has been removed.

Do not import a package under `iast` from the repository-root
`otel.instrumentation.go` file. otelc already loads the `otelc.yml` files of all
packages of this module when an application imports the root package.

Also make sure that the `README.md` document correctly references all instrumented
vulnerability types, including a reference to the package import path that contains
the corresponding instrumentation.

[orchestrion]: https://github.com/DataDog/orchestrion
[otelc]: https://github.com/open-telemetry/opentelemetry-go-compile-instrumentation
