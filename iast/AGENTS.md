# Agent Instructions

When adding or removing an `orchestrion.yml` file under this package, keep the
repository-root `orchestrion.tool.go` file up to date. It must import every Go
package under `iast` that contains an `orchestrion.yml` file, and must not retain
imports for packages whose `orchestrion.yml` file has been removed.
