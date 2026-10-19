// Package otelc holds end-to-end tests of IAST detections, built with a
// compile-time instrumentation tool (otelc or Orchestrion).
//
// The tool file of this module imports the root package of dd-iast-go. The
// modules in setups/ run the same checks (internal/suite) with other tool files:
// one imports only a sub-package, the other imports the root package and a
// sub-package. Only otelc supports these two. Run each module with
// "go tool otelc go test ./..." from its directory.
package otelc
