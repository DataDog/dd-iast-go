// Package otelc holds end-to-end tests of IAST detections, built with a
// compile-time instrumentation tool (otelc or Orchestrion).
//
// The tool file of this module imports the root package of dd-iast-go. The
// modules in setups/ run the same checks (internal/suite) with other tool files:
// one imports only a sub-package, the other imports the root package and a
// sub-package. Only otelc supports these two.
//
// Run the tests from the directory of each module:
//
//   - In the setups, run "go tool otelc go test ./...".
//   - In this module, run "go tool otelc go test . ./internal/..." (or the same
//     command with "orchestrion"). Do not use "./...": it includes cmd/app, a
//     main package. The create_tracer rule of dd-trace-go also instruments the
//     main package of the test binary, and the build fails.
//
// Use a separate GOCACHE for each tool (for example in CI).
//
// Known difference (temporary): with the otelc version in go.mod, a report
// whose location is inside a package that otelc changes (the PKCS#12 reports
// of golang.org/x/crypto/pkcs12) has a file name with no directory and lines
// that are moved down. Orchestrion gives the original path and line. otelc
// PR #1499 fixes it. See knownOtelcPKCS12Gap in internal/suite.
package otelc
