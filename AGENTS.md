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


## Testing

All tests in this module require [orchestrion], so the correct way to execute
them is to use the following command pattern:

```console
$ go tool orchestrion go test <go test args ...>
```

In order to be friendlier to users, all tests in this codebase must begin with a
conditional skip instructing the user on how to properly run the suite if
[orchestrion] was not properly used:

```go
import "github.com/DataDog/orchestrion/runtime/built"

func TestName(t *testing.T) {
  if !built.WithOrchestrion {
    t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
  }

  // ...
}
```

[orchestrion]: https://github.com/DataDog/orchestrion
