//go:build tools

package main

import (
	_ "github.com/DataDog/orchestrion"

	_ "github.com/DataDog/dd-iast-go/iast/crypto/hash"
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)
